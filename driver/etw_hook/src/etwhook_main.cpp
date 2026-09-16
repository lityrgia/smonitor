#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <etwhook_manager.hpp>
#include <scall_protocol.h>

extern "C" NTKERNELAPI NTSTATUS IoCreateDriver(
    PUNICODE_STRING DriverName,
    PDRIVER_INITIALIZE InitializationFunction);
extern "C" NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);

#define LOG_RING_ENTRIES (64 * 1024)
#define DETAIL_RING_ENTRIES (32 * 1024)
#define POOL_TAG 'gLsS'

static_assert((LOG_RING_ENTRIES & (LOG_RING_ENTRIES - 1)) == 0, "ring size must be a power of two");
static_assert(sizeof(SCALL_EVENT) == 80, "SCALL_EVENT ABI changed");
static_assert(sizeof(SCALL_ARGUMENT_CONDITION) == 16, "SCALL_ARGUMENT_CONDITION ABI changed");
static_assert(sizeof(SCALL_ARGUMENT_RULE) == 72, "SCALL_ARGUMENT_RULE ABI changed");
static_assert(sizeof(SCALL_CONFIG) == 10592, "SCALL_CONFIG ABI changed");
static_assert(sizeof(SCALL_STATS) == 56, "SCALL_STATS ABI changed");
static_assert(sizeof(SCALL_DETAIL) == 176, "SCALL_DETAIL ABI changed");

struct SYSCALL_INFO {
    char name[64];
    USHORT category;
};

static SYSCALL_INFO gSyscallTable[SCALL_MAX_SYSCALLS] = {};
static ULONG gSyscallCount = 0;
static SCALL_EVENT* gRing = nullptr;
static SCALL_DETAIL* gDetailRing = nullptr;
static ULONG gHead = 0;
static ULONG gTail = 0;
static ULONG gDetailHead = 0;
static ULONG gDetailTail = 0;
static KSPIN_LOCK gRingLock;
static PDEVICE_OBJECT gDeviceObject = nullptr;

static volatile LONG gUnloading = 0;
static volatile LONG gHooksActive = 0;
static volatile LONG gCaptureEnabled = 0;
static volatile LONG gTargetPidCount = 0;
static volatile LONG gTargetPids[SCALL_MAX_TARGET_PIDS] = {};
static volatile LONG gTargetNameCount = 0;
static volatile LONG gTargetNameWords[SCALL_MAX_TARGET_NAMES]
    [SCALL_PROCESS_NAME_BYTES / sizeof(LONG)] = {};
static volatile LONG gTargetFilterUpdating = 0;
static volatile LONG gOperationMask[SCALL_OPERATION_MASK_WORDS] = {};
static volatile LONG gOperationFilterUpdating = 0;
static SCALL_ARGUMENT_RULE gArgumentRules[SCALL_MAX_ARGUMENT_RULES] = {};
static volatile LONG gArgumentRuleCount = 0;
static volatile LONG gArgumentFilterUpdating = 0;
static volatile LONG gArgumentRuleOperationMask[SCALL_OPERATION_MASK_WORDS] = {};
static volatile LONG gExcludedPid = 0;
static volatile LONG gCategoryMask = SCALL_ALL_CATEGORIES;
static volatile LONG64 gSequence = 0;
static volatile LONG64 gCaptured = 0;
static volatile LONG64 gDelivered = 0;
static volatile LONG64 gDropped = 0;
static volatile LONG64 gDetailsDropped = 0;

static USHORT ClassifySyscall(const char* name, BOOLEAN win32k) {
    if (win32k) {
        if (strstr(name, "Gdi") || strstr(name, "DComposition") || strstr(name, "Dxg"))
            return ScallCategoryGraphics;
        return ScallCategoryUser;
    }
    if (strstr(name, "DeviceIoControl") || strstr(name, "FsControl"))
        return ScallCategorySystem;
    if (strstr(name, "File") || strstr(name, "Directory") || strstr(name, "Volume") || strstr(name, "Ea"))
        return ScallCategoryFile;
    if (strstr(name, "Key") || strstr(name, "Registry"))
        return ScallCategoryRegistry;
    if (strstr(name, "Process") || strstr(name, "Job") || strstr(name, "DebugObject"))
        return ScallCategoryProcess;
    if (strstr(name, "Thread") || strstr(name, "Apc"))
        return ScallCategoryThread;
    if (strstr(name, "VirtualMemory") || strstr(name, "Section") || strstr(name, "Memory"))
        return ScallCategoryMemory;
    if (strstr(name, "Token") || strstr(name, "Security") || strstr(name, "AccessCheck") || strstr(name, "Privilege"))
        return ScallCategorySecurity;
    if (strstr(name, "Alpc") || strstr(name, "Port") || strstr(name, "Lpc"))
        return ScallCategoryIpc;
    if (strstr(name, "Event") || strstr(name, "Timer") || strstr(name, "Semaphore") || strstr(name, "Mutant") || strstr(name, "Wait"))
        return ScallCategorySync;
    if (strstr(name, "System") || strstr(name, "Power") || strstr(name, "Trace") || strstr(name, "Wnf") || strstr(name, "Atom") || strstr(name, "Driver"))
        return ScallCategorySystem;
    return ScallCategoryOther;
}

static ULONG ParsePeExports(PVOID imageBase, BOOLEAN win32k) {
    ULONG parsed = 0;
    __try {
        auto dos = static_cast<PIMAGE_DOS_HEADER>(imageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<PUCHAR>(imageBase) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        ULONG exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRva) return 0;
        auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<PUCHAR>(imageBase) + exportRva);
        auto names = reinterpret_cast<PULONG>(static_cast<PUCHAR>(imageBase) + exports->AddressOfNames);
        auto ordinals = reinterpret_cast<PUSHORT>(static_cast<PUCHAR>(imageBase) + exports->AddressOfNameOrdinals);
        auto functions = reinterpret_cast<PULONG>(static_cast<PUCHAR>(imageBase) + exports->AddressOfFunctions);

        for (ULONG i = 0; i < exports->NumberOfNames; ++i) {
            auto name = reinterpret_cast<char*>(static_cast<PUCHAR>(imageBase) + names[i]);
            if (name[0] != 'N' || name[1] != 't' || name[2] < 'A' || name[2] > 'Z') continue;
            PUCHAR function = static_cast<PUCHAR>(imageBase) + functions[ordinals[i]];
            if (function[0] != 0x4c || function[1] != 0x8b || function[2] != 0xd1 || function[3] != 0xb8) continue;
            ULONG id = *reinterpret_cast<PULONG>(function + 4);
            if (id >= SCALL_MAX_SYSCALLS) continue;
            RtlStringCbCopyA(gSyscallTable[id].name, sizeof(gSyscallTable[id].name), name);
            gSyscallTable[id].category = ClassifySyscall(name, win32k);
            if (id >= gSyscallCount) gSyscallCount = id + 1;
            ++parsed;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        parsed = 0;
    }
    return parsed;
}

static NTSTATUS LoadSyscallTable(const wchar_t* path, BOOLEAN win32k) {
    UNICODE_STRING dllName;
    RtlInitUnicodeString(&dllName, path);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &dllName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    IO_STATUS_BLOCK io = {};
    HANDLE file = nullptr;
    NTSTATUS status = ZwOpenFile(&file, FILE_READ_DATA | SYNCHRONIZE, &attributes, &io,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return status;

    HANDLE section = nullptr;
    status = ZwCreateSection(&section, SECTION_MAP_READ, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, file);
    ZwClose(file);
    if (!NT_SUCCESS(status)) return status;

    PVOID base = nullptr;
    SIZE_T size = 0;
    status = ZwMapViewOfSection(section, ZwCurrentProcess(), &base, 0, 0, nullptr, &size,
        ViewUnmap, 0, PAGE_READONLY);
    ZwClose(section);
    if (!NT_SUCCESS(status)) return status;
    ULONG parsed = ParsePeExports(base, win32k);
    ZwUnmapViewOfSection(ZwCurrentProcess(), base);
    return parsed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static NTSTATUS BuildSyscallTable() {
    NTSTATUS status = LoadSyscallTable(L"\\SystemRoot\\System32\\ntdll.dll", FALSE);
    if (!NT_SUCCESS(status)) return status;
    return LoadSyscallTable(L"\\SystemRoot\\System32\\win32u.dll", TRUE);
}

static char LowerAscii(char value) {
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

static void NormalizeProcessName(const char* input, char output[SCALL_PROCESS_NAME_BYTES]) {
    RtlZeroMemory(output, SCALL_PROCESS_NAME_BYTES);
    if (!input) return;
    ULONG length = 0;
    while (length < SCALL_PROCESS_NAME_BYTES - 1 && input[length]) {
        output[length] = LowerAscii(input[length]);
        ++length;
    }
    if (length >= 4 && output[length - 4] == '.' && output[length - 3] == 'e' &&
        output[length - 2] == 'x' && output[length - 1] == 'e') {
        output[length - 4] = 0;
    }
}

static BOOLEAN EqualProcessName(const char* left, const char* right) {
    static const char exeSuffix[] = ".exe";
    for (ULONG i = 0; i < SCALL_PROCESS_NAME_BYTES; ++i) {
        if (!right[i]) {
            if (!left[i]) return TRUE;
            for (ULONG suffix = 0; i + suffix < SCALL_PROCESS_NAME_BYTES && left[i + suffix];
                 ++suffix) {
                if (suffix >= RTL_NUMBER_OF(exeSuffix) - 1 ||
                    LowerAscii(left[i + suffix]) != exeSuffix[suffix]) return FALSE;
            }
            return TRUE;
        }
        if (!left[i]) return FALSE;
        if (LowerAscii(left[i]) != LowerAscii(right[i])) return FALSE;
    }
    return TRUE;
}

static BOOLEAN ResolveProcessId(HANDLE processId, ULONG_PTR* resolvedPid,
    char* processName, SIZE_T processNameSize) {
    if (!resolvedPid || !processName || processNameSize == 0) return FALSE;
    *resolvedPid = reinterpret_cast<ULONG_PTR>(processId);
    processName[0] = 0;
    if (!processId) return FALSE;
    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(processId, &process);
    if (!NT_SUCCESS(status) || !process) return FALSE;
    *resolvedPid = reinterpret_cast<ULONG_PTR>(PsGetProcessId(process));
    RtlStringCbCopyA(processName, processNameSize, PsGetProcessImageFileName(process));
    ObDereferenceObject(process);
    return processName[0] != 0;
}

static BOOLEAN ResolveProcessHandle(HANDLE processHandle, ULONG_PTR* processId,
    char* processName, SIZE_T processNameSize) {
    if (!processId || !processName || processNameSize == 0) return FALSE;
    *processId = 0;
    processName[0] = 0;
    if (!processHandle) return FALSE;
    PEPROCESS process = nullptr;
    NTSTATUS status = ObReferenceObjectByHandle(processHandle, 0, *PsProcessType, UserMode,
        reinterpret_cast<PVOID*>(&process), nullptr);
    if (!NT_SUCCESS(status) || !process) return FALSE;
    *processId = reinterpret_cast<ULONG_PTR>(PsGetProcessId(process));
    RtlStringCbCopyA(processName, processNameSize, PsGetProcessImageFileName(process));
    ObDereferenceObject(process);
    return processName[0] != 0;
}

static BOOLEAN MatchesTargetProcess(ULONG pid) {
    if (InterlockedCompareExchange(&gTargetFilterUpdating, 0, 0)) return FALSE;
    LONG count = InterlockedCompareExchange(&gTargetPidCount, 0, 0);
    LONG nameCount = InterlockedCompareExchange(&gTargetNameCount, 0, 0);
    if (count == 0 && nameCount == 0) return TRUE;
    for (LONG i = 0; i < count; ++i) {
        ULONG target = static_cast<ULONG>(InterlockedCompareExchange(&gTargetPids[i], 0, 0));
        if (target == pid) return TRUE;
    }
    if (nameCount > 0) {
        char imageName[SCALL_PROCESS_NAME_BYTES];
        NormalizeProcessName(PsGetProcessImageFileName(PsGetCurrentProcess()), imageName);
        for (LONG i = 0; i < nameCount; ++i) {
            alignas(LONG) char targetName[SCALL_PROCESS_NAME_BYTES];
            auto targetWords = reinterpret_cast<LONG*>(targetName);
            for (ULONG word = 0; word < SCALL_PROCESS_NAME_BYTES / sizeof(LONG); ++word) {
                targetWords[word] = InterlockedCompareExchange(&gTargetNameWords[i][word], 0, 0);
            }
            if (EqualProcessName(imageName, targetName) &&
                !InterlockedCompareExchange(&gTargetFilterUpdating, 0, 0)) return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN OperationEnabled(ULONG syscallId) {
    if (syscallId >= SCALL_MAX_SYSCALLS || gOperationFilterUpdating) return FALSE;
    ULONG word = syscallId / 32;
    ULONG bit = syscallId % 32;
    ULONG mask = static_cast<ULONG>(InterlockedCompareExchange(&gOperationMask[word], 0, 0));
    return (mask & (1u << bit)) != 0;
}

static BOOLEAN ArgumentRulesAllow(ULONG syscallId, const ULONG_PTR* arguments) {
    if (InterlockedCompareExchange(&gArgumentFilterUpdating, 0, 0)) return FALSE;
    ULONG operationWord = syscallId / 32;
    ULONG operationBit = syscallId % 32;
    ULONG operationMask = static_cast<ULONG>(InterlockedCompareExchange(
        &gArgumentRuleOperationMask[operationWord], 0, 0));
    if ((operationMask & (1u << operationBit)) == 0) return TRUE;
    ULONG count = static_cast<ULONG>(InterlockedCompareExchange(&gArgumentRuleCount, 0, 0));
    count = min(count, SCALL_MAX_ARGUMENT_RULES);
    BOOLEAN hasOnlyRule = FALSE;
    BOOLEAN matchedOnlyRule = FALSE;
    for (ULONG i = 0; i < count; ++i) {
        const auto& rule = gArgumentRules[i];
        if (rule.syscall_id != syscallId) continue;
        if (rule.action == SCALL_ARGUMENT_RULE_ONLY) hasOnlyRule = TRUE;
        BOOLEAN matches = arguments != nullptr && rule.condition_count > 0 &&
            rule.condition_count <= SCALL_MAX_RULE_CONDITIONS;
        for (ULONG conditionIndex = 0; matches && conditionIndex < rule.condition_count;
             ++conditionIndex) {
            const auto& condition = rule.conditions[conditionIndex];
            if (condition.argument_index >= SCALL_MAX_RULE_CONDITIONS ||
                static_cast<ULONGLONG>(arguments[condition.argument_index]) != condition.value) {
                matches = FALSE;
            }
        }
        if (matches && rule.action == SCALL_ARGUMENT_RULE_EXCEPT) return FALSE;
        if (matches && rule.action == SCALL_ARGUMENT_RULE_ONLY) matchedOnlyRule = TRUE;
    }
    if (InterlockedCompareExchange(&gArgumentFilterUpdating, 0, 0)) return FALSE;
    return !hasOnlyRule || matchedOnlyRule;
}

static ULONGLONG EnqueueEvent(ULONG syscallId, const ULONG_PTR* arguments = nullptr) {
    if (gUnloading || !gCaptureEnabled || syscallId >= SCALL_MAX_SYSCALLS) return 0;
    if (!OperationEnabled(syscallId)) return 0;
    if (!ArgumentRulesAllow(syscallId, arguments)) return 0;
    ULONG pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
    ULONG excludedPid = static_cast<ULONG>(InterlockedCompareExchange(&gExcludedPid, 0, 0));
    if (excludedPid && excludedPid == pid) return 0;
    if (!MatchesTargetProcess(pid)) return 0;
    USHORT category = gSyscallTable[syscallId].category;
    ULONG categoryMask = static_cast<ULONG>(InterlockedCompareExchange(&gCategoryMask, 0, 0));
    if ((categoryMask & (1u << category)) == 0) return 0;

    SCALL_EVENT event = {};
    event.qpc = static_cast<ULONGLONG>(KeQueryPerformanceCounter(nullptr).QuadPart);
    event.pid = pid;
    event.tid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()));
    event.syscall_id = static_cast<USHORT>(syscallId);
    event.category = category;
    event.sequence = static_cast<ULONGLONG>(InterlockedIncrement64(&gSequence));
    RtlStringCbCopyA(event.process_name, sizeof(event.process_name),
        PsGetProcessImageFileName(PsGetCurrentProcess()));
    if (arguments) {
        __try {
            for (ULONG i = 0; i < RTL_NUMBER_OF(event.arguments); ++i)
                event.arguments[i] = static_cast<ULONGLONG>(arguments[i]);
            event.flags |= SCALL_EVENT_FLAG_ARGUMENTS_VALID;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            RtlZeroMemory(event.arguments, sizeof(event.arguments));
        }
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&gRingLock, &oldIrql);
    if (gHead - gTail >= LOG_RING_ENTRIES) {
        ++gTail;
        InterlockedIncrement64(&gDropped);
    }
    gRing[gHead & (LOG_RING_ENTRIES - 1)] = event;
    ++gHead;
    KeReleaseSpinLock(&gRingLock, oldIrql);
    InterlockedIncrement64(&gCaptured);
    return event.sequence;
}

static void EnqueueDetail(ULONGLONG sequence, const char* text) {
    if (!sequence || !text || !text[0]) return;
    SCALL_DETAIL detail = {};
    detail.sequence = sequence;
    SIZE_T length = strnlen(text, sizeof(detail.text) - 1);
    detail.length = static_cast<USHORT>(length);
    RtlCopyMemory(detail.text, text, length);

    KIRQL oldIrql;
    KeAcquireSpinLock(&gRingLock, &oldIrql);
    if (gDetailHead - gDetailTail >= DETAIL_RING_ENTRIES) {
        ++gDetailTail;
        InterlockedIncrement64(&gDetailsDropped);
    }
    gDetailRing[gDetailHead & (DETAIL_RING_ENTRIES - 1)] = detail;
    ++gDetailHead;
    KeReleaseSpinLock(&gRingLock, oldIrql);
}

static void ReadUnicode(PUNICODE_STRING source, char* output, ULONG outputSize) {
    output[0] = 0;
    if (!source || outputSize < 2) return;
    __try {
        UNICODE_STRING snapshot = *source;
        if (!snapshot.Buffer || !snapshot.Length) return;
        ULONG units = snapshot.Length / sizeof(WCHAR);
        ULONG written = 0;
        BOOLEAN truncated = FALSE;
        for (ULONG i = 0; i < units;) {
            ULONG codepoint = snapshot.Buffer[i++];
            if (codepoint >= 0xD800 && codepoint <= 0xDBFF && i < units) {
                ULONG low = snapshot.Buffer[i];
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    ++i;
                    codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00);
                } else {
                    codepoint = 0xFFFD;
                }
            } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
                codepoint = 0xFFFD;
            }

            UCHAR encoded[4];
            ULONG count;
            if (codepoint < 0x80) {
                encoded[0] = static_cast<UCHAR>(codepoint);
                count = 1;
            } else if (codepoint < 0x800) {
                encoded[0] = static_cast<UCHAR>(0xC0 | (codepoint >> 6));
                encoded[1] = static_cast<UCHAR>(0x80 | (codepoint & 0x3F));
                count = 2;
            } else if (codepoint < 0x10000) {
                encoded[0] = static_cast<UCHAR>(0xE0 | (codepoint >> 12));
                encoded[1] = static_cast<UCHAR>(0x80 | ((codepoint >> 6) & 0x3F));
                encoded[2] = static_cast<UCHAR>(0x80 | (codepoint & 0x3F));
                count = 3;
            } else {
                encoded[0] = static_cast<UCHAR>(0xF0 | (codepoint >> 18));
                encoded[1] = static_cast<UCHAR>(0x80 | ((codepoint >> 12) & 0x3F));
                encoded[2] = static_cast<UCHAR>(0x80 | ((codepoint >> 6) & 0x3F));
                encoded[3] = static_cast<UCHAR>(0x80 | (codepoint & 0x3F));
                count = 4;
            }
            ULONG reserve = i < units ? 3 : 0;
            if (written + count + reserve >= outputSize) {
                truncated = TRUE;
                break;
            }
            for (ULONG byte = 0; byte < count; ++byte) {
                output[written++] = static_cast<char>(encoded[byte]);
            }
        }
        if (truncated && written + 3 < outputSize) {
            output[written++] = '.';
            output[written++] = '.';
            output[written++] = '.';
        }
        output[written] = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlStringCbCopyA(output, outputSize, "<unreadable>");
    }
}

static BOOLEAN ReadHandleObjectName(HANDLE handle, char* output, ULONG outputSize) {
    output[0] = 0;
    if (!handle || outputSize < 2 || KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;
    PVOID object = nullptr;
    NTSTATUS status = ObReferenceObjectByHandle(
        handle, 0, nullptr, UserMode, &object, nullptr);
    if (!NT_SUCCESS(status) || !object) return FALSE;
    alignas(PVOID) UCHAR nameBuffer[512] = {};
    ULONG required = 0;
    status = ObQueryNameString(object, reinterpret_cast<POBJECT_NAME_INFORMATION>(nameBuffer),
        sizeof(nameBuffer), &required);
    if (NT_SUCCESS(status)) {
        auto information = reinterpret_cast<POBJECT_NAME_INFORMATION>(nameBuffer);
        ReadUnicode(&information->Name, output, outputSize);
    }
    ObDereferenceObject(object);
    return NT_SUCCESS(status) && output[0] != 0;
}

static void ReadObjectPath(POBJECT_ATTRIBUTES attributes, char* output, ULONG outputSize) {
    output[0] = 0;
    if (!attributes || outputSize < 2) return;
    __try {
        OBJECT_ATTRIBUTES snapshot = *attributes;
        char relative[128] = {};
        ReadUnicode(snapshot.ObjectName, relative, sizeof(relative));
        if (snapshot.RootDirectory && relative[0] && relative[0] != '\\') {
            char root[128] = {};
            if (ReadHandleObjectName(snapshot.RootDirectory, root, sizeof(root))) {
                RtlStringCbPrintfA(output, outputSize, "%s\\%s", root, relative);
                return;
            }
        }
        RtlStringCbCopyA(output, outputSize, relative);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlStringCbCopyA(output, outputSize, "<unreadable>");
    }
}

struct SCALL_RECT32 {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

struct SCALL_TRACK_MOUSE_EVENT {
    ULONG size;
    ULONG flags;
    HANDLE window;
    ULONG hoverTime;
};

struct SCALL_POINT32 {
    LONG x;
    LONG y;
};

struct SCALL_WINDOW_PLACEMENT {
    ULONG length;
    ULONG flags;
    ULONG showCommand;
    SCALL_POINT32 minimumPosition;
    SCALL_POINT32 maximumPosition;
    SCALL_RECT32 normalPosition;
};

struct SCALL_FLASH_WINDOW_INFO {
    ULONG size;
    ULONG padding;
    HANDLE window;
    ULONG flags;
    ULONG count;
    ULONG timeout;
};

struct SCALL_INPUT_RECORD {
    ULONG type;
    ULONG padding;
    UCHAR data[32];
};

struct SCALL_LARGE_STRING {
    ULONG length;
    ULONG maximumLength;
    ULONG_PTR buffer;
};

template<typename T>
static BOOLEAN ReadUserValue(ULONG_PTR address, T* value) {
    if (!address || !value || KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;
    __try {
        ProbeForRead(reinterpret_cast<PVOID>(address), sizeof(T), 1);
        RtlCopyMemory(value, reinterpret_cast<PVOID>(address), sizeof(T));
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static void ReadRect(ULONG_PTR address, char* output, ULONG outputSize) {
    if (!address) {
        RtlStringCbCopyA(output, outputSize, "all");
        return;
    }
    SCALL_RECT32 rect = {};
    if (!ReadUserValue(address, &rect)) {
        RtlStringCbCopyA(output, outputSize, "unavailable");
        return;
    }
    RtlStringCbPrintfA(output, outputSize, "(%ld,%ld)-(%ld,%ld)",
        rect.left, rect.top, rect.right, rect.bottom);
}

static void ReadWideText(ULONG_PTR address, ULONG characters, char* output, ULONG outputSize) {
    output[0] = 0;
    if (!address || !characters || KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    ULONG capped = characters > 96 ? 96 : characters;
    UNICODE_STRING text = {};
    text.Buffer = reinterpret_cast<PWCHAR>(address);
    text.Length = static_cast<USHORT>(capped * sizeof(WCHAR));
    text.MaximumLength = text.Length;
    ReadUnicode(&text, output, outputSize);
}

static void ReadUnicodeArgument(ULONG_PTR address, char* output, ULONG outputSize) {
    output[0] = 0;
    if (!address || KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    ReadUnicode(reinterpret_cast<PUNICODE_STRING>(address), output, outputSize);
}

static void ReadLargeString(ULONG_PTR address, char* output, ULONG outputSize) {
    output[0] = 0;
    SCALL_LARGE_STRING text = {};
    if (!ReadUserValue(address, &text) || !text.buffer || !text.length) return;
    if (text.maximumLength & 0x80000000u) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
        ULONG capped = text.length > outputSize - 1 ? outputSize - 1 : text.length;
        __try {
            ProbeForRead(reinterpret_cast<PVOID>(text.buffer), capped, 1);
            RtlCopyMemory(output, reinterpret_cast<PVOID>(text.buffer), capped);
            output[capped] = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            RtlStringCbCopyA(output, outputSize, "<unavailable>");
        }
        return;
    }
    ReadWideText(text.buffer, text.length / sizeof(WCHAR), output, outputSize);
}

static void DecodeWin32kArguments(ULONGLONG sequence, const char* name,
    const ULONG_PTR* arguments) {
    if (!sequence || !name || !arguments) return;
    ULONG_PTR a1 = arguments[0];
    ULONG_PTR a2 = arguments[1];
    ULONG_PTR a3 = arguments[2];
    ULONG_PTR a4 = arguments[3];
    char detail[160] = {};

    if (!strcmp(name, "NtUserFindWindowEx")) {
        char className[44] = {};
        char windowName[44] = {};
        ReadUnicodeArgument(a3, className, sizeof(className));
        ReadUnicodeArgument(a4, windowName, sizeof(windowName));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Parent=0x%llX Child=0x%llX Class=\"%s\" Title=\"%s\"",
            a1, a2, className, windowName);
    } else if (!strcmp(name, "NtUserDefSetText")) {
        char text[104] = {};
        ReadLargeString(a2, text, sizeof(text));
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Text=\"%s\"", a1, text);
    } else if (!strcmp(name, "NtUserSetWindowPlacement")) {
        SCALL_WINDOW_PLACEMENT placement = {};
        if (ReadUserValue(a2, &placement)) {
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Hwnd=0x%llX Show=%u Normal=(%ld,%ld)-(%ld,%ld)",
                a1, placement.showCommand, placement.normalPosition.left,
                placement.normalPosition.top, placement.normalPosition.right,
                placement.normalPosition.bottom);
        } else {
            RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Placement=0x%llX", a1, a2);
        }
    } else if (!strcmp(name, "NtUserFlashWindowEx")) {
        SCALL_FLASH_WINDOW_INFO flash = {};
        if (ReadUserValue(a1, &flash)) {
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Hwnd=0x%llX Flags=0x%X Count=%u Timeout=%u",
                reinterpret_cast<ULONG_PTR>(flash.window), flash.flags, flash.count, flash.timeout);
        } else {
            RtlStringCbPrintfA(detail, sizeof(detail), "Info=0x%llX", a1);
        }
    } else if (!strcmp(name, "NtUserCalculatePopupWindowPosition")) {
        SCALL_POINT32 anchor = {};
        SCALL_POINT32 size = {};
        BOOLEAN haveAnchor = ReadUserValue(a1, &anchor);
        BOOLEAN haveSize = ReadUserValue(a2, &size);
        if (haveAnchor && haveSize) {
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Anchor=(%ld,%ld) Size=%ldx%ld Flags=0x%X Exclude=0x%llX",
                anchor.x, anchor.y, size.x, size.y, static_cast<ULONG>(a3), a4);
        } else {
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Anchor=0x%llX Size=0x%llX Flags=0x%X Exclude=0x%llX",
                a1, a2, static_cast<ULONG>(a3), a4);
        }
    } else if (!strcmp(name, "NtUserInvalidateRect")) {
        char rect[64] = {};
        ReadRect(a2, rect, sizeof(rect));
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Rect=%s Erase=%s",
            a1, rect, a3 ? "true" : "false");
    } else if (!strcmp(name, "NtUserValidateRect")) {
        char rect[64] = {};
        ReadRect(a2, rect, sizeof(rect));
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Rect=%s", a1, rect);
    } else if (!strcmp(name, "NtUserRedrawWindow")) {
        char rect[64] = {};
        ReadRect(a2, rect, sizeof(rect));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX Rect=%s Region=0x%llX Flags=0x%llX", a1, rect, a3, a4);
    } else if (!strcmp(name, "NtUserDrawAnimatedRects")) {
        char from[48] = {};
        char to[48] = {};
        ReadRect(a3, from, sizeof(from));
        ReadRect(a4, to, sizeof(to));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX Animation=%llu From=%s To=%s", a1, a2, from, to);
    } else if (!strcmp(name, "NtUserClipCursor")) {
        char rect[64] = {};
        ReadRect(a1, rect, sizeof(rect));
        RtlStringCbPrintfA(detail, sizeof(detail), "Rect=%s", rect);
    } else if (!strcmp(name, "NtUserTrackMouseEvent")) {
        SCALL_TRACK_MOUSE_EVENT event = {};
        if (ReadUserValue(a1, &event)) {
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Hwnd=0x%llX Flags=0x%X HoverTime=%u",
                reinterpret_cast<ULONG_PTR>(event.window), event.flags, event.hoverTime);
        } else {
            RtlStringCbPrintfA(detail, sizeof(detail), "Event=0x%llX", a1);
        }
    } else if (!strcmp(name, "NtUserPostMessage") ||
        !strcmp(name, "NtUserMessageCall")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX Message=0x%X WParam=0x%llX LParam=0x%llX",
            a1, static_cast<ULONG>(a2), a3, a4);
    } else if (!strcmp(name, "NtUserGetMessage") ||
        !strcmp(name, "NtUserPeekMessage")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Message=0x%llX Hwnd=0x%llX Min=0x%X Max=0x%X",
            a1, a2, static_cast<ULONG>(a3), static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtUserSetWindowPos")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX InsertAfter=0x%llX X=%ld Y=%ld",
            a1, a2, static_cast<LONG>(a3), static_cast<LONG>(a4));
    } else if (!strcmp(name, "NtUserMoveWindow")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX X=%ld Y=%ld Width=%ld",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a3), static_cast<LONG>(a4));
    } else if (!strcmp(name, "NtUserSetCursorPos") ||
        !strcmp(name, "NtUserSetCaretPos")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "X=%ld Y=%ld",
            static_cast<LONG>(a1), static_cast<LONG>(a2));
    } else if (!strcmp(name, "NtUserWindowFromPoint") ||
        !strcmp(name, "NtUserWindowFromPhysicalPoint")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Point=(%ld,%ld)",
            static_cast<LONG>(a1), static_cast<LONG>(a1 >> 32));
    } else if (!strcmp(name, "NtUserChildWindowFromPointEx")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Point=(%ld,%ld) Flags=0x%llX",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a2 >> 32), a3);
    } else if (!strcmp(name, "NtUserRealChildWindowFromPoint") ||
        !strcmp(name, "NtUserDragDetect")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Point=(%ld,%ld)",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a2 >> 32));
    } else if (!strcmp(name, "NtUserRegisterHotKey")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX Id=%ld Modifiers=0x%X Key=0x%X",
            a1, static_cast<LONG>(a2), static_cast<ULONG>(a3), static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtUserSetLayeredWindowAttributes")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX Color=0x%06X Alpha=%u Flags=0x%X",
            a1, static_cast<ULONG>(a2) & 0xFFFFFF, static_cast<ULONG>(a3) & 0xFF,
            static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtUserSetTimer")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX Id=0x%llX Elapse=%u Callback=0x%llX",
            a1, a2, static_cast<ULONG>(a3), a4);
    } else if (!strcmp(name, "NtUserTrackPopupMenuEx")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Menu=0x%llX Flags=0x%X X=%ld Y=%ld",
            a1, static_cast<ULONG>(a2), static_cast<LONG>(a3), static_cast<LONG>(a4));
    } else if (!strcmp(name, "NtUserSendInput")) {
        SCALL_INPUT_RECORD input = {};
        if (ReadUserValue(a2, &input)) {
            if (input.type == 0) {
                LONG dx = 0;
                LONG dy = 0;
                ULONG mouseData = 0;
                ULONG flags = 0;
                RtlCopyMemory(&dx, &input.data[0], sizeof(dx));
                RtlCopyMemory(&dy, &input.data[4], sizeof(dy));
                RtlCopyMemory(&mouseData, &input.data[8], sizeof(mouseData));
                RtlCopyMemory(&flags, &input.data[12], sizeof(flags));
                RtlStringCbPrintfA(detail, sizeof(detail),
                    "Count=%u Mouse=(%ld,%ld) Data=0x%X Flags=0x%X",
                    static_cast<ULONG>(a1), dx, dy, mouseData, flags);
            } else if (input.type == 1) {
                USHORT key = 0;
                USHORT scan = 0;
                ULONG flags = 0;
                RtlCopyMemory(&key, &input.data[0], sizeof(key));
                RtlCopyMemory(&scan, &input.data[2], sizeof(scan));
                RtlCopyMemory(&flags, &input.data[4], sizeof(flags));
                RtlStringCbPrintfA(detail, sizeof(detail),
                    "Count=%u Keyboard Key=0x%X Scan=0x%X Flags=0x%X",
                    static_cast<ULONG>(a1), key, scan, flags);
            } else {
                RtlStringCbPrintfA(detail, sizeof(detail),
                    "Count=%u Type=%u InputSize=%u",
                    static_cast<ULONG>(a1), input.type, static_cast<ULONG>(a3));
            }
        } else {
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Count=%u Inputs=0x%llX InputSize=%u",
                static_cast<ULONG>(a1), a2, static_cast<ULONG>(a3));
        }
    } else if (!strcmp(name, "NtUserGetDCEx")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX ClipRegion=0x%llX Flags=0x%X",
            a1, a2, static_cast<ULONG>(a3));
    } else if (!strcmp(name, "NtUserPrintWindow")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hwnd=0x%llX Hdc=0x%llX Flags=0x%X", a1, a2, static_cast<ULONG>(a3));
    } else if (!strcmp(name, "NtUserAttachThreadInput")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Thread=%u AttachTo=%u Attach=%s",
            static_cast<ULONG>(a1), static_cast<ULONG>(a2), a3 ? "true" : "false");
    } else if (!strcmp(name, "NtUserOpenInputDesktop")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Flags=0x%X Inherit=%s Access=0x%X",
            static_cast<ULONG>(a1), a2 ? "true" : "false", static_cast<ULONG>(a3));
    } else if (!strcmp(name, "NtUserSetInformationThread") ||
        !strcmp(name, "NtUserQueryInformationThread")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Thread=0x%llX Class=%u Buffer=0x%llX Size=%u",
            a1, static_cast<ULONG>(a2), a3, static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtUserShowWindow") ||
        !strcmp(name, "NtUserShowWindowAsync")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Command=%ld",
            a1, static_cast<LONG>(a2));
    } else if (!strcmp(name, "NtUserSetFocus") ||
        !strcmp(name, "NtUserSetActiveWindow") || !strcmp(name, "NtUserSetCapture") ||
        !strcmp(name, "NtUserDestroyWindow") || !strcmp(name, "NtUserGetWindowDC")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX", a1);
    } else if (!strcmp(name, "NtUserGetAncestor")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Flags=0x%X",
            a1, static_cast<ULONG>(a2));
    } else if (!strcmp(name, "NtUserQueryWindow")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hwnd=0x%llX Class=%u",
            a1, static_cast<ULONG>(a2));
    } else if (!strcmp(name, "NtUserGetGuiResources")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Process=0x%llX Flags=0x%X",
            a1, static_cast<ULONG>(a2));
    } else if (!strcmp(name, "NtGdiGetTextExtent") ||
        !strcmp(name, "NtGdiGetTextExtentExW")) {
        char text[88] = {};
        ReadWideText(a2, static_cast<ULONG>(a3), text, sizeof(text));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hdc=0x%llX Text=\"%s\" Length=%u Limit=%u",
            a1, text, static_cast<ULONG>(a3), static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtGdiCreateRectRgn") ||
        !strcmp(name, "NtGdiCreateEllipticRgn")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Rect=(%ld,%ld)-(%ld,%ld)",
            static_cast<LONG>(a1), static_cast<LONG>(a2),
            static_cast<LONG>(a3), static_cast<LONG>(a4));
    } else if (!strcmp(name, "NtGdiCreateRoundRectRgn")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Rect=(%ld,%ld)-(%ld,%ld)",
            static_cast<LONG>(a1), static_cast<LONG>(a2),
            static_cast<LONG>(a3), static_cast<LONG>(a4));
    } else if (!strcmp(name, "NtGdiCreateCompatibleBitmap")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX Size=%ldx%ld",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a3));
    } else if (!strcmp(name, "NtGdiCreateBitmap")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Size=%ldx%ld Planes=%u BitsPerPixel=%u",
            static_cast<LONG>(a1), static_cast<LONG>(a2),
            static_cast<ULONG>(a3), static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtGdiCreateCompatibleDC")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX", a1);
    } else if (!strcmp(name, "NtGdiDeleteObjectApp")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Object=0x%llX", a1);
    } else if (!strcmp(name, "NtGdiSelectBitmap") ||
        !strcmp(name, "NtGdiSelectBrush") || !strcmp(name, "NtGdiSelectPen") ||
        !strcmp(name, "NtGdiSelectFont")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX Object=0x%llX", a1, a2);
    } else if (!strcmp(name, "NtGdiCreateSolidBrush")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Color=0x%06X Brush=0x%llX",
            static_cast<ULONG>(a1) & 0xFFFFFF, a2);
    } else if (!strcmp(name, "NtGdiCreatePen")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Style=%u Width=%ld Color=0x%06X Brush=0x%llX",
            static_cast<ULONG>(a1), static_cast<LONG>(a2),
            static_cast<ULONG>(a3) & 0xFFFFFF, a4);
    } else if (!strcmp(name, "NtGdiBitBlt") || !strcmp(name, "NtGdiStretchBlt") ||
        !strcmp(name, "NtGdiPatBlt")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX X=%ld Y=%ld Width=%ld",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a3), static_cast<LONG>(a4));
    } else if (!strcmp(name, "NtGdiRectangle") || !strcmp(name, "NtGdiEllipse") ||
        !strcmp(name, "NtGdiIntersectClipRect")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX Left=%ld Top=%ld Right=%ld",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a3), static_cast<LONG>(a4));
    } else if (!strcmp(name, "NtGdiLineTo") || !strcmp(name, "NtGdiMoveTo")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX X=%ld Y=%ld",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a3));
    } else if (!strcmp(name, "NtGdiSetPixel")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX X=%ld Y=%ld Color=0x%06X",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a3),
            static_cast<ULONG>(a4) & 0xFFFFFF);
    } else if (!strcmp(name, "NtGdiGetPixel")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX X=%ld Y=%ld",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a3));
    } else if (!strcmp(name, "NtGdiFrameRgn")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hdc=0x%llX Region=0x%llX Brush=0x%llX Width=%ld",
            a1, a2, a3, static_cast<LONG>(a4));
    } else if (!strcmp(name, "NtGdiFillRgn")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Hdc=0x%llX Region=0x%llX Brush=0x%llX", a1, a2, a3);
    } else if (!strcmp(name, "NtGdiInvertRgn")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Hdc=0x%llX Region=0x%llX", a1, a2);
    } else if (!strcmp(name, "NtGdiOffsetRgn")) {
        RtlStringCbPrintfA(detail, sizeof(detail), "Region=0x%llX X=%ld Y=%ld",
            a1, static_cast<LONG>(a2), static_cast<LONG>(a3));
    }

    EnqueueDetail(sequence, detail);
}

static void FormatHandleName(ULONG_PTR value, char* output, ULONG outputSize) {
    if (!ReadHandleObjectName(reinterpret_cast<HANDLE>(value), output, outputSize))
        RtlStringCbPrintfA(output, outputSize, "0x%llX", value);
}

static void DecodeNativeArguments(ULONGLONG sequence, const char* name,
    const ULONG_PTR* arguments) {
    if (!sequence || !name || !arguments) return;
    const ULONG_PTR a1 = arguments[0];
    const ULONG_PTR a2 = arguments[1];
    const ULONG_PTR a3 = arguments[2];
    const ULONG_PTR a4 = arguments[3];
    char detail[160] = {};

    if (!strcmp(name, "NtOpenKeyEx")) {
        char path[112] = {};
        ReadObjectPath(reinterpret_cast<POBJECT_ATTRIBUTES>(a3), path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Action=Open Key=\"%s\" Access=0x%X OpenOptions=0x%X",
            path, static_cast<ULONG>(a2), static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtOpenKey")) {
        char path[120] = {};
        ReadObjectPath(reinterpret_cast<POBJECT_ATTRIBUTES>(a3), path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Action=Open Key=\"%s\" Access=0x%X", path, static_cast<ULONG>(a2));
    } else if (!strcmp(name, "NtCreateKey")) {
        char path[112] = {};
        ReadObjectPath(reinterpret_cast<POBJECT_ATTRIBUTES>(a3), path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Action=Create/Open Key=\"%s\" Access=0x%X TitleIndex=%u",
            path, static_cast<ULONG>(a2), static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtSetValueKey")) {
        char key[88] = {};
        char value[48] = {};
        FormatHandleName(a1, key, sizeof(key));
        ReadUnicodeArgument(a2, value, sizeof(value));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Action=SetValue Key=\"%s\" Value=\"%s\" Type=%u",
            key, value, static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtDeleteValueKey")) {
        char key[88] = {};
        char value[48] = {};
        FormatHandleName(a1, key, sizeof(key));
        ReadUnicodeArgument(a2, value, sizeof(value));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Action=DeleteValue Key=\"%s\" Value=\"%s\"", key, value);
    } else if (!strcmp(name, "NtRenameKey")) {
        char key[88] = {};
        char value[48] = {};
        FormatHandleName(a1, key, sizeof(key));
        ReadUnicodeArgument(a2, value, sizeof(value));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Action=Rename Key=\"%s\" NewName=\"%s\"", key, value);
    } else if (!strcmp(name, "NtDeleteKey")) {
        char key[128] = {};
        FormatHandleName(a1, key, sizeof(key));
        RtlStringCbPrintfA(detail, sizeof(detail), "Action=Delete Key=\"%s\"", key);
    } else if (!strcmp(name, "NtQueryKey")) {
        char key[104] = {};
        FormatHandleName(a1, key, sizeof(key));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Key=\"%s\" Class=%u BufferSize=%u",
            key, static_cast<ULONG>(a2), static_cast<ULONG>(a4));
    } else if (!strcmp(name, "NtQueryValueKey")) {
        char key[80] = {};
        char value[48] = {};
        FormatHandleName(a1, key, sizeof(key));
        ReadUnicodeArgument(a2, value, sizeof(value));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Key=\"%s\" Value=\"%s\" Class=%u",
            key, value, static_cast<ULONG>(a3));
    } else if (!strcmp(name, "NtEnumerateKey") ||
        !strcmp(name, "NtEnumerateValueKey")) {
        char key[104] = {};
        FormatHandleName(a1, key, sizeof(key));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Key=\"%s\" Index=%u Class=%u",
            key, static_cast<ULONG>(a2), static_cast<ULONG>(a3));
    } else if (!strcmp(name, "NtOpenProcess")) {
        CLIENT_ID client = {};
        ULONG_PTR targetPid = 0;
        char targetName[24] = "<unresolved>";
        if (ReadUserValue(a4, &client)) {
            targetPid = reinterpret_cast<ULONG_PTR>(client.UniqueProcess);
            ResolveProcessId(client.UniqueProcess, &targetPid, targetName, sizeof(targetName));
        }
        RtlStringCbPrintfA(detail, sizeof(detail),
            "TargetPID=%llu TargetProcess=\"%s\" Access=0x%X",
            targetPid, targetName, static_cast<ULONG>(a2));
    } else if (!strcmp(name, "NtWriteVirtualMemory") ||
        !strcmp(name, "NtReadVirtualMemory")) {
        ULONG_PTR targetPid = 0;
        char targetName[24] = "<unresolved>";
        ResolveProcessHandle(reinterpret_cast<HANDLE>(a1), &targetPid,
            targetName, sizeof(targetName));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "TargetHandle=0x%llX TargetPID=%llu TargetProcess=\"%s\" Base=0x%llX Size=%llu",
            a1, targetPid, targetName, a2, a4);
    } else if (!strcmp(name, "NtAllocateVirtualMemory") ||
        !strcmp(name, "NtProtectVirtualMemory") || !strcmp(name, "NtFreeVirtualMemory")) {
        ULONG_PTR targetPid = 0;
        char targetName[24] = "<unresolved>";
        ResolveProcessHandle(reinterpret_cast<HANDLE>(a1), &targetPid,
            targetName, sizeof(targetName));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "TargetPID=%llu TargetProcess=\"%s\" BasePtr=0x%llX SizePtr=0x%llX Flags=0x%llX",
            targetPid, targetName, a2, a3, a4);
    } else if (!strcmp(name, "NtCreateFile") || !strcmp(name, "NtOpenFile")) {
        char path[112] = {};
        ReadObjectPath(reinterpret_cast<POBJECT_ATTRIBUTES>(a3), path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Path=\"%s\" Access=0x%X", path, static_cast<ULONG>(a2));
    } else if (!strcmp(name, "NtQueryAttributesFile") ||
        !strcmp(name, "NtQueryFullAttributesFile")) {
        char path[136] = {};
        ReadObjectPath(reinterpret_cast<POBJECT_ATTRIBUTES>(a1), path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Path=\"%s\"", path);
    } else if (!strcmp(name, "NtReadFile") || !strcmp(name, "NtWriteFile") ||
        !strcmp(name, "NtQueryInformationFile") || !strcmp(name, "NtSetInformationFile") ||
        !strcmp(name, "NtQueryDirectoryFile") || !strcmp(name, "NtQueryDirectoryFileEx") ||
        !strcmp(name, "NtDeviceIoControlFile") || !strcmp(name, "NtFsControlFile")) {
        char path[112] = {};
        FormatHandleName(a1, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "File=\"%s\" Arg2=0x%llX Arg3=0x%llX Arg4=0x%llX", path, a2, a3, a4);
    } else if (!strcmp(name, "NtQuerySystemInformation")) {
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Class=%u Buffer=0x%llX BufferSize=%u",
            static_cast<ULONG>(a1), a2, static_cast<ULONG>(a3));
    } else if (!strcmp(name, "NtOpenThread")) {
        CLIENT_ID client = {};
        if (ReadUserValue(a4, &client)) {
            RtlStringCbPrintfA(detail, sizeof(detail),
                "TargetPID=%llu TargetTID=%llu Access=0x%X",
                reinterpret_cast<ULONG_PTR>(client.UniqueProcess),
                reinterpret_cast<ULONG_PTR>(client.UniqueThread), static_cast<ULONG>(a2));
        }
    } else if (!strcmp(name, "NtTerminateProcess") ||
        !strcmp(name, "NtQueryInformationProcess") ||
        !strcmp(name, "NtSetInformationProcess")) {
        ULONG_PTR targetPid = 0;
        char targetName[24] = "<unresolved>";
        ResolveProcessHandle(reinterpret_cast<HANDLE>(a1), &targetPid,
            targetName, sizeof(targetName));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "TargetPID=%llu TargetProcess=\"%s\" Arg2=0x%llX Arg3=0x%llX Arg4=0x%llX",
            targetPid, targetName, a2, a3, a4);
    }

    EnqueueDetail(sequence, detail);
}

static void LogEntryArguments(ULONG syscallId, const ULONG_PTR* arguments) {
    ULONGLONG sequence = EnqueueEvent(syscallId, arguments);
    if (!sequence) return;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    USHORT category = gSyscallTable[syscallId].category;
    if (category == ScallCategoryUser || category == ScallCategoryGraphics)
        DecodeWin32kArguments(sequence, gSyscallTable[syscallId].name, arguments);
    else
        DecodeNativeArguments(sequence, gSyscallTable[syscallId].name, arguments);
}

static void __fastcall SyscallCallback(unsigned int syscallId, void** syscallFunction,
    ULONG_PTR* rawArguments) {
    UNREFERENCED_PARAMETER(syscallFunction);
    if (gUnloading) return;
    if (syscallId >= gSyscallCount || !gSyscallTable[syscallId].name[0]) return;
    InterlockedIncrement(&gHooksActive);
    __try {
        LogEntryArguments(syscallId, rawArguments);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement64(&gDetailsDropped);
    }
    InterlockedDecrement(&gHooksActive);
}


static NTSTATUS CompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR information) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS DispatchCreateCleanupClose(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    auto stack = IoGetCurrentIrpStackLocation(irp);
    if (stack->MajorFunction == IRP_MJ_CREATE) {
        ULONG pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
        InterlockedExchange(&gCaptureEnabled, 0);
        InterlockedExchange(&gExcludedPid, static_cast<LONG>(pid));

        KIRQL oldIrql;
        KeAcquireSpinLock(&gRingLock, &oldIrql);
        gTail = gHead;
        gDetailTail = gDetailHead;
        KeReleaseSpinLock(&gRingLock, oldIrql);
    } else if (stack->MajorFunction == IRP_MJ_CLEANUP) {
        // The GUI owns the only user-mode connection. Stop capture as soon as
        // its file object is cleaned up, including process termination paths
        // where the collector thread cannot send a final configuration update.
        InterlockedExchange(&gCaptureEnabled, 0);
        InterlockedExchange(&gExcludedPid, 0);
    }
    return CompleteIrp(irp, STATUS_SUCCESS, 0);
}

static PVOID GetDirectOutputBuffer(PIRP irp) {
    return irp->MdlAddress
        ? MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute)
        : nullptr;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    auto stack = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (code == SCALL_IOCTL_SET_CONFIG) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(SCALL_CONFIG))
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        auto config = static_cast<SCALL_CONFIG*>(irp->AssociatedIrp.SystemBuffer);
        if (!config || config->version != SCALL_PROTOCOL_VERSION)
            return CompleteIrp(irp, STATUS_REVISION_MISMATCH, 0);
        ULONG newCount = min(config->target_pid_count, SCALL_MAX_TARGET_PIDS);
        ULONG newNameCount = min(config->target_name_count, SCALL_MAX_TARGET_NAMES);
        InterlockedExchange(&gTargetFilterUpdating, 1);
        LONG oldCount = InterlockedCompareExchange(&gTargetPidCount, 0, 0);
        BOOLEAN filtersChanged = oldCount != static_cast<LONG>(newCount);
        for (ULONG i = 0; i < SCALL_MAX_TARGET_PIDS; ++i) {
            ULONG next = i < newCount ? config->target_pids[i] : 0;
            ULONG old = static_cast<ULONG>(InterlockedExchange(
                &gTargetPids[i], static_cast<LONG>(next)));
            if (old != next) filtersChanged = TRUE;
        }
        InterlockedExchange(&gTargetPidCount, static_cast<LONG>(newCount));
        LONG oldNameCount = InterlockedCompareExchange(&gTargetNameCount, 0, 0);
        if (oldNameCount != static_cast<LONG>(newNameCount)) filtersChanged = TRUE;
        for (ULONG i = 0; i < SCALL_MAX_TARGET_NAMES; ++i) {
            auto inputWords = reinterpret_cast<const LONG*>(config->target_names[i]);
            for (ULONG word = 0; word < SCALL_PROCESS_NAME_BYTES / sizeof(LONG); ++word) {
                LONG next = i < newNameCount ? inputWords[word] : 0;
                LONG old = InterlockedExchange(&gTargetNameWords[i][word], next);
                if (old != next) filtersChanged = TRUE;
            }
        }
        InterlockedExchange(&gTargetNameCount, static_cast<LONG>(newNameCount));
        InterlockedExchange(&gTargetFilterUpdating, 0);
        InterlockedExchange(&gOperationFilterUpdating, 1);
        for (ULONG i = 0; i < SCALL_OPERATION_MASK_WORDS; ++i) {
            ULONG old = static_cast<ULONG>(InterlockedExchange(
                &gOperationMask[i], static_cast<LONG>(config->operation_mask[i])));
            if (old != config->operation_mask[i]) filtersChanged = TRUE;
        }
        InterlockedExchange(&gOperationFilterUpdating, 0);
        ULONG requestedRuleCount = min(config->argument_rule_count, SCALL_MAX_ARGUMENT_RULES);
        LONG oldRuleCount = InterlockedCompareExchange(&gArgumentRuleCount, 0, 0);
        InterlockedExchange(&gArgumentFilterUpdating, 1);
        for (ULONG i = 0; i < SCALL_OPERATION_MASK_WORDS; ++i)
            InterlockedExchange(&gArgumentRuleOperationMask[i], 0);
        ULONG acceptedRuleCount = 0;
        for (ULONG i = 0; i < requestedRuleCount; ++i) {
            const auto& inputRule = config->argument_rules[i];
            if (inputRule.syscall_id >= SCALL_MAX_SYSCALLS ||
                (inputRule.action != SCALL_ARGUMENT_RULE_EXCEPT &&
                 inputRule.action != SCALL_ARGUMENT_RULE_ONLY) ||
                inputRule.condition_count == 0 ||
                inputRule.condition_count > SCALL_MAX_RULE_CONDITIONS) {
                continue;
            }
            BOOLEAN valid = TRUE;
            for (ULONG conditionIndex = 0; conditionIndex < inputRule.condition_count;
                 ++conditionIndex) {
                if (inputRule.conditions[conditionIndex].argument_index >=
                    SCALL_MAX_RULE_CONDITIONS) {
                    valid = FALSE;
                    break;
                }
            }
            if (!valid) continue;
            if (acceptedRuleCount >= static_cast<ULONG>(oldRuleCount) ||
                RtlCompareMemory(&gArgumentRules[acceptedRuleCount], &inputRule,
                    sizeof(inputRule)) != sizeof(inputRule)) {
                filtersChanged = TRUE;
            }
            gArgumentRules[acceptedRuleCount++] = inputRule;
            ULONG word = inputRule.syscall_id / 32;
            ULONG bit = inputRule.syscall_id % 32;
            InterlockedOr(&gArgumentRuleOperationMask[word], static_cast<LONG>(1u << bit));
        }
        for (ULONG i = acceptedRuleCount; i < SCALL_MAX_ARGUMENT_RULES; ++i)
            RtlZeroMemory(&gArgumentRules[i], sizeof(gArgumentRules[i]));
        InterlockedExchange(&gArgumentRuleCount, static_cast<LONG>(acceptedRuleCount));
        InterlockedExchange(&gArgumentFilterUpdating, 0);
        if (oldRuleCount != static_cast<LONG>(acceptedRuleCount))
            filtersChanged = TRUE;
        InterlockedExchange(&gCategoryMask, static_cast<LONG>(config->category_mask & SCALL_ALL_CATEGORIES));
        InterlockedExchange(&gCaptureEnabled, config->capture_enabled ? 1 : 0);
        InterlockedExchange(&gExcludedPid, static_cast<LONG>(config->excluded_pid));
        if (filtersChanged) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&gRingLock, &oldIrql);
            gTail = gHead;
            gDetailTail = gDetailHead;
            KeReleaseSpinLock(&gRingLock, oldIrql);
        }
        return CompleteIrp(irp, STATUS_SUCCESS, 0);
    }

    if (code == SCALL_IOCTL_GET_STATS) {
        if (outputLength < sizeof(SCALL_STATS))
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        auto stats = static_cast<SCALL_STATS*>(irp->AssociatedIrp.SystemBuffer);
        LARGE_INTEGER frequency;
        KeQueryPerformanceCounter(&frequency);
        stats->version = SCALL_PROTOCOL_VERSION;
        stats->ring_capacity = LOG_RING_ENTRIES;
        stats->ring_queued = gHead - gTail;
        stats->reserved = 0;
        stats->captured = static_cast<ULONGLONG>(InterlockedCompareExchange64(&gCaptured, 0, 0));
        stats->delivered = static_cast<ULONGLONG>(InterlockedCompareExchange64(&gDelivered, 0, 0));
        stats->dropped = static_cast<ULONGLONG>(InterlockedCompareExchange64(&gDropped, 0, 0));
        stats->qpc_frequency = static_cast<ULONGLONG>(frequency.QuadPart);
        stats->details_dropped = static_cast<ULONGLONG>(
            InterlockedCompareExchange64(&gDetailsDropped, 0, 0));
        return CompleteIrp(irp, STATUS_SUCCESS, sizeof(*stats));
    }

    if (code == SCALL_IOCTL_READ_EVENTS) {
        auto output = static_cast<SCALL_EVENT*>(GetDirectOutputBuffer(irp));
        if (!output || outputLength < sizeof(SCALL_EVENT))
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        ULONG capacity = outputLength / sizeof(SCALL_EVENT);
        ULONG copied = 0;
        KIRQL oldIrql;
        KeAcquireSpinLock(&gRingLock, &oldIrql);
        while (gTail != gHead && copied < capacity) {
            output[copied++] = gRing[gTail & (LOG_RING_ENTRIES - 1)];
            ++gTail;
        }
        KeReleaseSpinLock(&gRingLock, oldIrql);
        InterlockedAdd64(&gDelivered, copied);
        return CompleteIrp(irp, STATUS_SUCCESS, copied * sizeof(SCALL_EVENT));
    }

    if (code == SCALL_IOCTL_READ_DETAILS) {
        auto output = static_cast<SCALL_DETAIL*>(GetDirectOutputBuffer(irp));
        if (!output || outputLength < sizeof(SCALL_DETAIL))
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        ULONG capacity = outputLength / sizeof(SCALL_DETAIL);
        ULONG copied = 0;
        KIRQL oldIrql;
        KeAcquireSpinLock(&gRingLock, &oldIrql);
        while (gDetailTail != gDetailHead && copied < capacity) {
            output[copied++] = gDetailRing[gDetailTail & (DETAIL_RING_ENTRIES - 1)];
            ++gDetailTail;
        }
        KeReleaseSpinLock(&gRingLock, oldIrql);
        return CompleteIrp(irp, STATUS_SUCCESS, copied * sizeof(SCALL_DETAIL));
    }

    if (code == SCALL_IOCTL_GET_TABLE) {
        auto output = static_cast<SCALL_SYSCALL_INFO*>(GetDirectOutputBuffer(irp));
        if (!output) return CompleteIrp(irp, STATUS_INVALID_USER_BUFFER, 0);
        ULONG capacity = outputLength / sizeof(SCALL_SYSCALL_INFO);
        ULONG copied = 0;
        for (ULONG id = 0; id < gSyscallCount && copied < capacity; ++id) {
            if (!gSyscallTable[id].name[0]) continue;
            output[copied].syscall_id = static_cast<USHORT>(id);
            output[copied].category = gSyscallTable[id].category;
            RtlStringCbCopyA(output[copied].name, sizeof(output[copied].name), gSyscallTable[id].name);
            ++copied;
        }
        return CompleteIrp(irp, STATUS_SUCCESS, copied * sizeof(SCALL_SYSCALL_INFO));
    }
    return CompleteIrp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static void DriverUnload(PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);
    InterlockedExchange(&gUnloading, 1);
    InterlockedExchange(&gCaptureEnabled, 0);
    EtwHookManager::GetInstance()->Destroy();
    while (InterlockedCompareExchange(&gHooksActive, 0, 0) != 0)
        KeStallExecutionProcessor(50);
    UNICODE_STRING dosName;
    RtlInitUnicodeString(&dosName, SCALL_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosName);
    if (gDeviceObject) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = nullptr;
    }
    if (gRing) {
        ExFreePoolWithTag(gRing, POOL_TAG);
        gRing = nullptr;
    }
    if (gDetailRing) {
        ExFreePoolWithTag(gDetailRing, POOL_TAG);
        gDetailRing = nullptr;
    }
}

static NTSTATUS InitializeMonitorDriver(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);
    KeInitializeSpinLock(&gRingLock);
    gRing = static_cast<SCALL_EVENT*>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED, static_cast<SIZE_T>(LOG_RING_ENTRIES) * sizeof(SCALL_EVENT), POOL_TAG));
    if (!gRing) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(gRing, static_cast<SIZE_T>(LOG_RING_ENTRIES) * sizeof(SCALL_EVENT));
    gDetailRing = static_cast<SCALL_DETAIL*>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED, static_cast<SIZE_T>(DETAIL_RING_ENTRIES) * sizeof(SCALL_DETAIL), POOL_TAG));
    if (!gDetailRing) {
        ExFreePoolWithTag(gRing, POOL_TAG);
        gRing = nullptr;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(gDetailRing,
        static_cast<SIZE_T>(DETAIL_RING_ENTRIES) * sizeof(SCALL_DETAIL));

    NTSTATUS status = BuildSyscallTable();
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(gRing, POOL_TAG);
        gRing = nullptr;
        ExFreePoolWithTag(gDetailRing, POOL_TAG);
        gDetailRing = nullptr;
        return status;
    }
    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    RtlInitUnicodeString(&deviceName, SCALL_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, SCALL_DOS_DEVICE_NAME);
    status = IoCreateDevice(driverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceObject);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(gRing, POOL_TAG);
        gRing = nullptr;
        ExFreePoolWithTag(gDetailRing, POOL_TAG);
        gDetailRing = nullptr;
        return status;
    }
    status = IoCreateSymbolicLink(&dosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = nullptr;
        ExFreePoolWithTag(gRing, POOL_TAG);
        gRing = nullptr;
        ExFreePoolWithTag(gDetailRing, POOL_TAG);
        gDetailRing = nullptr;
        return status;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateCleanupClose;
    driverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchCreateCleanupClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateCleanupClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    driverObject->DriverUnload = DriverUnload;
    gDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    status = EtwHookManager::GetInstance()->Initialize(SyscallCallback);
    if (!NT_SUCCESS(status)) {
        DriverUnload(driverObject);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[scall-monitor] ready: %lu syscalls, %u ring entries\n", gSyscallCount, LOG_RING_ENTRIES);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry() {
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, L"\\Driver\\ScallMonitor");
    return IoCreateDriver(&driverName, InitializeMonitorDriver);
}
