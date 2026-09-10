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
#define HANDLE_NAME_ENTRIES (2 * 1024)
#define RESULT_SLOT_ENTRIES (4 * 1024)
#define RESULT_STACK_DEPTH 4
#define POOL_TAG 'gLsS'

static_assert((LOG_RING_ENTRIES & (LOG_RING_ENTRIES - 1)) == 0, "ring size must be a power of two");
static_assert(sizeof(SCALL_EVENT) == 80, "SCALL_EVENT ABI changed");
static_assert(sizeof(SCALL_CONFIG) == 856, "SCALL_CONFIG ABI changed");
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
static KSPIN_LOCK gHandleNameLock;
static KSPIN_LOCK gResultLock;
static PDEVICE_OBJECT gDeviceObject = nullptr;

struct HANDLE_NAME_ENTRY {
    PEPROCESS process;
    HANDLE handle;
    PVOID object;
    char name[112];
};

static HANDLE_NAME_ENTRY gHandleNames[HANDLE_NAME_ENTRIES] = {};
static ULONG gHandleNameNext = 0;

struct RESULT_SLOT {
    PETHREAD thread;
    ULONG depth;
    ULONGLONG sequences[RESULT_STACK_DEPTH];
};

static RESULT_SLOT gResultSlots[RESULT_SLOT_ENTRIES] = {};

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
static volatile LONG gExcludedPid = 0;
static volatile LONG gCategoryMask = SCALL_ALL_CATEGORIES;
static volatile LONG64 gSequence = 0;
static volatile LONG64 gCaptured = 0;
static volatile LONG64 gDelivered = 0;
static volatile LONG64 gDropped = 0;
static volatile LONG64 gDetailsDropped = 0;
static PVOID volatile gOriginalFunctions[SCALL_MAX_SYSCALLS] = {};
static PVOID gDetourFunctions[SCALL_MAX_SYSCALLS] = {};

static ULONG gIdxCreateFile = MAXULONG;
static ULONG gIdxOpenProcess = MAXULONG;
static ULONG gIdxAllocateVirtualMemory = MAXULONG;
static ULONG gIdxProtectVirtualMemory = MAXULONG;
static ULONG gIdxWriteVirtualMemory = MAXULONG;
static ULONG gIdxCreateThreadEx = MAXULONG;
static ULONG gIdxOpenKey = MAXULONG;
static ULONG gIdxSetValueKey = MAXULONG;
static ULONG gIdxOpenFile = MAXULONG;
static ULONG gIdxQueryAttributesFile = MAXULONG;
static ULONG gIdxQueryFullAttributesFile = MAXULONG;
static ULONG gIdxQueryDirectoryFile = MAXULONG;
static ULONG gIdxQueryDirectoryFileEx = MAXULONG;
static ULONG gIdxDeviceIoControlFile = MAXULONG;
static ULONG gIdxOpenKeyEx = MAXULONG;
static ULONG gIdxCreateKey = MAXULONG;
static ULONG gIdxQueryValueKey = MAXULONG;
static ULONG gIdxDeleteValueKey = MAXULONG;
static ULONG gIdxRenameKey = MAXULONG;
static ULONG gIdxOpenSection = MAXULONG;
static ULONG gIdxCreateEvent = MAXULONG;
static ULONG gIdxOpenEvent = MAXULONG;
static ULONG gIdxCreateMutant = MAXULONG;
static ULONG gIdxOpenMutant = MAXULONG;
static ULONG gIdxCreateSemaphore = MAXULONG;
static ULONG gIdxOpenSemaphore = MAXULONG;
static ULONG gIdxCreateTimer = MAXULONG;
static ULONG gIdxOpenDirectoryObject = MAXULONG;
static ULONG gIdxOpenSymbolicLinkObject = MAXULONG;
static ULONG gIdxConnectPort = MAXULONG;
static ULONG gIdxSecureConnectPort = MAXULONG;
static ULONG gIdxAlpcConnectPort = MAXULONG;
static ULONG gIdxAlpcConnectPortEx = MAXULONG;
static ULONG gIdxLoadDriver = MAXULONG;
static ULONG gIdxReadFile = MAXULONG;
static ULONG gIdxWriteFile = MAXULONG;
static ULONG gIdxQueryInformationFile = MAXULONG;
static ULONG gIdxSetInformationFile = MAXULONG;
static ULONG gIdxFsControlFile = MAXULONG;
static ULONG gIdxQueryKey = MAXULONG;
static ULONG gIdxDeleteKey = MAXULONG;
static ULONG gIdxEnumerateKey = MAXULONG;
static ULONG gIdxEnumerateValueKey = MAXULONG;
static ULONG gIdxFreeVirtualMemory = MAXULONG;
static ULONG gIdxReadVirtualMemory = MAXULONG;
static ULONG gIdxMapViewOfSection = MAXULONG;
static ULONG gIdxUnmapViewOfSection = MAXULONG;
static ULONG gIdxTerminateProcess = MAXULONG;
static ULONG gIdxQueryInformationProcess = MAXULONG;
static ULONG gIdxSetInformationProcess = MAXULONG;
static ULONG gIdxOpenThread = MAXULONG;
static ULONG gIdxSuspendThread = MAXULONG;
static ULONG gIdxResumeThread = MAXULONG;
static ULONG gIdxQueueApcThread = MAXULONG;
static ULONG gIdxOpenProcessToken = MAXULONG;
static ULONG gIdxOpenThreadTokenEx = MAXULONG;
static ULONG gIdxAdjustPrivilegesToken = MAXULONG;
static ULONG gIdxReleaseMutant = MAXULONG;
static ULONG gIdxAlpcSendWaitReceivePort = MAXULONG;
static ULONG gIdxQuerySystemInformation = MAXULONG;

static NTSTATUS DetCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
static NTSTATUS DetOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
static NTSTATUS DetAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
static NTSTATUS DetProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
static NTSTATUS DetWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
static NTSTATUS DetCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID,
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
static NTSTATUS DetOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static NTSTATUS DetSetValueKey(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
static NTSTATUS DetOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
static NTSTATUS DetQueryAttributesFile(POBJECT_ATTRIBUTES, PVOID);
static NTSTATUS DetQueryFullAttributesFile(POBJECT_ATTRIBUTES, PVOID);
static NTSTATUS DetQueryDirectoryFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID,
    ULONG, ULONG, BOOLEAN, PUNICODE_STRING, BOOLEAN);
static NTSTATUS DetQueryDirectoryFileEx(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID,
    ULONG, ULONG, ULONG, PUNICODE_STRING);
static NTSTATUS DetDeviceIoControlFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG,
    PVOID, ULONG, PVOID, ULONG);
static NTSTATUS DetOpenKeyEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
static NTSTATUS DetCreateKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING,
    ULONG, PULONG);
static NTSTATUS DetQueryValueKey(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
static NTSTATUS DetDeleteValueKey(HANDLE, PUNICODE_STRING);
static NTSTATUS DetRenameKey(HANDLE, PUNICODE_STRING);
static NTSTATUS DetOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static NTSTATUS DetCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE, BOOLEAN);
static NTSTATUS DetOpenEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static NTSTATUS DetCreateMutant(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
static NTSTATUS DetOpenMutant(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static NTSTATUS DetCreateSemaphore(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
static NTSTATUS DetOpenSemaphore(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static NTSTATUS DetCreateTimer(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TIMER_TYPE);
static NTSTATUS DetOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static NTSTATUS DetOpenSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static NTSTATUS DetConnectPort(PHANDLE, PUNICODE_STRING, PVOID, PVOID, PVOID, PULONG, PVOID, PULONG);
static NTSTATUS DetSecureConnectPort(PHANDLE, PUNICODE_STRING, PVOID, PVOID, PVOID, PVOID,
    PULONG, PVOID, PULONG);
static NTSTATUS DetAlpcConnectPort(PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PVOID, ULONG,
    PVOID, PVOID, PSIZE_T, PVOID, PVOID, PVOID);
static NTSTATUS DetAlpcConnectPortEx(PHANDLE, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, PVOID,
    ULONG, PVOID, PVOID, PSIZE_T, PVOID, PVOID, PVOID);
static NTSTATUS DetLoadDriver(PUNICODE_STRING);
static NTSTATUS DetReadFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PVOID, PVOID);
static NTSTATUS DetWriteFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PVOID, PVOID);
static NTSTATUS DetQueryInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
static NTSTATUS DetSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
static NTSTATUS DetFsControlFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID,
    ULONG, PVOID, ULONG);
static NTSTATUS DetQueryKey(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NTSTATUS DetDeleteKey(HANDLE);
static NTSTATUS DetEnumerateKey(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
static NTSTATUS DetEnumerateValueKey(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
static NTSTATUS DetFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);
static NTSTATUS DetReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
static NTSTATUS DetMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PVOID, PSIZE_T,
    ULONG, ULONG, ULONG);
static NTSTATUS DetUnmapViewOfSection(HANDLE, PVOID);
static NTSTATUS DetTerminateProcess(HANDLE, NTSTATUS);
static NTSTATUS DetQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NTSTATUS DetSetInformationProcess(HANDLE, ULONG, PVOID, ULONG);
static NTSTATUS DetOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
static NTSTATUS DetSuspendThread(HANDLE, PULONG);
static NTSTATUS DetResumeThread(HANDLE, PULONG);
static NTSTATUS DetQueueApcThread(HANDLE, PVOID, PVOID, PVOID, PVOID);
static NTSTATUS DetOpenProcessToken(HANDLE, ACCESS_MASK, PHANDLE);
static NTSTATUS DetOpenThreadTokenEx(HANDLE, ACCESS_MASK, BOOLEAN, ULONG, PHANDLE);
static NTSTATUS DetAdjustPrivilegesToken(HANDLE, BOOLEAN, PVOID, ULONG, PVOID, PULONG);
static NTSTATUS DetReleaseMutant(HANDLE, PULONG);
static NTSTATUS DetAlpcSendWaitReceivePort(HANDLE, ULONG, PVOID, PVOID, PVOID, PSIZE_T, PVOID, PVOID);
static NTSTATUS DetQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

struct IMPORTANT_DETOUR {
    const char* name;
    ULONG* index;
    PVOID function;
};

static IMPORTANT_DETOUR gImportantDetours[] = {
    { "NtCreateFile", &gIdxCreateFile, reinterpret_cast<PVOID>(DetCreateFile) },
    { "NtOpenProcess", &gIdxOpenProcess, reinterpret_cast<PVOID>(DetOpenProcess) },
    { "NtAllocateVirtualMemory", &gIdxAllocateVirtualMemory, reinterpret_cast<PVOID>(DetAllocateVirtualMemory) },
    { "NtProtectVirtualMemory", &gIdxProtectVirtualMemory, reinterpret_cast<PVOID>(DetProtectVirtualMemory) },
    { "NtWriteVirtualMemory", &gIdxWriteVirtualMemory, reinterpret_cast<PVOID>(DetWriteVirtualMemory) },
    { "NtCreateThreadEx", &gIdxCreateThreadEx, reinterpret_cast<PVOID>(DetCreateThreadEx) },
    { "NtOpenKey", &gIdxOpenKey, reinterpret_cast<PVOID>(DetOpenKey) },
    { "NtSetValueKey", &gIdxSetValueKey, reinterpret_cast<PVOID>(DetSetValueKey) },
    { "NtOpenFile", &gIdxOpenFile, reinterpret_cast<PVOID>(DetOpenFile) },
    { "NtQueryAttributesFile", &gIdxQueryAttributesFile, reinterpret_cast<PVOID>(DetQueryAttributesFile) },
    { "NtQueryFullAttributesFile", &gIdxQueryFullAttributesFile, reinterpret_cast<PVOID>(DetQueryFullAttributesFile) },
    { "NtQueryDirectoryFile", &gIdxQueryDirectoryFile, reinterpret_cast<PVOID>(DetQueryDirectoryFile) },
    { "NtQueryDirectoryFileEx", &gIdxQueryDirectoryFileEx, reinterpret_cast<PVOID>(DetQueryDirectoryFileEx) },
    { "NtDeviceIoControlFile", &gIdxDeviceIoControlFile, reinterpret_cast<PVOID>(DetDeviceIoControlFile) },
    { "NtOpenKeyEx", &gIdxOpenKeyEx, reinterpret_cast<PVOID>(DetOpenKeyEx) },
    { "NtCreateKey", &gIdxCreateKey, reinterpret_cast<PVOID>(DetCreateKey) },
    { "NtQueryValueKey", &gIdxQueryValueKey, reinterpret_cast<PVOID>(DetQueryValueKey) },
    { "NtDeleteValueKey", &gIdxDeleteValueKey, reinterpret_cast<PVOID>(DetDeleteValueKey) },
    { "NtRenameKey", &gIdxRenameKey, reinterpret_cast<PVOID>(DetRenameKey) },
    { "NtOpenSection", &gIdxOpenSection, reinterpret_cast<PVOID>(DetOpenSection) },
    { "NtCreateEvent", &gIdxCreateEvent, reinterpret_cast<PVOID>(DetCreateEvent) },
    { "NtOpenEvent", &gIdxOpenEvent, reinterpret_cast<PVOID>(DetOpenEvent) },
    { "NtCreateMutant", &gIdxCreateMutant, reinterpret_cast<PVOID>(DetCreateMutant) },
    { "NtOpenMutant", &gIdxOpenMutant, reinterpret_cast<PVOID>(DetOpenMutant) },
    { "NtCreateSemaphore", &gIdxCreateSemaphore, reinterpret_cast<PVOID>(DetCreateSemaphore) },
    { "NtOpenSemaphore", &gIdxOpenSemaphore, reinterpret_cast<PVOID>(DetOpenSemaphore) },
    { "NtCreateTimer", &gIdxCreateTimer, reinterpret_cast<PVOID>(DetCreateTimer) },
    { "NtOpenDirectoryObject", &gIdxOpenDirectoryObject, reinterpret_cast<PVOID>(DetOpenDirectoryObject) },
    { "NtOpenSymbolicLinkObject", &gIdxOpenSymbolicLinkObject, reinterpret_cast<PVOID>(DetOpenSymbolicLinkObject) },
    { "NtConnectPort", &gIdxConnectPort, reinterpret_cast<PVOID>(DetConnectPort) },
    { "NtSecureConnectPort", &gIdxSecureConnectPort, reinterpret_cast<PVOID>(DetSecureConnectPort) },
    { "NtAlpcConnectPort", &gIdxAlpcConnectPort, reinterpret_cast<PVOID>(DetAlpcConnectPort) },
    { "NtAlpcConnectPortEx", &gIdxAlpcConnectPortEx, reinterpret_cast<PVOID>(DetAlpcConnectPortEx) },
    { "NtLoadDriver", &gIdxLoadDriver, reinterpret_cast<PVOID>(DetLoadDriver) },
    { "NtReadFile", &gIdxReadFile, reinterpret_cast<PVOID>(DetReadFile) },
    { "NtWriteFile", &gIdxWriteFile, reinterpret_cast<PVOID>(DetWriteFile) },
    { "NtQueryInformationFile", &gIdxQueryInformationFile, reinterpret_cast<PVOID>(DetQueryInformationFile) },
    { "NtSetInformationFile", &gIdxSetInformationFile, reinterpret_cast<PVOID>(DetSetInformationFile) },
    { "NtFsControlFile", &gIdxFsControlFile, reinterpret_cast<PVOID>(DetFsControlFile) },
    { "NtQueryKey", &gIdxQueryKey, reinterpret_cast<PVOID>(DetQueryKey) },
    { "NtDeleteKey", &gIdxDeleteKey, reinterpret_cast<PVOID>(DetDeleteKey) },
    { "NtEnumerateKey", &gIdxEnumerateKey, reinterpret_cast<PVOID>(DetEnumerateKey) },
    { "NtEnumerateValueKey", &gIdxEnumerateValueKey, reinterpret_cast<PVOID>(DetEnumerateValueKey) },
    { "NtFreeVirtualMemory", &gIdxFreeVirtualMemory, reinterpret_cast<PVOID>(DetFreeVirtualMemory) },
    { "NtReadVirtualMemory", &gIdxReadVirtualMemory, reinterpret_cast<PVOID>(DetReadVirtualMemory) },
    { "NtMapViewOfSection", &gIdxMapViewOfSection, reinterpret_cast<PVOID>(DetMapViewOfSection) },
    { "NtUnmapViewOfSection", &gIdxUnmapViewOfSection, reinterpret_cast<PVOID>(DetUnmapViewOfSection) },
    { "NtTerminateProcess", &gIdxTerminateProcess, reinterpret_cast<PVOID>(DetTerminateProcess) },
    { "NtQueryInformationProcess", &gIdxQueryInformationProcess, reinterpret_cast<PVOID>(DetQueryInformationProcess) },
    { "NtSetInformationProcess", &gIdxSetInformationProcess, reinterpret_cast<PVOID>(DetSetInformationProcess) },
    { "NtOpenThread", &gIdxOpenThread, reinterpret_cast<PVOID>(DetOpenThread) },
    { "NtSuspendThread", &gIdxSuspendThread, reinterpret_cast<PVOID>(DetSuspendThread) },
    { "NtResumeThread", &gIdxResumeThread, reinterpret_cast<PVOID>(DetResumeThread) },
    { "NtQueueApcThread", &gIdxQueueApcThread, reinterpret_cast<PVOID>(DetQueueApcThread) },
    { "NtOpenProcessToken", &gIdxOpenProcessToken, reinterpret_cast<PVOID>(DetOpenProcessToken) },
    { "NtOpenThreadTokenEx", &gIdxOpenThreadTokenEx, reinterpret_cast<PVOID>(DetOpenThreadTokenEx) },
    { "NtAdjustPrivilegesToken", &gIdxAdjustPrivilegesToken, reinterpret_cast<PVOID>(DetAdjustPrivilegesToken) },
    { "NtReleaseMutant", &gIdxReleaseMutant, reinterpret_cast<PVOID>(DetReleaseMutant) },
    { "NtAlpcSendWaitReceivePort", &gIdxAlpcSendWaitReceivePort, reinterpret_cast<PVOID>(DetAlpcSendWaitReceivePort) },
    { "NtQuerySystemInformation", &gIdxQuerySystemInformation, reinterpret_cast<PVOID>(DetQuerySystemInformation) },
};

static USHORT ClassifySyscall(const char* name) {
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

static void ParsePeExports(PVOID imageBase) {
    __try {
        auto dos = static_cast<PIMAGE_DOS_HEADER>(imageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<PUCHAR>(imageBase) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        ULONG exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRva) return;
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
            gSyscallTable[id].category = ClassifySyscall(name);
            for (auto& detour : gImportantDetours) {
                if (strcmp(name, detour.name) == 0) {
                    *detour.index = id;
                    gDetourFunctions[id] = detour.function;
                    break;
                }
            }
            if (id >= gSyscallCount) gSyscallCount = id + 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        gSyscallCount = 0;
    }
}

static NTSTATUS BuildSyscallTable() {
    UNICODE_STRING dllName;
    RtlInitUnicodeString(&dllName, L"\\SystemRoot\\System32\\ntdll.dll");
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
    ParsePeExports(base);
    ZwUnmapViewOfSection(ZwCurrentProcess(), base);
    return gSyscallCount ? STATUS_SUCCESS : STATUS_NOT_FOUND;
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

static ULONGLONG EnqueueEvent(ULONG syscallId, const ULONG_PTR* arguments = nullptr) {
    if (gUnloading || !gCaptureEnabled || syscallId >= SCALL_MAX_SYSCALLS) return 0;
    if (!OperationEnabled(syscallId)) return 0;
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

static void EnqueueDetailKind(ULONGLONG sequence, USHORT kind, const char* text) {
    if (!sequence || !text || !text[0]) return;
    SCALL_DETAIL detail = {};
    detail.sequence = sequence;
    detail.kind = kind;
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

static void EnqueueDetail(ULONGLONG sequence, const char* text) {
    EnqueueDetailKind(sequence, 0, text);
}

static RESULT_SLOT* FindResultSlot(PETHREAD thread, BOOLEAN create) {
    constexpr ULONG_PTR tombstone = 1;
    ULONG start = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(thread) >> 4) &
        (RESULT_SLOT_ENTRIES - 1);
    RESULT_SLOT* reusable = nullptr;
    for (ULONG probe = 0; probe < RESULT_SLOT_ENTRIES; ++probe) {
        auto slot = &gResultSlots[(start + probe) & (RESULT_SLOT_ENTRIES - 1)];
        if (slot->thread == thread) return slot;
        ULONG_PTR owner = reinterpret_cast<ULONG_PTR>(slot->thread);
        if (owner == tombstone) {
            if (!reusable) reusable = slot;
            continue;
        }
        if (!owner) return create ? (reusable ? reusable : slot) : nullptr;
    }
    return create ? reusable : nullptr;
}

static BOOLEAN BeginImportant(ULONGLONG sequence) {
    if (!sequence) return FALSE;
    PETHREAD thread = PsGetCurrentThread();
    KIRQL oldIrql;
    KeAcquireSpinLock(&gResultLock, &oldIrql);
    auto slot = FindResultSlot(thread, TRUE);
    BOOLEAN stored = slot && slot->depth < RESULT_STACK_DEPTH;
    if (stored) {
        if (slot->thread != thread) {
            slot->thread = thread;
            slot->depth = 0;
        }
        slot->sequences[slot->depth++] = sequence;
    }
    KeReleaseSpinLock(&gResultLock, oldIrql);
    if (!stored) InterlockedIncrement64(&gDetailsDropped);
    return stored;
}

static ULONGLONG CurrentImportantSequence() {
    PETHREAD thread = PsGetCurrentThread();
    KIRQL oldIrql;
    KeAcquireSpinLock(&gResultLock, &oldIrql);
    auto slot = FindResultSlot(thread, FALSE);
    ULONGLONG sequence = slot && slot->depth ? slot->sequences[slot->depth - 1] : 0;
    KeReleaseSpinLock(&gResultLock, oldIrql);
    return sequence;
}

static void LogImportant(ULONG syscallId, const char* text) {
    UNREFERENCED_PARAMETER(syscallId);
    EnqueueDetail(CurrentImportantSequence(), text);
}

static void LogCurrentResult(NTSTATUS status) {
    PETHREAD thread = PsGetCurrentThread();
    KIRQL oldIrql;
    KeAcquireSpinLock(&gResultLock, &oldIrql);
    auto slot = FindResultSlot(thread, FALSE);
    ULONGLONG sequence = slot && slot->depth ? slot->sequences[--slot->depth] : 0;
    if (slot && !slot->depth) slot->thread = reinterpret_cast<PETHREAD>(1);
    KeReleaseSpinLock(&gResultLock, oldIrql);
    if (!sequence) return;
    char result[32];
    RtlStringCbPrintfA(result, sizeof(result), "0x%08X", static_cast<ULONG>(status));
    EnqueueDetailKind(sequence, 1, result);
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

static void ReadObjectPath(POBJECT_ATTRIBUTES attributes, char* output, ULONG outputSize) {
    output[0] = 0;
    if (!attributes || outputSize < 2) return;
    __try {
        ReadUnicode(attributes->ObjectName, output, outputSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlStringCbCopyA(output, outputSize, "<unreadable>");
    }
}

static void RememberHandleName(HANDLE handle, const char* name) {
    if (!handle || !name || !name[0]) return;
    PVOID object = nullptr;
    if (!NT_SUCCESS(ObReferenceObjectByHandle(
        handle, 0, nullptr, UserMode, &object, nullptr))) return;
    PEPROCESS process = PsGetCurrentProcess();
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHandleNameLock, &oldIrql);
    HANDLE_NAME_ENTRY* entry = nullptr;
    for (ULONG i = 0; i < HANDLE_NAME_ENTRIES; ++i) {
        if (gHandleNames[i].process == process && gHandleNames[i].handle == handle) {
            entry = &gHandleNames[i];
            break;
        }
    }
    if (!entry) entry = &gHandleNames[gHandleNameNext++ & (HANDLE_NAME_ENTRIES - 1)];
    entry->process = process;
    entry->handle = handle;
    entry->object = object;
    RtlStringCbCopyA(entry->name, sizeof(entry->name), name);
    KeReleaseSpinLock(&gHandleNameLock, oldIrql);
    ObDereferenceObject(object);
}

static BOOLEAN FindHandleName(HANDLE handle, char* output, ULONG outputSize) {
    output[0] = 0;
    if (!handle || outputSize < 2) return FALSE;
    PVOID object = nullptr;
    if (!NT_SUCCESS(ObReferenceObjectByHandle(
        handle, 0, nullptr, UserMode, &object, nullptr))) return FALSE;
    PEPROCESS process = PsGetCurrentProcess();
    BOOLEAN found = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHandleNameLock, &oldIrql);
    for (ULONG i = 0; i < HANDLE_NAME_ENTRIES; ++i) {
        if (gHandleNames[i].process == process && gHandleNames[i].handle == handle &&
            gHandleNames[i].object == object) {
            RtlStringCbCopyA(output, outputSize, gHandleNames[i].name);
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gHandleNameLock, oldIrql);
    ObDereferenceObject(object);
    return found;
}

static void RememberReturnedHandle(PHANDLE returnedHandle, const char* name, NTSTATUS status) {
    if (!NT_SUCCESS(status) || !returnedHandle || !name || !name[0]) return;
    __try {
        RememberHandleName(*returnedHandle, name);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void LogRawArguments(ULONG syscallId, const ULONG_PTR* arguments) {
    EnqueueEvent(syscallId, arguments);
}

static void __fastcall SyscallCallback(unsigned int syscallId, void** syscallFunction,
    ULONG_PTR* rawArguments) {
    if (gUnloading) return;
    if (syscallId >= gSyscallCount || !gSyscallTable[syscallId].name[0]) return;
    InterlockedIncrement(&gHooksActive);
    PVOID detour = syscallId < SCALL_MAX_SYSCALLS ? gDetourFunctions[syscallId] : nullptr;
    if (detour && gCaptureEnabled) {
        ULONG pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
        ULONG excludedPid = static_cast<ULONG>(InterlockedCompareExchange(&gExcludedPid, 0, 0));
        ULONG mask = static_cast<ULONG>(InterlockedCompareExchange(&gCategoryMask, 0, 0));
        USHORT category = gSyscallTable[syscallId].category;
        if (pid != excludedPid && MatchesTargetProcess(pid) && OperationEnabled(syscallId) &&
            (mask & (1u << category))) {
            ULONGLONG sequence = EnqueueEvent(syscallId, rawArguments);
            if (!sequence) {
                InterlockedDecrement(&gHooksActive);
                return;
            }
            PVOID original = *syscallFunction;
            if (!original || reinterpret_cast<ULONG_PTR>(original) <
                reinterpret_cast<ULONG_PTR>(MmSystemRangeStart)) {
                InterlockedDecrement(&gHooksActive);
                return;
            }
            if (!gOriginalFunctions[syscallId])
                InterlockedCompareExchangePointer(
                    &gOriginalFunctions[syscallId], original, nullptr);
            if (!gOriginalFunctions[syscallId]) {
                InterlockedDecrement(&gHooksActive);
                return;
            }
            if (!BeginImportant(sequence)) {
                InterlockedDecrement(&gHooksActive);
                return;
            }
            *syscallFunction = detour;
            InterlockedDecrement(&gHooksActive);
            return;
        }
    }
    LogRawArguments(syscallId, rawArguments);
    InterlockedDecrement(&gHooksActive);
}

static NTSTATUS DetCreateFile(PHANDLE file, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    PIO_STATUS_BLOCK io, PLARGE_INTEGER allocationSize, ULONG fileAttributes, ULONG shareAccess,
    ULONG disposition, ULONG options, PVOID eaBuffer, ULONG eaLength) {
    InterlockedIncrement(&gHooksActive);
    char path[96] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Path=\"%s\" Access=0x%X Disposition=%u Options=0x%X", path, access, disposition, options);
        LogImportant(gIdxCreateFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetCreateFile)>(gOriginalFunctions[gIdxCreateFile]);
    NTSTATUS status = original ? original(file, access, attributes, io, allocationSize, fileAttributes,
        shareAccess, disposition, options, eaBuffer, eaLength) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(file, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenProcess(PHANDLE process, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes, PCLIENT_ID clientId) {
    InterlockedIncrement(&gHooksActive);
    __try {
        ULONG_PTR targetPid = clientId ? reinterpret_cast<ULONG_PTR>(clientId->UniqueProcess) : 0;
        char detail[160];
        RtlStringCbPrintfA(detail, sizeof(detail), "TargetPID=%llu Access=0x%X",
            static_cast<ULONGLONG>(targetPid), access);
        LogImportant(gIdxOpenProcess, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenProcess)>(gOriginalFunctions[gIdxOpenProcess]);
    NTSTATUS status = original ? original(process, access, attributes, clientId) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetAllocateVirtualMemory(HANDLE process, PVOID* base, ULONG_PTR zeroBits,
    PSIZE_T size, ULONG allocationType, ULONG protection) {
    InterlockedIncrement(&gHooksActive);
    __try {
        PVOID address = base ? *base : nullptr;
        SIZE_T bytes = size ? *size : 0;
        char detail[160];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Process=0x%llX Base=0x%llX Size=0x%llX Type=0x%X Protect=0x%X",
            reinterpret_cast<ULONGLONG>(process), reinterpret_cast<ULONGLONG>(address),
            static_cast<ULONGLONG>(bytes), allocationType, protection);
        LogImportant(gIdxAllocateVirtualMemory, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetAllocateVirtualMemory)>(
        gOriginalFunctions[gIdxAllocateVirtualMemory]);
    NTSTATUS status = original ? original(process, base, zeroBits, size, allocationType, protection)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetProtectVirtualMemory(HANDLE process, PVOID* base, PSIZE_T size,
    ULONG protection, PULONG oldProtection) {
    InterlockedIncrement(&gHooksActive);
    __try {
        PVOID address = base ? *base : nullptr;
        SIZE_T bytes = size ? *size : 0;
        char detail[160];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Process=0x%llX Base=0x%llX Size=0x%llX NewProtect=0x%X",
            reinterpret_cast<ULONGLONG>(process), reinterpret_cast<ULONGLONG>(address),
            static_cast<ULONGLONG>(bytes), protection);
        LogImportant(gIdxProtectVirtualMemory, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetProtectVirtualMemory)>(
        gOriginalFunctions[gIdxProtectVirtualMemory]);
    NTSTATUS status = original ? original(process, base, size, protection, oldProtection)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetWriteVirtualMemory(HANDLE process, PVOID base, PVOID buffer,
    SIZE_T size, PSIZE_T written) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[160];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Process=0x%llX Base=0x%llX Buffer=0x%llX Size=0x%llX",
            reinterpret_cast<ULONGLONG>(process), reinterpret_cast<ULONGLONG>(base),
            reinterpret_cast<ULONGLONG>(buffer), static_cast<ULONGLONG>(size));
        LogImportant(gIdxWriteVirtualMemory, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetWriteVirtualMemory)>(
        gOriginalFunctions[gIdxWriteVirtualMemory]);
    NTSTATUS status = original ? original(process, base, buffer, size, written)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetCreateThreadEx(PHANDLE thread, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes, HANDLE process, PVOID startAddress, PVOID parameter,
    ULONG flags, SIZE_T zeroBits, SIZE_T stackSize, SIZE_T maximumStackSize,
    PVOID attributeList) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[160];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Process=0x%llX Start=0x%llX Parameter=0x%llX Access=0x%X Flags=0x%X",
            reinterpret_cast<ULONGLONG>(process), reinterpret_cast<ULONGLONG>(startAddress),
            reinterpret_cast<ULONGLONG>(parameter), access, flags);
        LogImportant(gIdxCreateThreadEx, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetCreateThreadEx)>(
        gOriginalFunctions[gIdxCreateThreadEx]);
    NTSTATUS status = original ? original(thread, access, attributes, process, startAddress, parameter,
        flags, zeroBits, stackSize, maximumStackSize, attributeList) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenKey(PHANDLE key, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes) {
    InterlockedIncrement(&gHooksActive);
    char path[112] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Key=\"%s\" Access=0x%X", path, access);
        LogImportant(gIdxOpenKey, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenKey)>(gOriginalFunctions[gIdxOpenKey]);
    NTSTATUS status = original ? original(key, access, attributes) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(key, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetSetValueKey(HANDLE key, PUNICODE_STRING valueName, ULONG titleIndex,
    ULONG type, PVOID data, ULONG dataSize) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[72], keyPath[64];
        char detail[160];
        ReadUnicode(valueName, name, sizeof(name));
        if (FindHandleName(key, keyPath, sizeof(keyPath)))
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Key=\"%s\" Value=\"%s\" Type=%u Size=%u", keyPath, name, type, dataSize);
        else
            RtlStringCbPrintfA(detail, sizeof(detail),
                "KeyHandle=0x%llX Value=\"%s\" Type=%u Size=%u",
                reinterpret_cast<ULONGLONG>(key), name, type, dataSize);
        LogImportant(gIdxSetValueKey, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetSetValueKey)>(gOriginalFunctions[gIdxSetValueKey]);
    NTSTATUS status = original ? original(key, valueName, titleIndex, type, data, dataSize)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenFile(PHANDLE file, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    PIO_STATUS_BLOCK io, ULONG shareAccess, ULONG options) {
    InterlockedIncrement(&gHooksActive);
    char path[104] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Path=\"%s\" Access=0x%X Share=0x%X Options=0x%X", path, access, shareAccess, options);
        LogImportant(gIdxOpenFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenFile)>(gOriginalFunctions[gIdxOpenFile]);
    NTSTATUS status = original ? original(file, access, attributes, io, shareAccess, options)
                               : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(file, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetQueryAttributesFile(POBJECT_ATTRIBUTES attributes, PVOID information) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char path[136], detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Path=\"%s\"", path);
        LogImportant(gIdxQueryAttributesFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueryAttributesFile)>(
        gOriginalFunctions[gIdxQueryAttributesFile]);
    NTSTATUS status = original ? original(attributes, information) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetQueryFullAttributesFile(POBJECT_ATTRIBUTES attributes, PVOID information) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char path[136], detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Path=\"%s\"", path);
        LogImportant(gIdxQueryFullAttributesFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueryFullAttributesFile)>(
        gOriginalFunctions[gIdxQueryFullAttributesFile]);
    NTSTATUS status = original ? original(attributes, information) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetQueryDirectoryFile(HANDLE file, HANDLE event, PVOID apc, PVOID apcContext,
    PIO_STATUS_BLOCK io, PVOID information, ULONG length, ULONG informationClass,
    BOOLEAN singleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char pattern[64], filePath[64], detail[160];
        ReadUnicode(fileName, pattern, sizeof(pattern));
        if (FindHandleName(file, filePath, sizeof(filePath)))
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Directory=\"%s\" Pattern=\"%s\" Class=%u Size=%u", filePath, pattern,
                informationClass, length);
        else
            RtlStringCbPrintfA(detail, sizeof(detail),
                "FileHandle=0x%llX Pattern=\"%s\" Class=%u Size=%u",
                reinterpret_cast<ULONGLONG>(file), pattern, informationClass, length);
        LogImportant(gIdxQueryDirectoryFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueryDirectoryFile)>(
        gOriginalFunctions[gIdxQueryDirectoryFile]);
    NTSTATUS status = original ? original(file, event, apc, apcContext, io, information, length,
        informationClass, singleEntry, fileName, restartScan) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetQueryDirectoryFileEx(HANDLE file, HANDLE event, PVOID apc, PVOID apcContext,
    PIO_STATUS_BLOCK io, PVOID information, ULONG length, ULONG informationClass,
    ULONG flags, PUNICODE_STRING fileName) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char pattern[64], filePath[64], detail[160];
        ReadUnicode(fileName, pattern, sizeof(pattern));
        if (FindHandleName(file, filePath, sizeof(filePath)))
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Directory=\"%s\" Pattern=\"%s\" Class=%u Flags=0x%X", filePath, pattern,
                informationClass, flags);
        else
            RtlStringCbPrintfA(detail, sizeof(detail),
                "FileHandle=0x%llX Pattern=\"%s\" Class=%u Flags=0x%X",
                reinterpret_cast<ULONGLONG>(file), pattern, informationClass, flags);
        LogImportant(gIdxQueryDirectoryFileEx, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueryDirectoryFileEx)>(
        gOriginalFunctions[gIdxQueryDirectoryFileEx]);
    NTSTATUS status = original ? original(file, event, apc, apcContext, io, information, length,
        informationClass, flags, fileName) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetDeviceIoControlFile(HANDLE file, HANDLE event, PVOID apc, PVOID apcContext,
    PIO_STATUS_BLOCK io, ULONG controlCode, PVOID input, ULONG inputLength, PVOID output,
    ULONG outputLength) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char filePath[80], detail[160];
        if (FindHandleName(file, filePath, sizeof(filePath)))
            RtlStringCbPrintfA(detail, sizeof(detail),
                "File=\"%s\" IOCTL=0x%08X InputSize=%u OutputSize=%u",
                filePath, controlCode, inputLength, outputLength);
        else
            RtlStringCbPrintfA(detail, sizeof(detail),
                "FileHandle=0x%llX IOCTL=0x%08X InputSize=%u OutputSize=%u",
                reinterpret_cast<ULONGLONG>(file), controlCode, inputLength, outputLength);
        LogImportant(gIdxDeviceIoControlFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetDeviceIoControlFile)>(
        gOriginalFunctions[gIdxDeviceIoControlFile]);
    NTSTATUS status = original ? original(file, event, apc, apcContext, io, controlCode, input,
        inputLength, output, outputLength) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenKeyEx(PHANDLE key, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    ULONG options) {
    InterlockedIncrement(&gHooksActive);
    char path[104] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Key=\"%s\" Access=0x%X Options=0x%X",
            path, access, options);
        LogImportant(gIdxOpenKeyEx, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenKeyEx)>(gOriginalFunctions[gIdxOpenKeyEx]);
    NTSTATUS status = original ? original(key, access, attributes, options) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(key, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetCreateKey(PHANDLE key, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    ULONG titleIndex, PUNICODE_STRING keyClass, ULONG options, PULONG disposition) {
    InterlockedIncrement(&gHooksActive);
    char path[88] = {};
    __try {
        char className[40], detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        ReadUnicode(keyClass, className, sizeof(className));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Key=\"%s\" Class=\"%s\" Access=0x%X Options=0x%X", path, className, access, options);
        LogImportant(gIdxCreateKey, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetCreateKey)>(gOriginalFunctions[gIdxCreateKey]);
    NTSTATUS status = original ? original(key, access, attributes, titleIndex, keyClass, options,
        disposition) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(key, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetQueryValueKey(HANDLE key, PUNICODE_STRING valueName, ULONG informationClass,
    PVOID information, ULONG length, PULONG resultLength) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[72], keyPath[64], detail[160];
        ReadUnicode(valueName, name, sizeof(name));
        if (FindHandleName(key, keyPath, sizeof(keyPath)))
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Key=\"%s\" Value=\"%s\" Class=%u BufferSize=%u",
                keyPath, name, informationClass, length);
        else
            RtlStringCbPrintfA(detail, sizeof(detail),
                "KeyHandle=0x%llX Value=\"%s\" Class=%u BufferSize=%u",
                reinterpret_cast<ULONGLONG>(key), name, informationClass, length);
        LogImportant(gIdxQueryValueKey, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueryValueKey)>(
        gOriginalFunctions[gIdxQueryValueKey]);
    NTSTATUS status = original ? original(key, valueName, informationClass, information, length,
        resultLength) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetDeleteValueKey(HANDLE key, PUNICODE_STRING valueName) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[72], keyPath[64], detail[160];
        ReadUnicode(valueName, name, sizeof(name));
        if (FindHandleName(key, keyPath, sizeof(keyPath)))
            RtlStringCbPrintfA(detail, sizeof(detail), "Key=\"%s\" Value=\"%s\"", keyPath, name);
        else
            RtlStringCbPrintfA(detail, sizeof(detail), "KeyHandle=0x%llX Value=\"%s\"",
                reinterpret_cast<ULONGLONG>(key), name);
        LogImportant(gIdxDeleteValueKey, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetDeleteValueKey)>(
        gOriginalFunctions[gIdxDeleteValueKey]);
    NTSTATUS status = original ? original(key, valueName) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetRenameKey(HANDLE key, PUNICODE_STRING newName) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[72], keyPath[64], detail[160];
        ReadUnicode(newName, name, sizeof(name));
        if (FindHandleName(key, keyPath, sizeof(keyPath)))
            RtlStringCbPrintfA(detail, sizeof(detail), "Key=\"%s\" NewName=\"%s\"", keyPath, name);
        else
            RtlStringCbPrintfA(detail, sizeof(detail), "KeyHandle=0x%llX NewName=\"%s\"",
                reinterpret_cast<ULONGLONG>(key), name);
        LogImportant(gIdxRenameKey, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetRenameKey)>(gOriginalFunctions[gIdxRenameKey]);
    NTSTATUS status = original ? original(key, newName) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenSection(PHANDLE section, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes) {
    InterlockedIncrement(&gHooksActive);
    char path[112] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Section=\"%s\" Access=0x%X", path, access);
        LogImportant(gIdxOpenSection, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenSection)>(gOriginalFunctions[gIdxOpenSection]);
    NTSTATUS status = original ? original(section, access, attributes) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(section, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetCreateEvent(PHANDLE event, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    EVENT_TYPE type, BOOLEAN initialState) {
    InterlockedIncrement(&gHooksActive);
    char path[96] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Event=\"%s\" Access=0x%X Type=%u InitialState=%u", path, access,
            static_cast<ULONG>(type), static_cast<ULONG>(initialState));
        LogImportant(gIdxCreateEvent, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetCreateEvent)>(gOriginalFunctions[gIdxCreateEvent]);
    NTSTATUS status = original ? original(event, access, attributes, type, initialState)
                               : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(event, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenEvent(PHANDLE event, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes) {
    InterlockedIncrement(&gHooksActive);
    char path[112] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Event=\"%s\" Access=0x%X", path, access);
        LogImportant(gIdxOpenEvent, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenEvent)>(gOriginalFunctions[gIdxOpenEvent]);
    NTSTATUS status = original ? original(event, access, attributes) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(event, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetCreateMutant(PHANDLE mutant, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes, BOOLEAN initialOwner) {
    InterlockedIncrement(&gHooksActive);
    char path[96] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Mutant=\"%s\" Access=0x%X InitialOwner=%u", path, access,
            static_cast<ULONG>(initialOwner));
        LogImportant(gIdxCreateMutant, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetCreateMutant)>(
        gOriginalFunctions[gIdxCreateMutant]);
    NTSTATUS status = original ? original(mutant, access, attributes, initialOwner)
                               : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(mutant, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenMutant(PHANDLE mutant, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes) {
    InterlockedIncrement(&gHooksActive);
    char path[112] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Mutant=\"%s\" Access=0x%X", path, access);
        LogImportant(gIdxOpenMutant, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenMutant)>(gOriginalFunctions[gIdxOpenMutant]);
    NTSTATUS status = original ? original(mutant, access, attributes) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(mutant, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetCreateSemaphore(PHANDLE semaphore, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes, LONG initialCount, LONG maximumCount) {
    InterlockedIncrement(&gHooksActive);
    char path[88] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Semaphore=\"%s\" Access=0x%X Initial=%ld Maximum=%ld", path, access,
            initialCount, maximumCount);
        LogImportant(gIdxCreateSemaphore, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetCreateSemaphore)>(
        gOriginalFunctions[gIdxCreateSemaphore]);
    NTSTATUS status = original ? original(semaphore, access, attributes, initialCount, maximumCount)
                               : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(semaphore, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenSemaphore(PHANDLE semaphore, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes) {
    InterlockedIncrement(&gHooksActive);
    char path[104] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Semaphore=\"%s\" Access=0x%X", path, access);
        LogImportant(gIdxOpenSemaphore, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenSemaphore)>(
        gOriginalFunctions[gIdxOpenSemaphore]);
    NTSTATUS status = original ? original(semaphore, access, attributes) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(semaphore, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetCreateTimer(PHANDLE timer, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    TIMER_TYPE type) {
    InterlockedIncrement(&gHooksActive);
    char path[96] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Timer=\"%s\" Access=0x%X Type=%u", path,
            access, static_cast<ULONG>(type));
        LogImportant(gIdxCreateTimer, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetCreateTimer)>(gOriginalFunctions[gIdxCreateTimer]);
    NTSTATUS status = original ? original(timer, access, attributes, type) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(timer, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenDirectoryObject(PHANDLE directory, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes) {
    InterlockedIncrement(&gHooksActive);
    char path[104] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Directory=\"%s\" Access=0x%X", path, access);
        LogImportant(gIdxOpenDirectoryObject, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenDirectoryObject)>(
        gOriginalFunctions[gIdxOpenDirectoryObject]);
    NTSTATUS status = original ? original(directory, access, attributes) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(directory, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenSymbolicLinkObject(PHANDLE link, ACCESS_MASK access,
    POBJECT_ATTRIBUTES attributes) {
    InterlockedIncrement(&gHooksActive);
    char path[104] = {};
    __try {
        char detail[160];
        ReadObjectPath(attributes, path, sizeof(path));
        RtlStringCbPrintfA(detail, sizeof(detail), "Link=\"%s\" Access=0x%X", path, access);
        LogImportant(gIdxOpenSymbolicLinkObject, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenSymbolicLinkObject)>(
        gOriginalFunctions[gIdxOpenSymbolicLinkObject]);
    NTSTATUS status = original ? original(link, access, attributes) : STATUS_NOT_IMPLEMENTED;
    RememberReturnedHandle(link, path, status);
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetConnectPort(PHANDLE port, PUNICODE_STRING portName, PVOID securityQos,
    PVOID clientView, PVOID serverView, PULONG maximumMessageLength, PVOID connectionInfo,
    PULONG connectionInfoLength) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[112], detail[160];
        ReadUnicode(portName, name, sizeof(name));
        ULONG bytes = connectionInfoLength ? *connectionInfoLength : 0;
        RtlStringCbPrintfA(detail, sizeof(detail), "Port=\"%s\" ConnectionInfoSize=%u", name, bytes);
        LogImportant(gIdxConnectPort, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetConnectPort)>(gOriginalFunctions[gIdxConnectPort]);
    NTSTATUS status = original ? original(port, portName, securityQos, clientView, serverView,
        maximumMessageLength, connectionInfo, connectionInfoLength) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetSecureConnectPort(PHANDLE port, PUNICODE_STRING portName, PVOID securityQos,
    PVOID clientView, PVOID requiredServerSid, PVOID serverView, PULONG maximumMessageLength,
    PVOID connectionInfo, PULONG connectionInfoLength) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[112], detail[160];
        ReadUnicode(portName, name, sizeof(name));
        ULONG bytes = connectionInfoLength ? *connectionInfoLength : 0;
        RtlStringCbPrintfA(detail, sizeof(detail), "Port=\"%s\" ConnectionInfoSize=%u", name, bytes);
        LogImportant(gIdxSecureConnectPort, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetSecureConnectPort)>(
        gOriginalFunctions[gIdxSecureConnectPort]);
    NTSTATUS status = original ? original(port, portName, securityQos, clientView,
        requiredServerSid, serverView, maximumMessageLength, connectionInfo, connectionInfoLength)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetAlpcConnectPort(PHANDLE port, PUNICODE_STRING portName,
    POBJECT_ATTRIBUTES attributes, PVOID portAttributes, ULONG flags, PVOID requiredServerSid,
    PVOID connectionMessage, PSIZE_T bufferLength, PVOID outputMessageAttributes,
    PVOID inputMessageAttributes, PVOID timeout) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[104], detail[160];
        ReadUnicode(portName, name, sizeof(name));
        SIZE_T bytes = bufferLength ? *bufferLength : 0;
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Port=\"%s\" Flags=0x%X MessageSize=%llu", name, flags,
            static_cast<ULONGLONG>(bytes));
        LogImportant(gIdxAlpcConnectPort, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetAlpcConnectPort)>(
        gOriginalFunctions[gIdxAlpcConnectPort]);
    NTSTATUS status = original ? original(port, portName, attributes, portAttributes, flags,
        requiredServerSid, connectionMessage, bufferLength, outputMessageAttributes,
        inputMessageAttributes, timeout) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetAlpcConnectPortEx(PHANDLE port, POBJECT_ATTRIBUTES connectionAttributes,
    POBJECT_ATTRIBUTES serverAttributes, PVOID portAttributes, ULONG flags,
    PVOID serverSecurityRequirements, PVOID connectionMessage, PSIZE_T bufferLength,
    PVOID outputMessageAttributes, PVOID inputMessageAttributes, PVOID timeout) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char connection[72], server[48], detail[160];
        ReadObjectPath(connectionAttributes, connection, sizeof(connection));
        ReadObjectPath(serverAttributes, server, sizeof(server));
        SIZE_T bytes = bufferLength ? *bufferLength : 0;
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Connection=\"%s\" Server=\"%s\" Flags=0x%X MessageSize=%llu", connection,
            server, flags, static_cast<ULONGLONG>(bytes));
        LogImportant(gIdxAlpcConnectPortEx, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetAlpcConnectPortEx)>(
        gOriginalFunctions[gIdxAlpcConnectPortEx]);
    NTSTATUS status = original ? original(port, connectionAttributes, serverAttributes,
        portAttributes, flags, serverSecurityRequirements, connectionMessage, bufferLength,
        outputMessageAttributes, inputMessageAttributes, timeout) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetLoadDriver(PUNICODE_STRING serviceName) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[136], detail[160];
        ReadUnicode(serviceName, name, sizeof(name));
        RtlStringCbPrintfA(detail, sizeof(detail), "Service=\"%s\"", name);
        LogImportant(gIdxLoadDriver, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetLoadDriver)>(gOriginalFunctions[gIdxLoadDriver]);
    NTSTATUS status = original ? original(serviceName) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetReadFile(HANDLE file, HANDLE event, PVOID apc, PVOID apcContext,
    PIO_STATUS_BLOCK io, PVOID buffer, ULONG length, PVOID offset, PVOID key) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char path[96], detail[160];
        if (FindHandleName(file, path, sizeof(path)))
            RtlStringCbPrintfA(detail, sizeof(detail), "File=\"%s\" Size=%u", path, length);
        else
            RtlStringCbPrintfA(detail, sizeof(detail), "FileHandle=0x%llX Size=%u",
                reinterpret_cast<ULONGLONG>(file), length);
        LogImportant(gIdxReadFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetReadFile)>(gOriginalFunctions[gIdxReadFile]);
    NTSTATUS status = original ? original(file, event, apc, apcContext, io, buffer, length, offset, key)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetWriteFile(HANDLE file, HANDLE event, PVOID apc, PVOID apcContext,
    PIO_STATUS_BLOCK io, PVOID buffer, ULONG length, PVOID offset, PVOID key) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char path[96], detail[160];
        if (FindHandleName(file, path, sizeof(path)))
            RtlStringCbPrintfA(detail, sizeof(detail), "File=\"%s\" Size=%u", path, length);
        else
            RtlStringCbPrintfA(detail, sizeof(detail), "FileHandle=0x%llX Size=%u",
                reinterpret_cast<ULONGLONG>(file), length);
        LogImportant(gIdxWriteFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetWriteFile)>(gOriginalFunctions[gIdxWriteFile]);
    NTSTATUS status = original ? original(file, event, apc, apcContext, io, buffer, length, offset, key)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static void LogFileInformation(ULONG syscallId, HANDLE file, ULONG informationClass, ULONG length) {
    char path[88], detail[160];
    if (FindHandleName(file, path, sizeof(path)))
        RtlStringCbPrintfA(detail, sizeof(detail), "File=\"%s\" Class=%u BufferSize=%u",
            path, informationClass, length);
    else
        RtlStringCbPrintfA(detail, sizeof(detail),
            "FileHandle=0x%llX Class=%u BufferSize=%u",
            reinterpret_cast<ULONGLONG>(file), informationClass, length);
    LogImportant(syscallId, detail);
}

static NTSTATUS DetQueryInformationFile(HANDLE file, PIO_STATUS_BLOCK io, PVOID information,
    ULONG length, ULONG informationClass) {
    InterlockedIncrement(&gHooksActive);
    __try { LogFileInformation(gIdxQueryInformationFile, file, informationClass, length); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueryInformationFile)>(
        gOriginalFunctions[gIdxQueryInformationFile]);
    NTSTATUS status = original ? original(file, io, information, length, informationClass)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetSetInformationFile(HANDLE file, PIO_STATUS_BLOCK io, PVOID information,
    ULONG length, ULONG informationClass) {
    InterlockedIncrement(&gHooksActive);
    __try { LogFileInformation(gIdxSetInformationFile, file, informationClass, length); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetSetInformationFile)>(
        gOriginalFunctions[gIdxSetInformationFile]);
    NTSTATUS status = original ? original(file, io, information, length, informationClass)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetFsControlFile(HANDLE file, HANDLE event, PVOID apc, PVOID apcContext,
    PIO_STATUS_BLOCK io, ULONG controlCode, PVOID input, ULONG inputLength, PVOID output,
    ULONG outputLength) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char path[72], detail[160];
        if (FindHandleName(file, path, sizeof(path)))
            RtlStringCbPrintfA(detail, sizeof(detail),
                "File=\"%s\" FSCTL=0x%08X InputSize=%u OutputSize=%u",
                path, controlCode, inputLength, outputLength);
        else
            RtlStringCbPrintfA(detail, sizeof(detail),
                "FileHandle=0x%llX FSCTL=0x%08X InputSize=%u OutputSize=%u",
                reinterpret_cast<ULONGLONG>(file), controlCode, inputLength, outputLength);
        LogImportant(gIdxFsControlFile, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetFsControlFile)>(
        gOriginalFunctions[gIdxFsControlFile]);
    NTSTATUS status = original ? original(file, event, apc, apcContext, io, controlCode, input,
        inputLength, output, outputLength) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static void LogKeyInformation(ULONG syscallId, HANDLE key, const char* operation,
    ULONG index, ULONG informationClass, ULONG length) {
    char path[72], detail[160];
    if (FindHandleName(key, path, sizeof(path)))
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Key=\"%s\" %s Index=%u Class=%u BufferSize=%u",
            path, operation, index, informationClass, length);
    else
        RtlStringCbPrintfA(detail, sizeof(detail),
            "KeyHandle=0x%llX %s Index=%u Class=%u BufferSize=%u",
            reinterpret_cast<ULONGLONG>(key), operation, index, informationClass, length);
    LogImportant(syscallId, detail);
}

static NTSTATUS DetQueryKey(HANDLE key, ULONG informationClass, PVOID information,
    ULONG length, PULONG resultLength) {
    InterlockedIncrement(&gHooksActive);
    __try { LogKeyInformation(gIdxQueryKey, key, "Query", 0, informationClass, length); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueryKey)>(gOriginalFunctions[gIdxQueryKey]);
    NTSTATUS status = original ? original(key, informationClass, information, length, resultLength)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetDeleteKey(HANDLE key) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char path[112], detail[160];
        if (FindHandleName(key, path, sizeof(path)))
            RtlStringCbPrintfA(detail, sizeof(detail), "Key=\"%s\"", path);
        else
            RtlStringCbPrintfA(detail, sizeof(detail), "KeyHandle=0x%llX",
                reinterpret_cast<ULONGLONG>(key));
        LogImportant(gIdxDeleteKey, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetDeleteKey)>(gOriginalFunctions[gIdxDeleteKey]);
    NTSTATUS status = original ? original(key) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetEnumerateKey(HANDLE key, ULONG index, ULONG informationClass,
    PVOID information, ULONG length, PULONG resultLength) {
    InterlockedIncrement(&gHooksActive);
    __try { LogKeyInformation(gIdxEnumerateKey, key, "Enumerate", index, informationClass, length); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetEnumerateKey)>(gOriginalFunctions[gIdxEnumerateKey]);
    NTSTATUS status = original ? original(key, index, informationClass, information, length, resultLength)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetEnumerateValueKey(HANDLE key, ULONG index, ULONG informationClass,
    PVOID information, ULONG length, PULONG resultLength) {
    InterlockedIncrement(&gHooksActive);
    __try { LogKeyInformation(gIdxEnumerateValueKey, key, "EnumerateValue", index, informationClass, length); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetEnumerateValueKey)>(
        gOriginalFunctions[gIdxEnumerateValueKey]);
    NTSTATUS status = original ? original(key, index, informationClass, information, length, resultLength)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetFreeVirtualMemory(HANDLE process, PVOID* base, PSIZE_T size, ULONG freeType) {
    InterlockedIncrement(&gHooksActive);
    __try {
        PVOID address = base ? *base : nullptr;
        SIZE_T bytes = size ? *size : 0;
        char detail[160];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Process=0x%llX Base=0x%llX Size=0x%llX FreeType=0x%X",
            reinterpret_cast<ULONGLONG>(process), reinterpret_cast<ULONGLONG>(address),
            static_cast<ULONGLONG>(bytes), freeType);
        LogImportant(gIdxFreeVirtualMemory, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetFreeVirtualMemory)>(
        gOriginalFunctions[gIdxFreeVirtualMemory]);
    NTSTATUS status = original ? original(process, base, size, freeType) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetReadVirtualMemory(HANDLE process, PVOID address, PVOID buffer,
    SIZE_T size, PSIZE_T bytesRead) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[160];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Process=0x%llX Address=0x%llX Size=0x%llX",
            reinterpret_cast<ULONGLONG>(process), reinterpret_cast<ULONGLONG>(address),
            static_cast<ULONGLONG>(size));
        LogImportant(gIdxReadVirtualMemory, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetReadVirtualMemory)>(
        gOriginalFunctions[gIdxReadVirtualMemory]);
    NTSTATUS status = original ? original(process, address, buffer, size, bytesRead)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetMapViewOfSection(HANDLE section, HANDLE process, PVOID* base,
    ULONG_PTR zeroBits, SIZE_T commitSize, PVOID offset, PSIZE_T viewSize, ULONG inherit,
    ULONG allocationType, ULONG protection) {
    InterlockedIncrement(&gHooksActive);
    __try {
        PVOID address = base ? *base : nullptr;
        SIZE_T bytes = viewSize ? *viewSize : 0;
        char sectionName[56], detail[160];
        if (FindHandleName(section, sectionName, sizeof(sectionName)))
            RtlStringCbPrintfA(detail, sizeof(detail),
                "Section=\"%s\" Process=0x%llX Base=0x%llX Size=0x%llX Protect=0x%X",
                sectionName, reinterpret_cast<ULONGLONG>(process),
                reinterpret_cast<ULONGLONG>(address), static_cast<ULONGLONG>(bytes), protection);
        else
            RtlStringCbPrintfA(detail, sizeof(detail),
                "SectionHandle=0x%llX Process=0x%llX Base=0x%llX Size=0x%llX Protect=0x%X",
                reinterpret_cast<ULONGLONG>(section), reinterpret_cast<ULONGLONG>(process),
                reinterpret_cast<ULONGLONG>(address), static_cast<ULONGLONG>(bytes), protection);
        LogImportant(gIdxMapViewOfSection, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetMapViewOfSection)>(
        gOriginalFunctions[gIdxMapViewOfSection]);
    NTSTATUS status = original ? original(section, process, base, zeroBits, commitSize, offset,
        viewSize, inherit, allocationType, protection) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetUnmapViewOfSection(HANDLE process, PVOID base) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[128];
        RtlStringCbPrintfA(detail, sizeof(detail), "Process=0x%llX Base=0x%llX",
            reinterpret_cast<ULONGLONG>(process), reinterpret_cast<ULONGLONG>(base));
        LogImportant(gIdxUnmapViewOfSection, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetUnmapViewOfSection)>(
        gOriginalFunctions[gIdxUnmapViewOfSection]);
    NTSTATUS status = original ? original(process, base) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetTerminateProcess(HANDLE process, NTSTATUS exitStatus) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[128];
        RtlStringCbPrintfA(detail, sizeof(detail), "Process=0x%llX ExitStatus=0x%08X",
            reinterpret_cast<ULONGLONG>(process), static_cast<ULONG>(exitStatus));
        LogImportant(gIdxTerminateProcess, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetTerminateProcess)>(
        gOriginalFunctions[gIdxTerminateProcess]);
    NTSTATUS status = original ? original(process, exitStatus) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetQueryInformationProcess(HANDLE process, ULONG informationClass,
    PVOID information, ULONG length, PULONG resultLength) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[144];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Process=0x%llX Class=%u BufferSize=%u",
            reinterpret_cast<ULONGLONG>(process), informationClass, length);
        LogImportant(gIdxQueryInformationProcess, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueryInformationProcess)>(
        gOriginalFunctions[gIdxQueryInformationProcess]);
    NTSTATUS status = original ? original(process, informationClass, information, length, resultLength)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetSetInformationProcess(HANDLE process, ULONG informationClass,
    PVOID information, ULONG length) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[144];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Process=0x%llX Class=%u BufferSize=%u",
            reinterpret_cast<ULONGLONG>(process), informationClass, length);
        LogImportant(gIdxSetInformationProcess, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetSetInformationProcess)>(
        gOriginalFunctions[gIdxSetInformationProcess]);
    NTSTATUS status = original ? original(process, informationClass, information, length)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenThread(PHANDLE thread, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    PCLIENT_ID clientId) {
    InterlockedIncrement(&gHooksActive);
    __try {
        ULONG_PTR pid = clientId ? reinterpret_cast<ULONG_PTR>(clientId->UniqueProcess) : 0;
        ULONG_PTR tid = clientId ? reinterpret_cast<ULONG_PTR>(clientId->UniqueThread) : 0;
        char detail[144];
        RtlStringCbPrintfA(detail, sizeof(detail), "TargetPID=%llu TargetTID=%llu Access=0x%X",
            static_cast<ULONGLONG>(pid), static_cast<ULONGLONG>(tid), access);
        LogImportant(gIdxOpenThread, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenThread)>(gOriginalFunctions[gIdxOpenThread]);
    NTSTATUS status = original ? original(thread, access, attributes, clientId)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetSuspendThread(HANDLE thread, PULONG previousCount) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[96];
        RtlStringCbPrintfA(detail, sizeof(detail), "Thread=0x%llX",
            reinterpret_cast<ULONGLONG>(thread));
        LogImportant(gIdxSuspendThread, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetSuspendThread)>(gOriginalFunctions[gIdxSuspendThread]);
    NTSTATUS status = original ? original(thread, previousCount) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetResumeThread(HANDLE thread, PULONG previousCount) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[96];
        RtlStringCbPrintfA(detail, sizeof(detail), "Thread=0x%llX",
            reinterpret_cast<ULONGLONG>(thread));
        LogImportant(gIdxResumeThread, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetResumeThread)>(gOriginalFunctions[gIdxResumeThread]);
    NTSTATUS status = original ? original(thread, previousCount) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetQueueApcThread(HANDLE thread, PVOID routine, PVOID argument1,
    PVOID argument2, PVOID argument3) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[160];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Thread=0x%llX Routine=0x%llX Arg1=0x%llX Arg2=0x%llX Arg3=0x%llX",
            reinterpret_cast<ULONGLONG>(thread), reinterpret_cast<ULONGLONG>(routine),
            reinterpret_cast<ULONGLONG>(argument1), reinterpret_cast<ULONGLONG>(argument2),
            reinterpret_cast<ULONGLONG>(argument3));
        LogImportant(gIdxQueueApcThread, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQueueApcThread)>(
        gOriginalFunctions[gIdxQueueApcThread]);
    NTSTATUS status = original ? original(thread, routine, argument1, argument2, argument3)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenProcessToken(HANDLE process, ACCESS_MASK access, PHANDLE token) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[112];
        RtlStringCbPrintfA(detail, sizeof(detail), "Process=0x%llX Access=0x%X",
            reinterpret_cast<ULONGLONG>(process), access);
        LogImportant(gIdxOpenProcessToken, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenProcessToken)>(
        gOriginalFunctions[gIdxOpenProcessToken]);
    NTSTATUS status = original ? original(process, access, token) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetOpenThreadTokenEx(HANDLE thread, ACCESS_MASK access, BOOLEAN openAsSelf,
    ULONG handleAttributes, PHANDLE token) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[144];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Thread=0x%llX Access=0x%X OpenAsSelf=%u Attributes=0x%X",
            reinterpret_cast<ULONGLONG>(thread), access, static_cast<ULONG>(openAsSelf),
            handleAttributes);
        LogImportant(gIdxOpenThreadTokenEx, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetOpenThreadTokenEx)>(
        gOriginalFunctions[gIdxOpenThreadTokenEx]);
    NTSTATUS status = original ? original(thread, access, openAsSelf, handleAttributes, token)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetAdjustPrivilegesToken(HANDLE token, BOOLEAN disableAll, PVOID newState,
    ULONG bufferLength, PVOID previousState, PULONG resultLength) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[144];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Token=0x%llX DisableAll=%u StateSize=%u",
            reinterpret_cast<ULONGLONG>(token), static_cast<ULONG>(disableAll), bufferLength);
        LogImportant(gIdxAdjustPrivilegesToken, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetAdjustPrivilegesToken)>(
        gOriginalFunctions[gIdxAdjustPrivilegesToken]);
    NTSTATUS status = original ? original(token, disableAll, newState, bufferLength,
        previousState, resultLength) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetReleaseMutant(HANDLE mutant, PULONG previousCount) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char name[112], detail[160];
        if (FindHandleName(mutant, name, sizeof(name)))
            RtlStringCbPrintfA(detail, sizeof(detail), "Mutant=\"%s\"", name);
        else
            RtlStringCbPrintfA(detail, sizeof(detail), "MutantHandle=0x%llX",
                reinterpret_cast<ULONGLONG>(mutant));
        LogImportant(gIdxReleaseMutant, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetReleaseMutant)>(
        gOriginalFunctions[gIdxReleaseMutant]);
    NTSTATUS status = original ? original(mutant, previousCount) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetAlpcSendWaitReceivePort(HANDLE port, ULONG flags, PVOID sendMessage,
    PVOID sendAttributes, PVOID receiveMessage, PSIZE_T receiveLength,
    PVOID receiveAttributes, PVOID timeout) {
    InterlockedIncrement(&gHooksActive);
    __try {
        SIZE_T bytes = receiveLength ? *receiveLength : 0;
        char detail[144];
        RtlStringCbPrintfA(detail, sizeof(detail),
            "Port=0x%llX Flags=0x%X ReceiveBufferSize=%llu Send=%u Receive=%u",
            reinterpret_cast<ULONGLONG>(port), flags, static_cast<ULONGLONG>(bytes),
            sendMessage ? 1u : 0u, receiveMessage ? 1u : 0u);
        LogImportant(gIdxAlpcSendWaitReceivePort, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetAlpcSendWaitReceivePort)>(
        gOriginalFunctions[gIdxAlpcSendWaitReceivePort]);
    NTSTATUS status = original ? original(port, flags, sendMessage, sendAttributes,
        receiveMessage, receiveLength, receiveAttributes, timeout) : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
}

static NTSTATUS DetQuerySystemInformation(ULONG informationClass, PVOID information,
    ULONG length, PULONG resultLength) {
    InterlockedIncrement(&gHooksActive);
    __try {
        char detail[112];
        RtlStringCbPrintfA(detail, sizeof(detail), "Class=%u BufferSize=%u",
            informationClass, length);
        LogImportant(gIdxQuerySystemInformation, detail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    auto original = reinterpret_cast<decltype(&DetQuerySystemInformation)>(
        gOriginalFunctions[gIdxQuerySystemInformation]);
    NTSTATUS status = original ? original(informationClass, information, length, resultLength)
                               : STATUS_NOT_IMPLEMENTED;
    LogCurrentResult(status);
    InterlockedDecrement(&gHooksActive);
    return status;
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
    KeInitializeSpinLock(&gHandleNameLock);
    KeInitializeSpinLock(&gResultLock);
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
