#pragma once

#include <fltKernel.h>
#include <ntimage.h>
#include <intrin.h>
#include <kstl/klog.hpp>

template<typename T>
static inline T* kalloc(POOL_FLAGS poolFlags, ULONG tag, SIZE_T size = 0)
{
	if (!size)
	{
		size = sizeof(T);
	}

	return reinterpret_cast<T*>(ExAllocatePool2(poolFlags, size, tag));
}

#define MAXIMUM_FILENAME_LENGTH 256

typedef struct _SYSTEM_MODULE_ENTRY
{
	ULONGLONG Unknown1;
	ULONGLONG Unknown2;
	PVOID BaseAddress;
	ULONG Size;
	ULONG Flags;
	ULONG EntryIndex;
	USHORT NameLength;
	USHORT PathLength;
	CHAR Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	ULONG Unknown1;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 0xb,
	SystemKernelDebuggerInformation = 0x23,
	SystemFirmwareTableInformation = 0x4c
} SYSTEM_INFORMATION_CLASS;

extern "C"
{
	NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

	NTKERNELAPI NTSTATUS NTAPI NtQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTKERNELAPI PVOID RtlPcToFileHeader(PVOID pc, PVOID* base);
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTKERNELAPI PVOID PsGetProcessPeb(PEPROCESS Process);
	NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);
};
