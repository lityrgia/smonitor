#pragma warning(disable : 5040)

#include <etwhook_manager.hpp>
#include <kstl/ksystem_info.hpp>
#include <kstl/kpe_parse.hpp>
#include <etwhook_utils.hpp>
#include <intrin.h>

#define OFFSET_KPCR_CURRENT_THREAD  0x188
#define OFFSET_KPCR_RSP_BASE        0x1A8

#define OFFSET_KTHREAD_SYSTEM_CALL_NUMBER 0x80

EtwHookManager* EtwHookManager::_instance = 0;

EtwHookManager::HalCollectPmcCountersProc EtwHookManager::_originalHalCollectPmcCounters;

namespace {

	constexpr ULONG kSyscallEtwMagic1Values[] = { 0x501802ul, 0x601802ul };
	constexpr USHORT kSyscallEtwMagic2 = 0xf33u;

	bool IsSyscallEtwMagic1(ULONG value)
	{
		for (auto v : kSyscallEtwMagic1Values) {
			if (value == v) return true;
		}
		return false;
	}

}


EtwHookManager* EtwHookManager::GetInstance()
{
	if (!_instance)
		_instance = new EtwHookManager;

	return _instance;
}


NTSTATUS EtwHookManager::Initialize(HOOK_CALLBACK hookCallback)
{
	if (!_instance)
		return STATUS_MEMORY_NOT_ALLOCATED;

	if (_isInitialized)
		return STATUS_SUCCESS;

	auto status = STATUS_UNSUCCESSFUL;

	auto sysInfo = kstd::SysInfoManager::GetInstance();

	if (!sysInfo)
		return STATUS_INSUFFICIENT_RESOURCES;

	if (sysInfo->GetBuildNumber() <= 7601)
	{
		LOG_ERROR("current os version is not supported!");
		return STATUS_NOT_SUPPORTED;
	}

	do {
		status = _initializer.StartTrace();
		if (!NT_SUCCESS(status))
			break;

		status = _initializer.OpenPmcCounter();
		if (!NT_SUCCESS(status))
			break;


		UINT_PTR* halPrivateDispatchTable = _initializer.GetHalPrivateDispatchTable();
		if (!halPrivateDispatchTable)
		{
			status = STATUS_UNSUCCESSFUL;
			LOG_ERROR("failed to get HalPrivateDispatchTable address!");
			break;
		}

		_disable();

		_originalHalCollectPmcCounters = reinterpret_cast<HalCollectPmcCountersProc>(halPrivateDispatchTable[_halCollectPmcCountersIndex]);

		halPrivateDispatchTable[_halCollectPmcCountersIndex] = reinterpret_cast<ULONG_PTR>(HalCollectPmcCountersHook);

		_enable();

		_hookCallback = hookCallback;

		_isInitialized = true;

	} while (false);

	return status;
}


NTSTATUS EtwHookManager::Destroy()
{
	if (!_instance)
		return STATUS_MEMORY_NOT_ALLOCATED;

	delete _instance;
	_instance = 0;

	return STATUS_SUCCESS;
}


void EtwHookManager::HalCollectPmcCountersHook(void* context, ULONGLONG traceBufferEnd)
{
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
	{
		if (_instance)
			_instance->TraceStackToSyscall();
	}

	return _originalHalCollectPmcCounters(context, traceBufferEnd);
}


EtwHookManager::EtwHookManager()
	:
	_isInitialized(false),
	_hookCallback(nullptr)
{

	void* kernelImageBase = FindModuleBase(L"ntoskrnl.exe", 0);

	_kiSystemServiceRepeat = kstd::PatternFindSections(kernelImageBase,
		"\x4c\x8d\x15\x00\x00\x00\x00\x4c\x8d\x1d\x00\x00\x00\x00\xf7\x43",
		"xxx????xxx????xx", ".text");
}


EtwHookManager::~EtwHookManager()
{
	_initializer.EndTrace();

	if (_originalHalCollectPmcCounters)
	{
		_disable();
		_initializer.GetHalPrivateDispatchTable()[_halCollectPmcCountersIndex] = reinterpret_cast<ULONG_PTR>(_originalHalCollectPmcCounters);
		_enable();
	}
}


void EtwHookManager::TraceStackToSyscall()
{
	if (ExGetPreviousMode() == KernelMode)
	{
		return;
	}

	PVOID* stackLimit = reinterpret_cast<PVOID*>(__readgsqword(OFFSET_KPCR_RSP_BASE));
	PVOID* stackPos = reinterpret_cast<PVOID*>(_AddressOfReturnAddress());

	ULONG64 currentThread = __readgsqword(OFFSET_KPCR_CURRENT_THREAD);
	unsigned systemCallIndex = *reinterpret_cast<unsigned*>(currentThread + OFFSET_KTHREAD_SYSTEM_CALL_NUMBER);

	do
	{

		if (!_kiSystemServiceRepeat)
		{
			LOG_ERROR("failed to find KiSystemServiceRepeat");
			break;
		}

		for (; stackPos < stackLimit; ++stackPos)
		{
			PUSHORT stackAsUshort = reinterpret_cast<PUSHORT>(stackPos);

			if (*stackAsUshort != kSyscallEtwMagic2) continue;

			++stackPos;

			PULONG stackAsUlong = reinterpret_cast<PULONG>(stackPos);

			if (!IsSyscallEtwMagic1(*stackAsUlong)) continue;

			for (; stackPos < stackLimit; ++stackPos)
			{
				if ((ULONG_PTR)*stackPos >= (ULONG_PTR)PAGE_ALIGN(_kiSystemServiceRepeat) &&
					(ULONG_PTR)*stackPos <= (ULONG_PTR)PAGE_ALIGN(reinterpret_cast<const char*>(_kiSystemServiceRepeat) + PAGE_SIZE * 2))
				{
					if (stackLimit - stackPos > 9)
						ProcessSyscall(systemCallIndex, stackPos);

					break;
				}
			}

			break;
		}

	} while (false);

}


void EtwHookManager::ProcessSyscall(unsigned systemCallIndex, void** stackPos)
{
	if (_hookCallback)
	{
		_hookCallback(systemCallIndex, &stackPos[9], reinterpret_cast<ULONG_PTR*>(&stackPos[5]));
	}
}
