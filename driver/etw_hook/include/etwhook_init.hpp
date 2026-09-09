#pragma once

#include <etwhook_base.hpp>

class EtwInitializer : public EtwBase
{
public:
	EtwInitializer();
	~EtwInitializer();

	NTSTATUS StartTrace();
	NTSTATUS EndTrace();

	NTSTATUS OpenPmcCounter();

	UINT_PTR* GetHalPrivateDispatchTable() const
	{
		return _halPrivateDispatchTable;
	}

private:
	EtwInitializer(const EtwInitializer&) = delete;
	EtwInitializer& operator=(const EtwInitializer&) = delete;

	NTSTATUS StartStopTrace(bool start);

	bool      _isActive;
	UINT_PTR* _halPrivateDispatchTable;
};
