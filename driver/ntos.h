#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>

NTSYSAPI
PVOID RtlPcToFileHeader(
	IN  PVOID PcValue,
	OUT PVOID* BaseOfImage
);

NTKERNELAPI
NTSTATUS PsLookupProcessByProcessId(
	IN HANDLE ProcessId,
	OUT PEPROCESS* Process
);

NTKERNELAPI
PPEB PsGetProcessPeb(
	IN PEPROCESS Process
);

NTKERNELAPI
NTSTATUS MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);
