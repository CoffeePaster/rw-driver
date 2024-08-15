#include "ntos.h"
#include "pe.h"

#ifdef _DEBUG
#define dbg_print(fmt, ...) dbg_print(fmt, ##__VA_ARGS__)
#else
#define dbg_print(fmt, ...)
#endif

#define REQ_MAGIC (*(uint64_t*)"lhLWcTzkMRX06qbu")

enum drv_request_type {
	REQ_READ    = 0,
	REQ_WRITE   = 1,
	REQ_GET_PEB = 2,
};

struct drv_request {
	uint64_t magic;
	int      mode;
	HANDLE   pid;
	PVOID    addr;
	PVOID    buf;
	SIZE_T   size;
};

typedef __int64(__fastcall* xKdEnumerateDebuggingDevicesFn)(__int64 a1, __int64* a2, __int64* a3);

struct drv_request request;
xKdEnumerateDebuggingDevicesFn xKdEnumerateDebuggingDevices_original;

PEPROCESS get_eprocess(HANDLE pid) {
	PEPROCESS proc;
	return NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc)) ? proc : 0;
}

ULONG copy_virtmem(PEPROCESS src_proc, PVOID src_addr, PEPROCESS dst_proc, PVOID dst_addr, SIZE_T size) {
	SIZE_T bytes;
	return NT_SUCCESS(MmCopyVirtualMemory(src_proc, src_addr, dst_proc, dst_addr, size, KernelMode, &bytes));
}

bool addr_in_usermode(PVOID addr, size_t size, size_t align) {
	return !((uintptr_t)addr & (align - 1)) && ((uintptr_t)addr + size <= MmUserProbeAddress);
}

bool copy_req_buffer(PVOID src) {
	PEPROCESS self = PsGetCurrentProcess();
	return copy_virtmem(self, src, self, &request, sizeof(request));
}

__int64 __fastcall xKdEnumerateDebuggingDevices_hook(__int64 a1, __int64* a2, __int64* a3) {
	if (ExGetPreviousMode() == UserMode
		&& a1
		&& addr_in_usermode((PVOID)a1, sizeof(request), sizeof(/* DWORD */ unsigned long))
		&& copy_req_buffer((PVOID)a1)
		&& request.magic == REQ_MAGIC) {

		PEPROCESS self   = PsGetCurrentProcess();
		PEPROCESS target = get_eprocess(request.pid);

		if (target) {
			//printDebug("xKdEnumerateDebuggingDevices_hook: mode => %d\n", req_buffer.mode);

			switch (request.mode) {
			case REQ_READ: {
				return copy_virtmem(target, request.addr, self, request.buf, request.size);
				break;
			}
			case REQ_WRITE: {
				return copy_virtmem(self, request.buf, target, request.addr, request.size);
				break;
			}
			case REQ_GET_PEB: {
				PVOID peb = PsGetProcessPeb(target);
				return copy_virtmem(self, &peb, self, request.buf, sizeof(peb));
				break;
			}
			default:
				break;
			}
			return 0;
		}
	}

	return xKdEnumerateDebuggingDevices_original(a1, a2, a3);
}

PVOID rva(PVOID base, uintptr_t offset) {
	if (!base) return 0;
	uintptr_t rel = (uintptr_t)base + offset;
	return (PVOID)(rel + *(int*)(rel - 4));
}

PVOID scan_code_section(PVOID base, char *pattern, char *mask) {
	struct DOSHeader   *dos = (struct DOSHeader*)base;
	struct NTHeaders64 *nt  = (struct NTHeaders64*)((char*)base + dos->e_lfanew);

	if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	struct SectionHeader *sections = (struct SectionHeader*)(nt + 1);
	ULONG mask_len = (ULONG)strlen(mask);

	for (ULONG i = 0; i < nt->NumberOfSections; i++) {
		struct SectionHeader *sect = &sections[i];

		if (sect->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			char *scan_base = (char*)base + sect->VirtualAddress;

			for (ULONG j = 0; j < sect->Misc.VirtualSize; j++) {
				char *current = &scan_base[j];
				bool found = true;

				for (ULONG k = 0; k < mask_len; k++) {
					if (mask[k] == 'x' && current[k] != pattern[k]) {
						found = false;
						break;
					}
				}

				if (found) {
					return current;
				}
			}
		}
	}

	return 0;
}

PVOID get_ntoskrnl_base() {
	PVOID ntos_base = 0;
	RtlPcToFileHeader((PVOID)RtlPcToFileHeader, &ntos_base);
	return ntos_base;
}

DriverEntry(PDRIVER_OBJECT drv_obj, PUNICODE_STRING reg_path) {
	UNREFERENCED_PARAMETER(drv_obj);
	UNREFERENCED_PARAMETER(reg_path);

	dbg_print("driver load\n");

	PVOID ntos_base = get_ntoskrnl_base();

	if (ntos_base) {
		PVOID xKdEnumerateDebuggingDevices = rva(scan_code_section(ntos_base, "\x48\x8B\x05\x00\x00\x00\x00\x75\x07\x48\x8B\x05\x00\x00\x00\x00\xE8", "xxx????xxxxx????x"), 7);

		if (xKdEnumerateDebuggingDevices)
			xKdEnumerateDebuggingDevices_original = (xKdEnumerateDebuggingDevicesFn)InterlockedExchangePointer(xKdEnumerateDebuggingDevices, (PVOID)xKdEnumerateDebuggingDevices_hook);
		else
			dbg_print("failed: hook\n");
	}
	else
		dbg_print("failed: ntoskrnl base\n");

	return STATUS_SUCCESS;
}
