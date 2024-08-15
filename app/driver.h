#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <Windows.h>

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

typedef __int64(__fastcall* NtConvertBetweenAuxiliaryCounterAndPerformanceCounterFn)(char a1, __int64* a2, __int64* a3, __int64* a4);
typedef NtConvertBetweenAuxiliaryCounterAndPerformanceCounterFn UserFn;

typedef struct drv {
	UserFn fn;
} *drv_obj;

bool drv_init(drv_obj drv) {
	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	if (ntdll)
		drv->fn = (UserFn)GetProcAddress(ntdll, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	return drv->fn;
}

bool drv_call(drv_obj drv, PVOID req) {
	__int64 dum;
	return drv->fn(1, (__int64*)&req, &dum, &dum);
}

bool drv_read(drv_obj drv, HANDLE pid, uintptr_t addr, PVOID buf, SIZE_T size) {
	struct drv_request req = { REQ_MAGIC, REQ_READ, pid, (PVOID)addr, buf, size };
	return drv_call(drv, &req);
}

bool drv_write(drv_obj drv, HANDLE pid, uintptr_t addr, PVOID buf, SIZE_T size) {
	struct drv_request req = { REQ_MAGIC, REQ_WRITE, pid, (PVOID)addr, buf, size };
	return drv_call(drv, &req);
}

PVOID drv_get_peb(drv_obj drv, HANDLE pid) {
	PVOID peb = 0;
	struct drv_request req = { REQ_MAGIC, REQ_GET_PEB, pid, 0, &peb, 0 };

	drv_call(drv, &req);
	return peb;
}
