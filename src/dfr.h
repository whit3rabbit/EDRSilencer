// src/dfr.h
#ifndef DFR_H
#define DFR_H

#include <windows.h>
#include "base/helpers.h"

// KERNEL32
DFR(KERNEL32, CloseHandle);
DFR(KERNEL32, CreateToolhelp32Snapshot);
DFR(KERNEL32, GetCurrentProcess);
DFR(KERNEL32, GetCurrentThread);
DFR(KERNEL32, GetFileAttributesW);
DFR(KERNEL32, GetLastError);
DFR(KERNEL32, GetProcessHeap);
DFR(KERNEL32, HeapAlloc);
DFR(KERNEL32, HeapFree);
DFR(KERNEL32, lstrcmpiA);
DFR(KERNEL32, lstrlenA);
DFR(KERNEL32, lstrlenW);
DFR(KERNEL32, MultiByteToWideChar);
DFR(KERNEL32, OpenProcess);
DFR(KERNEL32, Process32First);
DFR(KERNEL32, Process32Next);
DFR(KERNEL32, QueryDosDeviceW);
DFR(KERNEL32, QueryFullProcessImageNameW);
DFR(KERNEL32, WideCharToMultiByte);
DFR(KERNEL32, CopyMemory);

// ADVAPI32
DFR(ADVAPI32, AdjustTokenPrivileges);
DFR(ADVAPI32, GetSidSubAuthority);
DFR(ADVAPI32, GetSidSubAuthorityCount);
DFR(ADVAPI32, GetTokenInformation);
DFR(ADVAPI32, LookupPrivilegeValueA);
DFR(ADVAPI32, OpenProcessToken);
DFR(ADVAPI32, OpenThreadToken);

// USER32
DFR(USER32, CharLowerW);

// OLE32
DFR(OLE32, CoCreateInstance);
DFR(OLE32, CoInitializeEx);
DFR(OLE32, CoUninitialize);

// OLEAUT32
DFR(OLEAUT32, SysAllocString);
DFR(OLEAUT32, SysAllocStringLen);
DFR(OLEAUT32, SysFreeString);
DFR(OLEAUT32, VariantClear);
DFR(OLEAUT32, VariantInit);

// FWPUCLNT
DFR(FWPUCLNT, FwpmEngineOpen0);
DFR(FWPUCLNT, FwpmEngineClose0);
DFR(FWPUCLNT, FwpmFilterCreateEnumHandle0);
DFR(FWPUCLNT, FwpmFilterDestroyEnumHandle0);
DFR(FWPUCLNT, FwpmFilterEnum0);
DFR(FWPUCLNT, FwpmFilterDeleteById0);
DFR(FWPUCLNT, FwpmSubLayerDeleteByKey0);
DFR(FWPUCLNT, FwpmProviderDeleteByKey0);
DFR(FWPUCLNT, FwpmTransactionBegin0);
DFR(FWPUCLNT, FwpmTransactionCommit0);
DFR(FWPUCLNT, FwpmTransactionAbort0);
DFR(FWPUCLNT, FwpmFilterAdd0);
DFR(FWPUCLNT, FwpmProviderAdd0);
DFR(FWPUCLNT, FwpmSubLayerAdd0);
DFR(FWPUCLNT, FwpmFreeMemory0);

// MSVCRT (for _wcsicmp, strrchr, etc. used in firewall.c)
DFR(MSVCRT, _wcsicmp);
const char* (*strrchr_ptr)(const char*, int) = strrchr;
#define strrchr strrchr_ptr
DFR(MSVCRT, wcscmp);

#endif // DFR_H