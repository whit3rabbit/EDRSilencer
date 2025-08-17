#pragma once
#include <windows.h>
#include "../beacon.h" // For BEACON_INFO

// These are plausible definitions for types used by sleep mask BOFs,
// which seem to be missing from the provided project files.
// These definitions are based on common sleep mask kit structures.

typedef enum {
    DEFAULT_SLEEP,
    BEACON_GATE
} SLEEP_REASON;

typedef struct _SLEEPMASK_INFO {
    DWORD version;
    SLEEP_REASON reason;
    DWORD sleep_time;
    BEACON_INFO beacon_info;
} SLEEPMASK_INFO, *PSLEEPMASK_INFO;

// Placeholder enum for WinApi function names
typedef enum _WinApi {
    CreateFileA_Enum,
    WriteFile_Enum,
    CloseHandle_Enum,
    // Add other APIs as needed for the mock framework
} WinApi;

typedef struct _FUNCTION_CALL {
    PVOID functionPtr;
    WinApi function;
    BOOL bMask;
    int numOfArgs;
    ULONG_PTR args[16]; // Assuming a max of 16 args
} FUNCTION_CALL, *PFUNCTION_CALL;

typedef void (*SLEEPMASK_FUNC)(PSLEEPMASK_INFO sleepMaskInfo, PFUNCTION_CALL functionCall);
