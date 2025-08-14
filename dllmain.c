// File: dllmain.c
#include "core.h"

HANDLE g_hHeap = NULL;
BOOL g_isQuiet = FALSE;
CRITICAL_SECTION g_critSec; // For thread safety

// Worker thread to apply filters
DWORD WINAPI BlockerThread(LPVOID lpParam) {
    (void)lpParam; // Unused
    g_isQuiet = TRUE; // Run quietly by default
    if (CheckProcessIntegrityLevel()) {
        configureNetworkFilters();
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            g_hHeap = HeapCreate(0, 0, 0);
            if (g_hHeap == NULL) return FALSE;
            InitializeCriticalSection(&g_critSec);
            break;

        case DLL_PROCESS_DETACH:
            DeleteCriticalSection(&g_critSec);
            if (g_hHeap) HeapDestroy(g_hHeap);
            break;
    }
    return TRUE;
}

// --- Exported Functions ---

__declspec(dllexport) void Initialize(void) {
    // Run the main logic in a separate thread to avoid blocking the caller
    HANDLE hThread = CreateThread(NULL, 0, BlockerThread, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread); // We don't need to wait for it, so close the handle immediately
    }
}

// --- Exported Functions ---
__declspec(dllexport) void BlockEDR(BOOL quiet) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (CheckProcessIntegrityLevel()) {
        configureNetworkFilters();
    }
    LeaveCriticalSection(&g_critSec);
}

__declspec(dllexport) void AddRuleByPath(BOOL quiet, const char* processPath) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (processPath && CheckProcessIntegrityLevel()) {
        addProcessRule(processPath);
    }
    LeaveCriticalSection(&g_critSec);
}

__declspec(dllexport) void RemoveAllRules(BOOL quiet) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (CheckProcessIntegrityLevel()) {
        removeAllRules();
    }
    LeaveCriticalSection(&g_critSec);
}

__declspec(dllexport) void RemoveRuleByID(BOOL quiet, const char* ruleIdStr) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (ruleIdStr && CheckProcessIntegrityLevel()) {
        char *endptr;
        UINT64 ruleId = CustomStrToULL(ruleIdStr, &endptr);
        if (endptr != ruleIdStr) {
            removeRuleById(ruleId);
        }
    }
    LeaveCriticalSection(&g_critSec);
}
