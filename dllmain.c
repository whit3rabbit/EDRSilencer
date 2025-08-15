#include "core.h"
#include "firewall.h"

HANDLE g_hHeap = NULL;
BOOL g_isQuiet = FALSE;
CRITICAL_SECTION g_critSec; // For thread safety
BOOL g_isFirewallMode = FALSE; // Default to WFP mode

// Worker thread to apply filters
DWORD WINAPI BlockerThread(LPVOID lpParam) {
    (void)lpParam; // Unused
    g_isQuiet = TRUE; // Run quietly by default
    if (CheckProcessIntegrityLevel()) {
        if (g_isFirewallMode) {
            FirewallConfigureBlockRules();
        } else {
            configureNetworkFilters();
        }
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

// --- New Exported Function to set mode ---
__declspec(dllexport) void SetMode(BOOL useFirewall) {
    EnterCriticalSection(&g_critSec);
    g_isFirewallMode = useFirewall;
    LeaveCriticalSection(&g_critSec);
}

// --- Exported Functions ---
__declspec(dllexport) void BlockEDR(BOOL quiet) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (CheckProcessIntegrityLevel()) {
        if (g_isFirewallMode) {
            FirewallConfigureBlockRules();
        } else {
            configureNetworkFilters();
        }
    }
    LeaveCriticalSection(&g_critSec);
}

__declspec(dllexport) void AddRuleByPath(BOOL quiet, const char* processPath) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (processPath && CheckProcessIntegrityLevel()) {
        if (g_isFirewallMode) {
            FirewallAddRuleByPath(processPath);
        } else {
            addProcessRule(processPath);
        }
    }
    LeaveCriticalSection(&g_critSec);
}

__declspec(dllexport) void RemoveAllRules(BOOL quiet) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (CheckProcessIntegrityLevel()) {
        if (g_isFirewallMode) {
            FirewallRemoveAllRules();
        } else {
            removeAllRules();
        }
    }
    LeaveCriticalSection(&g_critSec);
}

__declspec(dllexport) void RemoveRuleByID(BOOL quiet, const char* ruleIdOrNameStr) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (ruleIdOrNameStr && CheckProcessIntegrityLevel()) {
        if (g_isFirewallMode) {
            // In firewall mode, the string is treated as a rule name.
            // For simplicity, we use the function that derives the name from path.
            // A more direct approach would be removing by exact name if provided.
            FirewallRemoveRuleByName(ruleIdOrNameStr);
        } else {
            // In WFP mode, the string is treated as a numeric ID.
            char *endptr;
            UINT64 ruleId = CustomStrToULL(ruleIdOrNameStr, &endptr);
            if (endptr != ruleIdOrNameStr) {
                removeRuleById(ruleId);
            }
        }
    }
    LeaveCriticalSection(&g_critSec);
}
