#include "core.h"
#include "errors.h"
#include "firewall.h"

HANDLE g_hHeap = NULL;
BOOL g_isQuiet = FALSE;
BOOL g_isForce = FALSE;
BOOL g_isFirewallMode = FALSE;

// showHelp function is specific to the EXE
void showHelp() {
    PRINTF("Usage: EDRSilencer.exe [--quiet | -q] [--firewall] <command>\n");
    PRINTF("Version: 1.8\n\n");
    PRINTF("Commands:\n");
    PRINTF("  blockedr    - Add network rules to block traffic of all detected target processes.\n");
    PRINTF("  add <path>  - Add a network rule to block traffic for a specific process.\n");
    PRINTF("                Example: EDRSilencer.exe add \"C:\\Windows\\System32\\curl.exe\"\n");
    PRINTF("  remove <id> - Remove a network rule by its ID.\n");
    PRINTF("                (In WFP mode, this is a numeric ID. In firewall mode, this is a process path.)\n");
    PRINTF("                Example (WFP): EDRSilencer.exe remove 1234567890\n");
    PRINTF("                Example (Firewall): EDRSilencer.exe --firewall remove \"C:\\...\\app.exe\"\n");
    PRINTF("  list        - List all network rules applied by this tool.\n");
    PRINTF("\nOptions:\n");
    PRINTF("  --quiet, -q - Suppress output messages.\n");
    PRINTF("  --firewall  - Use Windows Firewall instead of WFP for rules.\n");
    PRINTF("  help, -h    - Show this help message.\n");
}

int main(int argc, char *argv[]) {
    g_hHeap = HeapCreate(0, 0, 0);
    if (g_hHeap == NULL) {
        PrintDetailedError("Critical error: Failed to create private heap", GetLastError());
        return EXIT_FAILURE_GENERIC;
    }

    for (int i = 1; i < argc; i++) {
        if (lstrcmpiA(argv[i], "--quiet") == 0 || lstrcmpiA(argv[i], "-q") == 0) {
            g_isQuiet = TRUE;
            for (int j = i; j < argc - 1; j++) { argv[j] = argv[j + 1]; }
            argc--;
            i--;
        } else if (lstrcmpiA(argv[i], "--firewall") == 0) {
            g_isFirewallMode = TRUE;
            for (int j = i; j < argc - 1; j++) { argv[j] = argv[j + 1]; }
            argc--;
            i--;
        }
    }
    if (argc < 2) {
        showHelp();
        HeapDestroy(g_hHeap);
        return EXIT_FAILURE_ARGS;
    }

    if (lstrcmpiA(argv[1], "-h") == 0 || lstrcmpiA(argv[1], "--help") == 0) {
        showHelp();
        HeapDestroy(g_hHeap);
        return 0; // EXIT_SUCCESS
    }
    
    if (!CheckProcessIntegrityLevel()) {
        HeapDestroy(g_hHeap);
        return EXIT_FAILURE_PRIVS;
    }

    if (lstrcmpiA(argv[1], "remove") == 0) {
        if (argc < 3) {
            EPRINTF("[-] Missing argument for 'remove'. Provide a rule ID.\n");
            HeapDestroy(g_hHeap);
            return EXIT_FAILURE_ARGS;
        }
        if (g_isFirewallMode) {
            FirewallRemoveRuleByPath(argv[2]);
        } else {
            char* endptr;
            UINT64 ruleId = CustomStrToULL(argv[2], &endptr);
            if (endptr == argv[2] || *endptr != '\0') {
                EPRINTF("[-] Invalid rule ID provided. Please provide a numeric ID for WFP mode.\n");
                return EXIT_FAILURE_ARGS;
            }
            removeRuleById(ruleId);
        }
    } else if (lstrcmpiA(argv[1], "blockedr") == 0 || lstrcmpiA(argv[1], "add") == 0) {
        if (g_isForce) {
            EPRINTF("[-] The --force flag is not applicable to 'blockedr' or 'add'.\n");
            HeapDestroy(g_hHeap);
            return EXIT_FAILURE_ARGS;
        }
        if (lstrcmpiA(argv[1], "blockedr") == 0) {
            if (g_isFirewallMode) {
                FirewallConfigureBlockRules();
            } else {
                configureNetworkFilters();
            }
        } else { // "add"
            if (argc < 3) {
                EPRINTF("[-] Missing argument. Please provide the full path of the process.\n");
                HeapDestroy(g_hHeap);
                return EXIT_FAILURE_ARGS;
            }
            if (g_isFirewallMode) {
                FirewallAddRuleByPath(argv[2]);
            } else {
                addProcessRule(argv[2]);
            }
        }
    } else if (lstrcmpiA(argv[1], "list") == 0) {
        if (g_isFirewallMode) {
            PRINTF("[!] Listing rules is only implemented for WFP mode.\n");
            PRINTF("    Use standard Windows commands to view firewall rules, e.g.:\n");
            PRINTF("    > netsh advfirewall firewall show rule name=all | findstr \"EDR Silencer\"\n");
        } else {
            listRules();
        }
    } else {
        EPRINTF("[-] Invalid command: \"%s\". Use -h for help.\n", argv[1]);
        HeapDestroy(g_hHeap);
        return EXIT_FAILURE_ARGS;
    }

    HeapDestroy(g_hHeap);
    return 0; // EXIT_SUCCESS
}
