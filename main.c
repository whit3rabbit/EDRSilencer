#include "core.h"

HANDLE g_hHeap = NULL;
BOOL g_isQuiet = FALSE;

// showHelp function is specific to the EXE
void showHelp() {
    PRINTF("Usage: EDRSilencer.exe [--quiet | -q] <command>\n");
    PRINTF("Version: 1.5\n\n");
    PRINTF("Commands:\n");
    PRINTF("  blockedr    - Add network rules to block traffic of all detected target processes.\n");
    PRINTF("  add <path>  - Add a network rule to block traffic for a specific process.\n");
    PRINTF("                Example: EDRSilencer.exe add \"C:\\Windows\\System32\\curl.exe\"\n");
    PRINTF("  removeall   - Remove all network rules applied by this tool.\n");
    PRINTF("  remove <id> - Remove a specific network rule by its ID.\n");
    PRINTF("\nOptions:\n");
    PRINTF("  -q, --quiet - Suppress all console output.\n");
}

int main(int argc, char *argv[]) {
    g_hHeap = HeapCreate(0, 0, 0);
    if (g_hHeap == NULL) {
        HANDLE hStdErr = GetStdHandle(STD_ERROR_HANDLE);
        const char* msg = "[-] Critical error: Failed to create private heap.\n";
        DWORD written;
        WriteFile(hStdErr, msg, lstrlenA(msg), &written, NULL);
        return EXIT_FAILURE_GENERIC;
    }

    for (int i = 1; i < argc; i++) {
        if (lstrcmpiA(argv[i], "--quiet") == 0 || lstrcmpiA(argv[i], "-q") == 0) {
            g_isQuiet = TRUE;
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
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

    if (lstrcmpiA(argv[1], "blockedr") == 0) {
        configureNetworkFilters();
    } else if (lstrcmpiA(argv[1], "add") == 0) {
        if (argc < 3) {
            EPRINTF("[-] Missing argument. Please provide the full path of the process.\n");
            HeapDestroy(g_hHeap);
            return EXIT_FAILURE_ARGS;
        }
        addProcessRule(argv[2]);
    } else if (lstrcmpiA(argv[1], "removeall") == 0) {
        removeAllRules();
    } else if (lstrcmpiA(argv[1], "remove") == 0) {
        if (argc < 3) {
            EPRINTF("[-] Missing argument. Please provide the rule ID.\n");
            HeapDestroy(g_hHeap);
            return EXIT_FAILURE_ARGS;
        }
        char *endptr;
        UINT64 ruleId = CustomStrToULL(argv[2], &endptr);
        if (endptr == argv[2]) { // No digits were read
            EPRINTF("[-] Invalid rule ID provided.\n");
            HeapDestroy(g_hHeap);
            return EXIT_FAILURE_ARGS;
        }
        removeRuleById(ruleId);
    } else {
        EPRINTF("[-] Invalid command: \"%s\". Use -h for help.\n", argv[1]);
        HeapDestroy(g_hHeap);
        return EXIT_FAILURE_ARGS;
    }

    HeapDestroy(g_hHeap);
    return 0; // EXIT_SUCCESS
}
