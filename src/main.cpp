#include "core.hpp"
#include "errors.hpp"
#include "firewall.hpp"
#include <iostream>
#include <string>
#include <vector>

using namespace EDRSilencer;



void showHelp() {
    std::cout << "Usage: EDRSilencer.exe [--quiet | -q] [--firewall] <command>" << std::endl;
    std::cout << "Version: 1.8" << std::endl << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  blockedr    - Add network rules to block traffic of all detected target processes." << std::endl;
    std::cout << "  add <path>  - Add a network rule to block traffic for a specific process." << std::endl;
    std::cout << "                Example: EDRSilencer.exe add \"C:\\Windows\\System32\\curl.exe\"" << std::endl;
    std::cout << "  remove <id> - Remove a network rule by its ID." << std::endl;
    std::cout << "                (In WFP mode, this is a numeric ID. In firewall mode, this is a process path.)" << std::endl;
    std::cout << "                Example (WFP): EDRSilencer.exe remove 1234567890" << std::endl;
    std::cout << "                Example (Firewall): EDRSilencer.exe --firewall remove \"C:\\...\\app.exe\"" << std::endl;
    std::cout << "  list        - List all network rules applied by this tool." << std::endl;
    std::cout << std::endl << "Options:" << std::endl;
    std::cout << "  --quiet, -q - Suppress output messages." << std::endl;
    std::cout << "  --firewall  - Use Windows Firewall instead of WFP for rules." << std::endl;
    std::cout << "  help, -h    - Show this help message." << std::endl;
}

int main(int argc, char *argv[]) {
    g_hHeap = HeapCreate(0, 0, 0);
    if (g_hHeap == NULL) {
        PrintDetailedError("Critical error: Failed to create private heap", GetLastError());
        return static_cast<int>(ExitCode::EXIT_FAILURE_GENERIC);
    }

    std::vector<std::string> args(argv + 1, argv + argc);
    for (auto it = args.begin(); it != args.end(); ) {
        if (*it == "--quiet" || *it == "-q") {
            g_isQuiet = TRUE;
            it = args.erase(it);
        } else if (*it == "--firewall") {
            g_isFirewallMode = TRUE;
            it = args.erase(it);
        } else {
            ++it;
        }
    }

    if (args.empty()) {
        showHelp();
        HeapDestroy(g_hHeap);
        return static_cast<int>(ExitCode::EXIT_FAILURE_ARGS);
    }

    if (args[0] == "-h" || args[0] == "--help") {
        showHelp();
        HeapDestroy(g_hHeap);
        return 0; // EXIT_SUCCESS
    }

    if (!CheckProcessIntegrityLevel()) {
        HeapDestroy(g_hHeap);
        return static_cast<int>(ExitCode::EXIT_FAILURE_PRIVS);
    }

    if (args[0] == "remove") {
        if (args.size() < 2) {
            EPRINTF("[-] Missing argument for 'remove'. Provide a rule ID.\n");
            HeapDestroy(g_hHeap);
            return static_cast<int>(ExitCode::EXIT_FAILURE_ARGS);
        }
        if (g_isFirewallMode) {
            FirewallRemoveRuleByPath(args[1]);
        } else {
            char* endptr;
            UINT64 ruleId = CustomStrToULL(args[1].c_str(), &endptr);
            if (endptr == args[1].c_str() || *endptr != '\0') {
                EPRINTF("[-] Invalid rule ID provided. Please provide a numeric ID for WFP mode.\n");
                return static_cast<int>(ExitCode::EXIT_FAILURE_ARGS);
            }
            removeRuleById(ruleId);
        }
    } else if (args[0] == "blockedr" || args[0] == "add") {
        if (g_isForce) {
            EPRINTF("[-] The --force flag is not applicable to 'blockedr' or 'add'.\n");
            HeapDestroy(g_hHeap);
            return static_cast<int>(ExitCode::EXIT_FAILURE_ARGS);
        }
        if (args[0] == "blockedr") {
            if (g_isFirewallMode) {
                FirewallConfigureBlockRules();
            } else {
                configureNetworkFilters();
            }
        } else { // "add"
            if (args.size() < 2) {
                EPRINTF("[-] Missing argument. Please provide the full path of the process.\n");
                HeapDestroy(g_hHeap);
                return static_cast<int>(ExitCode::EXIT_FAILURE_ARGS);
            }
            if (g_isFirewallMode) {
                FirewallAddRuleByPath(args[1]);
            } else {
                addProcessRule(args[1]);
            }
        }
    } else if (args[0] == "list") {
        if (g_isFirewallMode) {
            PRINTF("[!] Listing rules is only implemented for WFP mode.\n");
            PRINTF("    Use standard Windows commands to view firewall rules, e.g.:\n");
            PRINTF("    > netsh advfirewall firewall show rule name=all | findstr \"EDR Silencer\"\n");
        } else {
            listRules();
        }
    } else {
        EPRINTF("[-] Invalid command: \"%s\". Use -h for help.\n", args[0].c_str());
        HeapDestroy(g_hHeap);
        return static_cast<int>(ExitCode::EXIT_FAILURE_ARGS);
    }

    HeapDestroy(g_hHeap);
    return 0; // EXIT_SUCCESS
}
