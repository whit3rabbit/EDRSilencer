#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// This header should be included by all source files to ensure correct
// include order and provide access to global definitions.

// 1. Define the Windows version and enforce correct include order.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Target Windows 7 or later
#endif

// MUST be included before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// 2. Include all other necessary system headers
#include <fwpmu.h>
#include <netfw.h>
#include <tlhelp32.h>
#include <strsafe.h>

// 3. Include project-specific headers
#include "beacon.h"

// 4. Define all project-wide GUIDs and constants
DEFINE_GUID(ProviderGUID, 0x4a4e4635, 0x8a2c, 0x4021, 0x95, 0x5, 0x6c, 0x80, 0x26, 0x2, 0x99, 0x2d);
DEFINE_GUID(SubLayerGUID, 0x4a4e4636, 0x8a2c, 0x4021, 0x95, 0x5, 0x6c, 0x80, 0x26, 0x2, 0x99, 0x2d);

#define EDR_PROVIDER_NAME L"EDRSilencer Provider"
#define EDR_SUBLAYER_NAME L"EDRSilencer Sublayer"
#define EDR_FILTER_NAME L"EDRSilencer Generic Block Rule"

#define EDR_PROVIDER_DESCRIPTION L"Provider for EDRSilencer WFP filters"
#define EDR_SUBLAYER_DESCRIPTION L"Sublayer for EDRSilencer WFP filters"
#define FIREWALL_RULE_GROUP L"EDRSilencer Rules"
#define FIREWALL_RULE_NAME_FORMAT L"EDRSilencer - %s"

typedef enum {
    CUSTOM_SUCCESS = 0,
    CUSTOM_NULL_INPUT,
    CUSTOM_DRIVE_NAME_NOT_FOUND,
    CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME,
    CUSTOM_STRING_FORMATTING_ERROR
} ErrorCode;

// 5. Declare global variables (to be defined in a .c file)
extern HANDLE g_hHeap;
extern BOOL g_isFirewallMode;
extern BOOL g_isQuiet;
extern BOOL g_isForce;

// 6. Declare function prototypes from across the project
// from process.c
struct EncryptedString { const unsigned char* data; size_t len; };
extern struct EncryptedString processData[];
extern const size_t PROCESS_DATA_COUNT;

// from utils.c
BOOL EnableSeDebugPrivilege();
BOOL CheckProcessIntegrityLevel();
char* decryptString(struct EncryptedString s);
BOOL getProcessFullPath(DWORD pid, WCHAR* fullPath, DWORD maxLen);
UINT64 CustomStrToULL(const char* str, char** endptr);
void PrintDetailedError(const char* userMessage, DWORD errorCode);
void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize);
BOOL GetDriveName(PCWSTR filePath, wchar_t* driveName, size_t driveNameSize);
ErrorCode ConvertToNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize);
BOOL FileExists(PCWSTR filePath);
DWORD CustomFwpmGetAppIdFromFileName0(PCWSTR fileName, FWP_BYTE_BLOB** appId);
void FreeAppId(FWP_BYTE_BLOB* appId);
BOOL FilterExists(HANDLE hEngine, const GUID* layerKey, const FWP_BYTE_BLOB* appId, const wchar_t* filterName);

// from core.c
void configureNetworkFilters();
void addProcessRule(const char* processPath);
void removeAllRules();
void listRules();
void removeRuleById(UINT64 ruleId);

// from firewall.c
void FirewallConfigureBlockRules();
void FirewallAddRuleByPath(const char* processPath);
void FirewallRemoveRuleByPath(const char* processPath);
void FirewallRemoveAllRules();

#ifdef __cplusplus
}
#endif
