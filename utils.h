#ifndef UTILS_H
#define UTILS_H

#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <fwptypes.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "process.h"

/*
 * utils.h
 * -------
 * Common types, globals, GUIDs, and helper APIs used across EDRSilencer.
 *
 * Key notes:
 * - _WIN32_WINNT 0x0601 targets Windows 7+ for WFP APIs used by this project.
 * - Console macros honor the global quiet flag to minimize OPSEC footprint; stderr always prints.
 * - Provider/sublayer/filter names are compile-time overrideable for OPSEC (see defines below).
 */

// --- WFP Type Forward Declarations ---
// Some toolchains lack full forward decls for opaque WFP structs; provide minimal forward reference.
typedef struct FWP_BYTE_BLOB_ FWP_BYTE_BLOB;

// --- Extern Variables ---
// Global runtime flags and shared resources set by the DLL entrypoints/exports.
// g_isQuiet: suppresses stdout messages (stderr still active via EPRINTF/EWPRINTF)
// g_isForce:  enables forced operations where applicable
// g_isFirewallMode: toggles between WFP mode (false) and Windows Firewall mode (true)
// g_hHeap:    process heap used for consistent allocations/free
// XOR_KEY:    key used for simple obfuscation/deobfuscation of embedded strings
extern BOOL g_isQuiet;
extern BOOL g_isForce;
extern BOOL g_isFirewallMode;
extern HANDLE g_hHeap;
extern const char XOR_KEY;

// --- MANUAL GUID DEFINITIONS (Self-Contained & Corrected) ---
// Keep GUIDs local to avoid header dependencies and ensure consistency across builds.
// ProviderGUID/SubLayerGUID identify our namespace in WFP; layers/conditions are standard WFP GUIDs.
DEFINE_GUID(ProviderGUID, 0x4e27e7d4, 0x2442, 0x4891, 0x91, 0x2e, 0x42, 0x5, 0x42, 0x8a, 0x85, 0x55);
DEFINE_GUID(SubLayerGUID, 0xd25b7369, 0x871b, 0x44f1, 0x82, 0x75, 0x5a, 0x30, 0xca, 0x1f, 0x5e, 0x57);

DEFINE_GUID(FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82);
DEFINE_GUID(FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0xc38d57d0, 0x4834, 0x43cd, 0x94, 0x69, 0x1a, 0x33, 0xce, 0x10, 0x22, 0x76);
DEFINE_GUID(FWPM_LAYER_OUTBOUND_TRANSPORT_V4, 0x4963864f, 0x9996, 0x4a8c, 0xac, 0xf0, 0x7e, 0x54, 0xd9, 0x47, 0x2b, 0x13);
DEFINE_GUID(FWPM_LAYER_OUTBOUND_TRANSPORT_V6, 0x51096519, 0x4552, 0x4939, 0x86, 0x3a, 0x59, 0x79, 0x4e, 0x6d, 0x16, 0x4b);
DEFINE_GUID(FWPM_CONDITION_ALE_APP_ID,        0xd78e1e87, 0x8644, 0x4ea5, 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71);
DEFINE_GUID(FWPM_CONDITION_ALE_IP_PROTOCOL,   0x39722b3f, 0x8a25, 0x4a59, 0x99, 0x23, 0x28, 0x14, 0x03, 0xc3, 0x24, 0x9f);
DEFINE_GUID(FWPM_CONDITION_ALE_REMOTE_PORT,   0x435cc29b, 0x8952, 0x471a, 0x96, 0xb8, 0x74, 0xac, 0x75, 0x61, 0x01, 0x43);

// --- Console Macros ---
// PRINTF/WPRINTF write to stdout only when g_isQuiet == FALSE.
// EPRINTF/EWPRINTF always write to stderr for error visibility irrespective of quiet mode.
#define PRINTF(...) do { if (!g_isQuiet) { ConsoleWriteA(GetStdHandle(STD_OUTPUT_HANDLE), __VA_ARGS__); } } while (0)
#define WPRINTF(...) do { if (!g_isQuiet) { ConsoleWriteW(GetStdHandle(STD_OUTPUT_HANDLE), __VA_ARGS__); } } while (0)
#define EPRINTF(...) do { ConsoleWriteA(GetStdHandle(STD_ERROR_HANDLE), __VA_ARGS__); } while (0)
#define EWPRINTF(...) do { ConsoleWriteW(GetStdHandle(STD_ERROR_HANDLE), __VA_ARGS__); } while (0)

// --- Provider/Filter Name Defines (overrideable for OPSEC) ---
// Operators may override these at compile time to reduce fingerprinting.
// Example (MinGW): -DEDR_PROVIDER_NAME=L"Windows Diagnostics Provider"
#ifndef EDR_PROVIDER_NAME
#define EDR_PROVIDER_NAME L"EDR Silencer Provider"
#endif

#ifndef EDR_SUBLAYER_NAME
#define EDR_SUBLAYER_NAME L"EDR Silencer SubLayer"
#endif

#ifndef EDR_FILTER_NAME
#define EDR_FILTER_NAME L"EDRSilencer Generic Block Rule"
#endif

#ifndef FIREWALL_RULE_NAME_FORMAT
#define FIREWALL_RULE_NAME_FORMAT L"Block Rule for %s"
#endif

// --- Exit Codes ---
// Standardized return codes for BOF/DLL invocations to simplify operator troubleshooting.
typedef enum ExitCode { EXIT_FAILURE_ARGS = 1, EXIT_FAILURE_PRIVS = 2, EXIT_FAILURE_WFP = 3, EXIT_FAILURE_GENERIC = 4 } ExitCode;
typedef enum {
    CUSTOM_SUCCESS = 0,
    CUSTOM_FILE_NOT_FOUND,
    CUSTOM_MEMORY_ALLOCATION_ERROR,
    CUSTOM_NULL_INPUT,
    CUSTOM_DRIVE_NAME_NOT_FOUND,
    CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME,
    CUSTOM_STRING_FORMATTING_ERROR,
    CUSTOM_ERROR_CODE_END
} CustomErrorCode;

typedef CustomErrorCode ErrorCode;

// --- Function Prototypes ---
// ConsoleWriteA/W: Minimal, dependency-light console output wrappers.
void ConsoleWriteA(HANDLE hConsole, const char* format, ...);
void ConsoleWriteW(HANDLE hConsole, const wchar_t* format, ...);
// getProcessFullPath: Resolve a process image full path by PID.
BOOL getProcessFullPath(DWORD pid, WCHAR* fullPath, DWORD maxChars);
// CheckProcessIntegrityLevel: Determine if the current process meets required integrity.
BOOL CheckProcessIntegrityLevel();
// EnableSeDebugPrivilege: Elevate SeDebugPrivilege for process inspection where needed.
BOOL EnableSeDebugPrivilege();
// CustomFwpmGetAppIdFromFileName0/FreeAppId: Obtain and free WFP AppID blobs for file paths.
ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId);
void FreeAppId(FWP_BYTE_BLOB* appId);
// decryptString: Decrypt embedded strings at runtime using XOR_KEY.
char* decryptString(struct EncryptedString encStr);
// FilterExists: Utility to detect presence of a named filter for an AppID at a layer.
BOOL FilterExists(HANDLE hEngine, const GUID* layerKey, const FWP_BYTE_BLOB* appId, const wchar_t* filterName);

#endif // UTILS_H