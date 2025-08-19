#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// CRITICAL: winsock2.h must come before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <fwptypes.h>
#include <cstdio>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <string_view>
#include "process.hpp"

namespace EDRSilencer
{
    // --- WFP Type Forward Declarations ---
    typedef struct FWP_BYTE_BLOB_ FWP_BYTE_BLOB;

    // --- Extern Variables ---
    extern BOOL g_isQuiet;
    extern BOOL g_isForce;
    extern BOOL g_isFirewallMode;
    extern HANDLE g_hHeap;
    extern const char XOR_KEY;

    // --- Project GUID declarations (defined in a single translation unit) ---
    extern const GUID ProviderGUID;
    extern const GUID SubLayerGUID;

    // --- Console Macros ---
    #define PRINTF(...) do { if (!g_isQuiet) { EDRSilencer::ConsoleWriteA(GetStdHandle(STD_OUTPUT_HANDLE), __VA_ARGS__); } } while (0)
    #define WPRINTF(...) do { if (!g_isQuiet) { EDRSilencer::ConsoleWriteW(GetStdHandle(STD_OUTPUT_HANDLE), __VA_ARGS__); } } while (0)
    #define EPRINTF(...) do { EDRSilencer::ConsoleWriteA(GetStdHandle(STD_ERROR_HANDLE), __VA_ARGS__); } while (0)
    #define EWPRINTF(...) do { EDRSilencer::ConsoleWriteW(GetStdHandle(STD_ERROR_HANDLE), __VA_ARGS__); } while (0)

    // --- Provider/Filter Name Defines (overrideable for OPSEC) ---
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
    enum class ExitCode {
        EXIT_FAILURE_ARGS = 1,
        EXIT_FAILURE_PRIVS = 2,
        EXIT_FAILURE_WFP = 3,
        EXIT_FAILURE_GENERIC = 4
    };

    enum class CustomErrorCode {
        CUSTOM_SUCCESS = 0,
        CUSTOM_FILE_NOT_FOUND,
        CUSTOM_MEMORY_ALLOCATION_ERROR,
        CUSTOM_NULL_INPUT,
        CUSTOM_DRIVE_NAME_NOT_FOUND,
        CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME,
        CUSTOM_STRING_FORMATTING_ERROR,
        CUSTOM_ERROR_CODE_END
    };

    using ErrorCode = CustomErrorCode;

    // --- Function Prototypes ---
    void ConsoleWriteA(HANDLE hConsole, const char* format, ...);
    void ConsoleWriteW(HANDLE hConsole, const wchar_t* format, ...);
    BOOL getProcessFullPath(DWORD pid, WCHAR* fullPath, DWORD maxChars);
    BOOL CheckProcessIntegrityLevel();
    BOOL EnableSeDebugPrivilege();
    ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId);
    void FreeAppId(FWP_BYTE_BLOB* appId);
    std::string decryptString(const struct EncryptedString& encStr);
    BOOL FilterExists(HANDLE hEngine, const GUID* layerKey, const FWP_BYTE_BLOB* appId, const wchar_t* filterName);

    const wchar_t* LayerGuidToString(const GUID* layerGuid);

    // --- String Conversion Helpers (ANSI <-> Wide using system codepage) ---
    // Returns TRUE on success, FALSE on failure.
    BOOL AnsiToWide(std::string_view ansi, std::wstring& wideOut);
    BOOL WideToAnsi(std::wstring_view wide, std::string& ansiOut);
}

