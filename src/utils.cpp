#include "utils.hpp"
#include "errors.hpp"
#include <strsafe.h>
 #include <string>
 #include <climits>
#pragma comment(lib, "Advapi32.lib")

namespace EDRSilencer {
const char XOR_KEY = 0x42;


void ConsoleWriteA(HANDLE hConsole, const char* format, ...) {
    char buffer[1024];
    DWORD bytesWritten;
    va_list args;

    va_start(args, format);
    // Using FormatMessage is complex for simple substitutions.
    // vsnprintf_s is CRT, so we'll use a combination of Win32 APIs.
    // A simpler way for non-CRT is to format it manually or use a safer sprint replacement.
    // For this example, we use StringCchVPrintfA for safe formatting.
    if (SUCCEEDED(StringCchVPrintfA(buffer, sizeof(buffer), format, args))) {
        WriteFile(hConsole, buffer, lstrlenA(buffer), &bytesWritten, NULL);
    }
    va_end(args);
}


BOOL AnsiToWide(std::string_view ansi, std::wstring& wideOut) {
    // Use system ACP to match Firewall COM expectations
    if (ansi.empty()) { wideOut.clear(); return TRUE; }
    int needed = MultiByteToWideChar(CP_ACP, 0, ansi.data(), static_cast<int>(ansi.size()), nullptr, 0);
    if (needed <= 0) return FALSE;
    wideOut.resize(static_cast<size_t>(needed));
    int written = MultiByteToWideChar(CP_ACP, 0, ansi.data(), static_cast<int>(ansi.size()), wideOut.data(), needed);
    return written > 0;
}

BOOL WideToAnsi(std::wstring_view wide, std::string& ansiOut) {
    if (wide.empty()) { ansiOut.clear(); return TRUE; }
    int needed = WideCharToMultiByte(CP_ACP, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return FALSE;
    ansiOut.resize(static_cast<size_t>(needed));
    int written = WideCharToMultiByte(CP_ACP, 0, wide.data(), static_cast<int>(wide.size()), ansiOut.data(), needed, nullptr, nullptr);
    return written > 0;
}

void ConsoleWriteW(HANDLE hConsole, const wchar_t* format, ...) {
    wchar_t buffer[1024];
    DWORD bytesWritten;
    va_list args;

    va_start(args, format);
    if (SUCCEEDED(StringCchVPrintfW(buffer, sizeof(buffer)/sizeof(wchar_t), format, args))) {
        // WriteConsoleW is better for wide characters
        WriteConsoleW(hConsole, buffer, lstrlenW(buffer), &bytesWritten, NULL);
    }
    va_end(args);
}


BOOL CheckProcessIntegrityLevel() {
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = 0;
    BOOL isHighIntegrity = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            PrintDetailedError("OpenThreadToken failed", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            PrintDetailedError("OpenProcessToken failed", GetLastError());
            return FALSE;
        }
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength) && 
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        PrintDetailedError("GetTokenInformation failed", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwLength);
    if (pTIL == NULL) {
        PrintDetailedError("HeapAlloc failed", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        PrintDetailedError("GetTokenInformation failed", GetLastError());
        HeapFree(g_hHeap, 0, pTIL);
        CloseHandle(hToken);
        return FALSE;
    }

    if (pTIL->Label.Sid == NULL || *GetSidSubAuthorityCount(pTIL->Label.Sid) < 1) {
        PrintDetailedError("SID structure is invalid", GetLastError());
        HeapFree(g_hHeap, 0, pTIL);
        CloseHandle(hToken);
        return FALSE;
    }
	
    dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        isHighIntegrity = TRUE;
    } else {
        PrintDetailedError("This program requires to run in high integrity level", GetLastError());
    }

    HeapFree(g_hHeap, 0, pTIL);
    CloseHandle(hToken);
    return isHighIntegrity;
}

BOOL EnableSeDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPrivileges = {0};
	
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            PrintDetailedError("OpenThreadToken failed", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            PrintDetailedError("OpenProcessToken failed", GetLastError());
            return FALSE;
        }
    }

	if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tokenPrivileges.Privileges[0].Luid)){
        PrintDetailedError("LookupPrivilegeValueA failed", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        PrintDetailedError("AdjustTokenPrivileges failed", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        PrintDetailedError("Failed to get SeDebugPrivilege", GetLastError());
		CloseHandle(hToken);
		return FALSE;
    }

	CloseHandle(hToken);
	return TRUE;
}

void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize) {
    // MultiByteToWideChar expects int for output buffer size; clamp safely to INT_MAX
    int cchWide = (wCharArraySize > static_cast<size_t>(INT_MAX)) ? INT_MAX : static_cast<int>(wCharArraySize);
    int result = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wCharArray, cchWide);

    if (result == 0) {
        PrintDetailedError("MultiByteToWideChar failed", GetLastError());
        wCharArray[0] = L'\0';
    }
}

BOOL GetDriveName(PCWSTR filePath, wchar_t* driveName, size_t driveNameSize) {
    if (!filePath) {
        return FALSE;
    }
    // wcschr is a fundamental CRT function, often inlined by the compiler.
    const wchar_t *colon = wcschr(filePath, L':');
          
    if (colon && (size_t)(colon - filePath + 1) < driveNameSize) {    
        StringCchCopyNW(driveName, driveNameSize, filePath, colon - filePath + 1);
        return TRUE;
    } else {
        return FALSE;
    }
}

ErrorCode ConvertToNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize) {
    WCHAR driveName[10];
    WCHAR ntDrivePath[MAX_PATH];
    if (!filePath || !ntPathBuffer) {
        return CustomErrorCode::CUSTOM_NULL_INPUT;
    }

    if (!GetDriveName(filePath, driveName, sizeof(driveName) / sizeof(WCHAR))) {
        return CustomErrorCode::CUSTOM_DRIVE_NAME_NOT_FOUND;
    }

    if (QueryDosDeviceW(driveName, ntDrivePath, sizeof(ntDrivePath) / sizeof(WCHAR)) == 0) {
        return CustomErrorCode::CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME;
    }

    HRESULT hr = StringCchPrintfW(ntPathBuffer, bufferSize / sizeof(wchar_t), L"%ls%ls", ntDrivePath, filePath + lstrlenW(driveName));
    if (FAILED(hr)) {
        return CustomErrorCode::CUSTOM_STRING_FORMATTING_ERROR;
    }

    CharLowerW(ntPathBuffer);
    return CustomErrorCode::CUSTOM_SUCCESS;
}


BOOL FileExists(PCWSTR filePath) {
    if (!filePath) {
        return FALSE;
    }

    DWORD fileAttrib = GetFileAttributesW(filePath);
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    return TRUE;
}

ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId) {
    if (!FileExists(filePath)) {
        return CustomErrorCode::CUSTOM_FILE_NOT_FOUND;
    }

    WCHAR ntPath[MAX_PATH];
    ErrorCode errorCode = ConvertToNtPath(filePath, ntPath, sizeof(ntPath));
    if (errorCode != CustomErrorCode::CUSTOM_SUCCESS) {
        return errorCode;
    }
    *appId = (FWP_BYTE_BLOB*)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, sizeof(FWP_BYTE_BLOB));
    if (!*appId) {
        return CustomErrorCode::CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    (*appId)->size = (lstrlenW(ntPath) + 1) * sizeof(WCHAR);
    
    (*appId)->data = (UINT8*)HeapAlloc(g_hHeap, 0, (*appId)->size);
    if (!(*appId)->data) {
        HeapFree(g_hHeap, 0, *appId);
        return CustomErrorCode::CUSTOM_MEMORY_ALLOCATION_ERROR;
    }
    // memcpy is also CRT, but often intrinsic. CopyMemory is the Win32 equivalent.
    CopyMemory((*appId)->data, ntPath, (*appId)->size);
    return CustomErrorCode::CUSTOM_SUCCESS;
}

void FreeAppId(FWP_BYTE_BLOB* appId) {
    if (appId) {
        if (appId->data) {
            HeapFree(g_hHeap, 0, appId->data);
        }
        HeapFree(g_hHeap, 0, appId);
    }
}

// Function to get the full path of a process from its PID
BOOL getProcessFullPath(DWORD pid, WCHAR* fullPath, DWORD maxChars) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return FALSE;
    }

    DWORD bufferSize = maxChars;
    if (QueryFullProcessImageNameW(hProcess, 0, fullPath, &bufferSize) == 0) {
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hProcess);
    return TRUE;
}

std::string decryptString(const struct EncryptedString& encStr) {
    if (!encStr.data || encStr.size == 0) {
        return {};
    }
    std::string decrypted;
    decrypted.reserve(encStr.size);
    for (size_t i = 0; i < encStr.size; ++i) {
        decrypted.push_back(static_cast<char>(encStr.data[i] ^ XOR_KEY));
    }
    return decrypted;
}

BOOL FilterExists(HANDLE hEngine, const GUID* layerKey, const FWP_BYTE_BLOB* appId, const wchar_t* filterName) {
    BOOL exists = FALSE;
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** filters = NULL;
    UINT32 numEntries = 0;

    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = {0};
    enumTemplate.layerKey = *layerKey;
    enumTemplate.providerKey = (GUID*)&ProviderGUID;
    enumTemplate.numFilterConditions = 1;

    FWPM_FILTER_CONDITION0 condition = {0};
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = (FWP_BYTE_BLOB*)appId;
    enumTemplate.filterCondition = &condition;

    if (FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle) == ERROR_SUCCESS) {
        // Enumerate all matching filters to check their names
        if (FwpmFilterEnum0(hEngine, enumHandle, (UINT32)-1, &filters, &numEntries) == ERROR_SUCCESS) {
            for (UINT32 i = 0; i < numEntries; i++) {
                if (filters[i]->displayData.name && filterName && wcscmp(filters[i]->displayData.name, filterName) == 0) {
                    exists = TRUE;
                    break;
                }
            }
            FwpmFreeMemory0((void**)&filters);
        }
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    }
    return exists;
}

UINT64 CustomStrToULL(const char* str, char** endptr) {
    UINT64 result = 0;
    const char* p = str;

    if (!str) {
        if (endptr) *endptr = (char*)str;
        return 0;
    }

    #if 0
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\f' || *p == '\v')) {
        p++;
    }
    #endif
    while (*p && isspace(static_cast<unsigned char>(*p))) {
        ++p;
    }

    while (*p && (*p >= '0' && *p <= '9')) {
        if (result > (0xFFFFFFFFFFFFFFFF / 10)) {
            result = 0xFFFFFFFFFFFFFFFF;
            break;
        }
        result *= 10;

        UINT64 digit = *p - '0';
        if (result > 0xFFFFFFFFFFFFFFFF - digit) {
            result = 0xFFFFFFFFFFFFFFFF;
            break;
        }
        result += digit;
        p++;
    }

    if (endptr) {
        *endptr = (char*)p;
    }

    return result;
}

const wchar_t* LayerGuidToString(const GUID* layerGuid) {
    if (IsEqualGUID(*layerGuid, FWPM_LAYER_ALE_AUTH_CONNECT_V4)) return L"ALE Connect v4";
    if (IsEqualGUID(*layerGuid, FWPM_LAYER_ALE_AUTH_CONNECT_V6)) return L"ALE Connect v6";
    if (IsEqualGUID(*layerGuid, FWPM_LAYER_OUTBOUND_TRANSPORT_V4)) return L"Outbound Transport v4";
    if (IsEqualGUID(*layerGuid, FWPM_LAYER_OUTBOUND_TRANSPORT_V6)) return L"Outbound Transport v6";
    return L"Unknown Layer";
}

} // namespace EDRSilencer