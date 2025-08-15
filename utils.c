#include "utils.h"
#include "errors.h"
#include <strsafe.h>

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
    int result = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wCharArray, wCharArraySize);

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
        return CUSTOM_NULL_INPUT;
    }

    if (!GetDriveName(filePath, driveName, sizeof(driveName) / sizeof(WCHAR))) {
        return CUSTOM_DRIVE_NAME_NOT_FOUND;
    }

    if (QueryDosDeviceW(driveName, ntDrivePath, sizeof(ntDrivePath) / sizeof(WCHAR)) == 0) {
        return CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME;
    }

    HRESULT hr = StringCchPrintfW(ntPathBuffer, bufferSize / sizeof(wchar_t), L"%ls%ls", ntDrivePath, filePath + lstrlenW(driveName));
    if (FAILED(hr)) {
        return CUSTOM_STRING_FORMATTING_ERROR;
    }

    CharLowerW(ntPathBuffer);
    return CUSTOM_SUCCESS;
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
        return CUSTOM_FILE_NOT_FOUND;
    }

    WCHAR ntPath[MAX_PATH];
    ErrorCode errorCode = ConvertToNtPath(filePath, ntPath, sizeof(ntPath));
    if (errorCode != CUSTOM_SUCCESS) {
        return errorCode;
    }
    *appId = (FWP_BYTE_BLOB*)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, sizeof(FWP_BYTE_BLOB));
    if (!*appId) {
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    (*appId)->size = (lstrlenW(ntPath) + 1) * sizeof(WCHAR);
    
    (*appId)->data = (UINT8*)HeapAlloc(g_hHeap, 0, (*appId)->size);
    if (!(*appId)->data) {
        HeapFree(g_hHeap, 0, *appId);
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }
    // memcpy is also CRT, but often intrinsic. CopyMemory is the Win32 equivalent.
    CopyMemory((*appId)->data, ntPath, (*appId)->size);
    return CUSTOM_SUCCESS;
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

char* decryptString(struct EncryptedString encStr) {
    if (!encStr.data || encStr.size == 0) {
        return NULL;
    }

    char* decrypted = (char*)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, encStr.size + 1);
    if (!decrypted) {
        EPRINTF("[-] Failed to allocate memory for decrypted string.\n");
        return NULL;
    }

    for (size_t i = 0; i < encStr.size; ++i) {
        decrypted[i] = encStr.data[i] ^ XOR_KEY;
    }
    decrypted[encStr.size] = '\0';

    return decrypted;
}

BOOL FilterExists(HANDLE hEngine, const GUID* layerKey, const FWP_BYTE_BLOB* appId) {
    BOOL exists = FALSE;
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** filters = NULL;
    UINT32 numEntries = 0;

    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = {0};
    enumTemplate.layerKey = *layerKey;
    enumTemplate.providerKey = (GUID*)&ProviderGUID; // Check only for filters from our provider
    enumTemplate.numFilterConditions = 1;
    
    FWPM_FILTER_CONDITION0 condition = {0};
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = (FWP_BYTE_BLOB*)appId;
    enumTemplate.filterCondition = &condition;

    if (FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle) == ERROR_SUCCESS) {
        if (FwpmFilterEnum0(hEngine, enumHandle, 1, &filters, &numEntries) == ERROR_SUCCESS) {
            if (numEntries > 0) {
                exists = TRUE; // We found at least one matching filter
            }
            FwpmFreeMemory0((void**)&filters);
        }
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    }
    return exists;
}