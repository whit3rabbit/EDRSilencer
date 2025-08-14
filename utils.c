#include <strsafe.h>
#include "utils.h"

BOOL g_isQuiet = FALSE;

BOOL CheckProcessIntegrityLevel() {
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = 0;
    BOOL isHighIntegrity = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            PRINTF("[-] OpenThreadToken failed with error code: 0x%lX.\n", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            PRINTF("[-] OpenProcessToken failed with error code: 0x%lX.\n", GetLastError());
            return FALSE;
        }
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength) && 
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                EPRINTF("[-] GetTokenInformation failed with error code: 0x%lX.\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
    if (pTIL == NULL) {
                EPRINTF("[-] LocalAlloc failed with error code: 0x%lX.\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
                EPRINTF("[-] GetTokenInformation failed with error code: 0x%lX.\n", GetLastError());
        LocalFree(pTIL);
        CloseHandle(hToken);
        return FALSE;
    }

    if (pTIL->Label.Sid == NULL || *GetSidSubAuthorityCount(pTIL->Label.Sid) < 1) {
        EPRINTF("[-] SID structure is invalid.\n");
        LocalFree(pTIL);
        CloseHandle(hToken);
        return FALSE;
    }
	
    dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        isHighIntegrity = TRUE;
    } else {
        EPRINTF("[-] This program requires to run in high integrity level.\n");
    }

    LocalFree(pTIL);
    CloseHandle(hToken);
    return isHighIntegrity;
}

BOOL EnableSeDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPrivileges = {0};
	
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
                        EPRINTF("[-] OpenThreadToken failed with error code: 0x%lX.\n", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
                    EPRINTF("[-] OpenProcessToken failed with error code: 0x%lX.\n", GetLastError());
            return FALSE;
        }
    }

	if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tokenPrivileges.Privileges[0].Luid)){
                EPRINTF("[-] LookupPrivilegeValueA failed with error code: 0x%lX.\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                EPRINTF("[-] AdjustTokenPrivileges failed with error code: 0x%lX.\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        EPRINTF("[-] Failed to get SeDebugPrivilege. You might not be able to get the process handle of the EDR process.\n");
		CloseHandle(hToken);
		return FALSE;
    }

	CloseHandle(hToken);
	return TRUE;
}

void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize) {
    int result = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wCharArray, wCharArraySize);

    if (result == 0) {
                EPRINTF("[-] MultiByteToWideChar failed with error code: 0x%lX.\n", GetLastError());
        wCharArray[0] = L'\0';
    }
}

BOOL GetDriveName(PCWSTR filePath, wchar_t* driveName, size_t driveNameSize) {
    if (!filePath) {
        return FALSE;
    }
    const wchar_t *colon = wcschr(filePath, L':');
          
    if (colon && (size_t)(colon - filePath + 1) < driveNameSize) {    
        wcsncpy(driveName, filePath, colon - filePath + 1);
        driveName[colon - filePath + 1] = L'\0';
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

    HRESULT hr = StringCchPrintfW(ntPathBuffer, bufferSize / sizeof(wchar_t), L"%ls%ls", ntDrivePath, filePath + wcslen(driveName));
    if (FAILED(hr)) {
        return CUSTOM_STRING_FORMATTING_ERROR;
    }
    
    for (size_t i = 0; ntPathBuffer[i] != L'\0'; ++i) {
        ntPathBuffer[i] = towlower(ntPathBuffer[i]);
    }
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

// SECURITY WARNING: This function is vulnerable to a Time-of-Check-to-Time-of-Use (TOCTOU) race condition.
// There is a time window between the FileExists check and when the path is used to create the App ID.
// An attacker could swap the file in that window, causing a rule to be applied to the wrong process.
// Given the tool's purpose (avoiding file handles), this risk is noted but accepted.
ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId) {
    if (!FileExists(filePath)) {
        return CUSTOM_FILE_NOT_FOUND;
    }

    WCHAR ntPath[MAX_PATH];
    ErrorCode errorCode = ConvertToNtPath(filePath, ntPath, sizeof(ntPath));
    if (errorCode != CUSTOM_SUCCESS) {
        return errorCode;
    }
    *appId = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
    if (!*appId) {
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    (*appId)->size = wcslen(ntPath) * sizeof(WCHAR) + sizeof(WCHAR);
    
    (*appId)->data = (UINT8*)malloc((*appId)->size);
    if (!(*appId)->data) {
        free(*appId);
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }
    memcpy((*appId)->data, ntPath, (*appId)->size);
    return CUSTOM_SUCCESS;
}

void FreeAppId(FWP_BYTE_BLOB* appId) {
    if (appId) {
        if (appId->data) {
            free(appId->data);
        }
        free(appId);
    }
}

// Function to get the full path of a process from its PID
BOOL getProcessFullPath(DWORD pid, WCHAR* fullPath, DWORD maxChars) {
    // Use PROCESS_QUERY_LIMITED_INFORMATION for better security and compatibility
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        // This can fail for protected system processes, which is expected.
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