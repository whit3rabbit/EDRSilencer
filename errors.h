// File: errors.h
#ifndef ERRORS_H
#define ERRORS_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <windows.h> // For DWORD

// The structure to map error codes to strings
typedef struct {
    DWORD code;
    const char* message;
} ErrorMapping;

// Function prototype for our error handler
void PrintDetailedError(const char* context, DWORD errorCode);
void PrintDetailedErrorW(const wchar_t* context, DWORD errorCode);


#endif // ERRORS_H
