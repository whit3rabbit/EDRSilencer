#include "utils.h"
#include "errors.h" // For EPRINTF and EWPRINTF macros

// The lookup table. We'll add common WFP and Win32 errors.
static const ErrorMapping errorMappings[] = {
    // --- General Windows Errors ---
    { ERROR_SUCCESS, "The operation completed successfully." },
    { ERROR_ACCESS_DENIED, "Access is denied. (Are you running as Administrator?)" },
    { ERROR_INVALID_PARAMETER, "Invalid parameter provided to function." },
    { ERROR_INSUFFICIENT_BUFFER, "The data area passed to a system call is too small." },
    { ERROR_FILE_NOT_FOUND, "The system cannot find the file specified." },
    { ERROR_PRIVILEGE_NOT_HELD, "A required privilege is not held by the client." },

    // --- Windows Filtering Platform (WFP) Errors ---
    // These start with 0x8032... and are defined as FWP_E_...
    { 0x80320001, "FWP_E_CALLOUT_NOT_FOUND" },
    { 0x80320002, "FWP_E_CONDITION_NOT_FOUND" },
    { 0x80320003, "FWP_E_FILTER_NOT_FOUND" },
    { 0x80320004, "FWP_E_LAYER_NOT_FOUND" },
    { 0x80320005, "FWP_E_PROVIDER_NOT_FOUND" },
    { 0x80320006, "FWP_E_PROVIDER_CONTEXT_NOT_FOUND" },
    { 0x80320007, "FWP_E_SUBLAYER_NOT_FOUND" },
    { 0x80320008, "FWP_E_NOT_FOUND" },
    { 0x80320009, "FWP_E_ALREADY_EXISTS" },
    { 0x8032000A, "FWP_E_IN_USE" },
    { 0x8032000B, "FWP_E_DYNAMIC_SESSION_IN_PROGRESS" },
    { 0x8032000C, "FWP_E_WRONG_SESSION" },
    { 0x8032000D, "FWP_E_NO_TXN_IN_PROGRESS" },
    { 0x8032000E, "FWP_E_TXN_IN_PROGRESS" },
    { 0x8032000F, "FWP_E_TXN_ABORTED" },
    { 0x80320010, "FWP_E_SESSION_ABORTED" },
    { 0x80320011, "FWP_E_INCOMPATIBLE_TXN" },
    { 0x80320012, "FWP_E_TIMEOUT" },
    { 0x80320013, "FWP_E_NET_EVENTS_DISABLED" },
    { 0x80320014, "FWP_E_INCOMPATIBLE_LAYER" },
    { 0x80320015, "FWP_E_KM_CLIENTS_ONLY" },
    { 0x80320016, "FWP_E_LIFETIME_MISMATCH" },
    { 0x80320017, "FWP_E_BUILTIN_ACTION" },
    { 0x80320018, "FWP_E_TOO_MANY_CALLOUTS" },
    { 0x80320019, "FWP_E_NOTIFICATION_DROPPED" },
    { 0x8032001A, "FWP_E_TRAFFIC_MISMATCH" },
    { 0x8032001B, "FWP_E_INCOMPATIBLE_SA_STATE" },
    { 0x8032001D, "FWP_E_NULL_POINTER" },
    { 0x8032001E, "FWP_E_INVALID_ENUMERATOR" },
    { 0x8032001F, "FWP_E_INVALID_FLAGS" },
    { 0x80320020, "FWP_E_INVALID_NET_MASK" },
    { 0x80320021, "FWP_E_INVALID_RANGE" },
    { 0x80320022, "FWP_E_INVALID_INTERVAL" },
    { 0x80320025, "FWP_E_INVALID_ACTION_TYPE" },
    { 0x80320028, "FWP_E_SESSION_DISABLED" },
    { 0x80320029, "FWP_E_NOT_A_COMMIT" },
};

// Implementation of the error printing function (ANSI version)
void PrintDetailedError(const char* context, DWORD errorCode) {
    const char* message = NULL;
    size_t count = sizeof(errorMappings) / sizeof(errorMappings[0]);

    for (size_t i = 0; i < count; ++i) {
        if (errorMappings[i].code == errorCode) {
            message = errorMappings[i].message;
            break;
        }
    }

    if (message) {
        EPRINTF("[-] %s. Reason: %s (0x%lX)\n", context, message, errorCode);
    } else {
        EPRINTF("[-] %s. Error: 0x%lX\n", context, errorCode);
    }
}

// Implementation of the error printing function (Wide Char version)
void PrintDetailedErrorW(const wchar_t* context, DWORD errorCode) {
    const char* message = NULL;
    size_t count = sizeof(errorMappings) / sizeof(errorMappings[0]);

    for (size_t i = 0; i < count; ++i) {
        if (errorMappings[i].code == errorCode) {
            message = errorMappings[i].message;
            break;
        }
    }

    if (message) {
        // We print the message as multibyte because our console output is set for that
        EWPRINTF(L"[-] %s. Reason: %hs (0x%lX)\n", context, message, errorCode);
    } else {
        EWPRINTF(L"[-] %s. Error: 0x%lX\n", context, errorCode);
    }
}
