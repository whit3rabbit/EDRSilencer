#include "utils.hpp"
#include "errors.hpp"

namespace EDRSilencer
{
    // The lookup table. We'll add common WFP and Win32 errors.
    static constexpr ErrorMapping errorMappings[] = {
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
        { 0x8032001C, "FWP_E_NULL_POINTER: A required pointer is null." },
        { 0x80320023, "FWP_E_NULL_DISPLAY_NAME: The displayData.name field cannot be null." },
        { 0x80320024, "FWP_E_INVALID_ACTION_TYPE: The action type is not one of the allowed action types for a filter." },
        { 0x80320026, "FWP_E_MATCH_TYPE_MISMATCH: A filter condition contains a match type that is not compatible with the operands." },
        { 0x80320027, "FWP_E_TYPE_MISMATCH: An FWP_VALUE0 structure or an FWPM_CONDITION_VALUE0 structure is of the wrong type." },
        { 0x8032002A, "FWP_E_DUPLICATE_CONDITION: A filter cannot contain multiple conditions operating on a single field." },
        { 0x8032002C, "FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER: The action type is not compatible with the layer." },
        { 0x8032002D, "FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER: The action type is not compatible with the sub-layer." },
        { 0x8032002E, "FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER: The raw context or the provider context is not compatible with the layer." },
        { 0x8032002F, "FWP_E_CONTEXT_INCOMPATIBLE_WITH_CALLOUT: The raw context or the provider context is not compatible with the callout." },
        { 0x80320030, "FWP_E_INCOMPATIBLE_AUTH_METHOD: The authentication method is not compatible with the policy type." },
        { 0x80320031, "FWP_E_INCOMPATIBLE_DH_GROUP: The Diffie-Hellman group is not compatible with the policy type." },
        { 0x80320032, "FWP_E_EM_NOT_SUPPORTED: An IKE policy cannot contain an Extended Mode policy." },
        { 0x80320033, "FWP_E_NEVER_MATCH: The enumeration template or subscription will never match any objects." },
        { 0x80320034, "FWP_E_PROVIDER_CONTEXT_MISMATCH: The provider context is of the wrong type." },
        { 0x80320036, "FWP_E_TOO_MANY_SUBLAYERS: The maximum number of sublayers has been reached. WFP supports at most 2^16 sublayers." },
        { 0x80320038, "FWP_E_INVALID_AUTH_TRANSFORM: The IPsec authentication transform is not valid." },
        { 0x80320039, "FWP_E_INVALID_CIPHER_TRANSFORM: The IPsec cipher transform is not valid." }

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
}
