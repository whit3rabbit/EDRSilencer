#pragma once

// Intentionally no Windows SDK includes here.
// Consumers must include `utils.hpp` (directly or indirectly) before this header
// so that Windows types like DWORD are available with the correct include order.

namespace EDRSilencer
{
    // The structure to map error codes to strings
    struct ErrorMapping {
        DWORD code;
        const char* message;
    };

    // Function prototype for our error handler
    void PrintDetailedError(const char* context, DWORD errorCode);
    void PrintDetailedErrorW(const wchar_t* context, DWORD errorCode);
}
