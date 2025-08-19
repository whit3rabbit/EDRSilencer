// Ensure Winsock2 is included before Windows headers to avoid conflicts
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Ensure any GUIDs using DEFINE_GUID in subsequent headers get defined here
#include <initguid.h>
#include <fwpmu.h>

namespace EDRSilencer {
    // Define project-specific GUIDs exactly once
    extern const GUID ProviderGUID = { 0x4e27e7d4, 0x2442, 0x4891, { 0x91, 0x2e, 0x42, 0x05, 0x42, 0x8a, 0x85, 0x55 } };
    extern const GUID SubLayerGUID = { 0xd25b7369, 0x871b, 0x44f1, { 0x82, 0x75, 0x5a, 0x30, 0xca, 0x1f, 0x5e, 0x57 } };
}
