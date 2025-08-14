// File: process.h

#ifndef PROCESSES_H
#define PROCESSES_H

#include <stddef.h> // Required for size_t
#include <windows.h> // Required for BOOL

// The struct definition is needed here so any file including this header
// knows what 'struct EncryptedString' is.
struct EncryptedString {
    const unsigned char* data;
    size_t size;
};

// DECLARATION of the array. The 'extern' keyword tells the compiler:
// "This array is defined in another .c file. The linker will find it."
extern struct EncryptedString processData[];

// DECLARATION of the array's size. We need this because sizeof()
// will not work on an external array declaration.
extern const size_t PROCESS_DATA_COUNT;

// DECLARATION of the function that checks the process list.
// This allows EDRSilencer.c to call this function.
BOOL isProcessInList(const char* procName);

#endif // PROCESSES_H