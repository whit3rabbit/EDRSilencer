// File: process.h

#ifndef PROCESSES_H
#define PROCESSES_H

#include <stddef.h> // Required for size_t
 

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

 

#endif // PROCESSES_H