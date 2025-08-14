# Compiler
CC = x86_64-w64-mingw32-gcc

# --- Source File Definitions ---
# Common source files used by both EXE and DLL
COMMON_SRCS = core.c utils.c process.c
# Entry-point source for the Executable
EXE_SRC = main.c
# Entry-point source for the DLL
DLL_SRC = dllmain.c

# --- Target Filename Definitions ---
TARGET_EXE_RELEASE = EDRSilencer.exe
TARGET_EXE_DEBUG = EDRSilencer_debug.exe
TARGET_DLL_RELEASE = EDRSilencer.dll
TARGET_DLL_DEBUG = EDRSilencer_debug.dll

# --- Flag Definitions ---
# Common flags for C compilation
CFLAGS_RELEASE = -Wall -Wextra -O2
CFLAGS_DEBUG = -Wall -Wextra -g
# Linker flags for building an EXE
LDFLAGS_EXE = -lfwpuclnt
# Linker flags for building a DLL (note the -shared flag)
LDFLAGS_DLL = -lfwpuclnt -shared

.PHONY: all release debug dll dll-debug clean

# --- Main Targets ---

# Default target: 'make' or 'make all' will build the release EXE
all: release

# 'make release' builds the release EXE
release: $(TARGET_EXE_RELEASE)

# 'make debug' builds the debug EXE
debug: $(TARGET_EXE_DEBUG)

# 'make dll' builds the release DLL
dll: $(TARGET_DLL_RELEASE)

# 'make dll-debug' builds the debug DLL
dll-debug: $(TARGET_DLL_DEBUG)

# --- Build Rules ---

# Rule to build the release EXE
$(TARGET_EXE_RELEASE): $(COMMON_SRCS) $(EXE_SRC)
	$(CC) $(CFLAGS_RELEASE) $^ -o $@ $(LDFLAGS_EXE) -s
	@echo "Release EXE build complete: $@"

# Rule to build the debug EXE
$(TARGET_EXE_DEBUG): $(COMMON_SRCS) $(EXE_SRC)
	$(CC) $(CFLAGS_DEBUG) $^ -o $@ $(LDFLAGS_EXE)
	@echo "Debug EXE build complete: $@"

# Rule to build the release DLL
$(TARGET_DLL_RELEASE): $(COMMON_SRCS) $(DLL_SRC)
	$(CC) $(CFLAGS_RELEASE) $^ -o $@ $(LDFLAGS_DLL) -s
	@echo "Release DLL build complete: $@"

# Rule to build the debug DLL
$(TARGET_DLL_DEBUG): $(COMMON_SRCS) $(DLL_SRC)
	$(CC) $(CFLAGS_DEBUG) $^ -o $@ $(LDFLAGS_DLL)
	@echo "Debug DLL build complete: $@"

# --- Cleanup Target ---
clean:
	rm -f $(TARGET_EXE_RELEASE) $(TARGET_EXE_DEBUG) $(TARGET_DLL_RELEASE) $(TARGET_DLL_DEBUG) *.o
	@echo "Cleanup complete."
