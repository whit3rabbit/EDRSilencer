# Compiler
CC = x86_64-w64-mingw32-gcc

# --- Directory and Source File Definitions ---
# Directory for Cobalt Strike assets
CNA_DIR = cna_script/EDRSilencer

# Common source files used by both EXE and DLL
COMMON_SRCS = core.c utils.c process.c
# Entry-point source for the Executable
EXE_SRC = main.c
# Entry-point source for the DLL
DLL_SRC = dllmain.c
# Source files for the BOF Loader
BOF_LOADER_SRC = $(CNA_DIR)/bof_loader.c
REFLECTIVE_LOADER_SRCS = $(CNA_DIR)/ReflectiveLoader.c

# --- Target Filename Definitions ---
TARGET_EXE_RELEASE = EDRSilencer.exe
TARGET_EXE_DEBUG = EDRSilencer_debug.exe
TARGET_DLL_RELEASE = EDRSilencer.dll
TARGET_DLL_DEBUG = EDRSilencer_debug.dll
# BOF object file will be placed directly in the CNA directory
BOF_LOADER_OBJ = $(CNA_DIR)/bof_loader.x64.o

# --- Flag Definitions ---
# Common flags for C compilation
CFLAGS_RELEASE = -Wall -Wextra -O2
CFLAGS_DEBUG = -Wall -Wextra -g
# Linker flags for building an EXE
LDFLAGS_EXE = -lfwpuclnt
# Linker flags for building a DLL (note the -shared flag)
LDFLAGS_DLL = -lfwpuclnt -shared

.PHONY: all release debug dll dll-debug bof clean

# --- Main Targets ---

# Default target: 'make' or 'make all' will build the release EXE
all: release

# 'make release' builds the release EXE
release: $(TARGET_EXE_RELEASE)

# 'make debug' builds the debug EXE
debug: $(TARGET_EXE_DEBUG)

# 'make dll' is now the primary target for building the full CS package
# It builds the DLL, builds the BOF, and copies the DLL to the CNA directory
dll: $(TARGET_DLL_RELEASE) bof
	@echo "Copying DLL to CNA script directory..."
	cp $(TARGET_DLL_RELEASE) $(CNA_DIR)/

# 'make dll-debug' does the same for the debug version
dll-debug: $(TARGET_DLL_DEBUG) bof
	@echo "Copying debug DLL to CNA script directory..."
	cp $(TARGET_DLL_DEBUG) $(CNA_DIR)/

# 'make bof' can be run standalone to just build the BOF loader
bof: $(BOF_LOADER_OBJ)

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

# Rule to build the BOF object file
$(BOF_LOADER_OBJ): $(BOF_LOADER_SRC) $(REFLECTIVE_LOADER_SRCS)
	$(CC) $(CFLAGS_RELEASE) -r $^ -o $@
	@echo "BOF loader build complete: $@"


# --- Cleanup Target ---
# Updated to also remove the compiled BOF and the copied DLL
clean:
	rm -f $(TARGET_EXE_RELEASE) $(TARGET_EXE_DEBUG) $(TARGET_DLL_RELEASE) $(TARGET_DLL_DEBUG) *.o $(BOF_LOADER_OBJ) $(CNA_DIR)/$(TARGET_DLL_RELEASE) $(CNA_DIR)/$(TARGET_DLL_DEBUG)
	@echo "Cleanup complete."