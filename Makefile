# Compiler
CC = x86_64-w64-mingw32-gcc

# --- Directory and Source File Definitions ---
# Directory for Cobalt Strike assets
CNA_DIR = cna_script/EDRSilencer

# Common source files used by both EXE and DLL
COMMON_SRCS = core.c utils.c process.c errors.c firewall.c
# Header files that should trigger a rebuild if changed
HEADERS = core.h utils.h process.h errors.h firewall.h
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
CFLAGS = -Wall -Wextra
CFLAGS_RELEASE = $(CFLAGS) -O2 -D_WIN32_WINNT=0x0601
CFLAGS_DEBUG = $(CFLAGS) -g -D_WIN32_WINNT=0x0601
# Linker flags for building an EXE
LDFLAGS_EXE = -lfwpuclnt -lole32 -loleaut32 -luuid
# Linker flags for building a DLL (note the -shared flag)
LDFLAGS_DLL = -lfwpuclnt -lole32 -loleaut32 -luuid -shared

.PHONY: all release debug dll dll-debug bof clean

# Stealth/OPSEC defines (wide-string literals). Adjust names to blend in.
STEALTH_DEFINES = \
  -DEDR_PROVIDER_NAME=L"Windows Diagnostics Provider" \
  -DEDR_SUBLAYER_NAME=L"Network Telemetry SubLayer" \
  -DEDR_PROVIDER_DESCRIPTION=L"Windows diagnostics components" \
  -DEDR_SUBLAYER_DESCRIPTION=L"Telemetry flow arbitration" \
  -DFIREWALL_RULE_GROUP=L"@Windows Diagnostics" \
  -DFIREWALL_RULE_NAME_FORMAT=L"Block Rule for %s" \
  -DEDR_FILTER_NAME=L"Generic Network Block Rule"

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

# --- Stealth Targets ---

# 'make stealth' builds the release EXE with stealthy names/descriptions
stealth:
	$(MAKE) CFLAGS_RELEASE='$(CFLAGS_RELEASE) $(STEALTH_DEFINES)' release

# 'make stealth-dll' builds the release DLL and BOF with stealth defines and copies DLL
stealth-dll:
	$(MAKE) CFLAGS_RELEASE='$(CFLAGS_RELEASE) $(STEALTH_DEFINES)' dll

# 'make bof' can be run standalone to just build the BOF loader
bof: $(BOF_LOADER_OBJ)

# --- Build Rules ---

# Rule to build the release EXE
$(TARGET_EXE_RELEASE): $(COMMON_SRCS) $(EXE_SRC) $(HEADERS)
	$(CC) $(CFLAGS_RELEASE) $(filter %.c,$^) -o $(TARGET_EXE_RELEASE) $(LDFLAGS_EXE) -s
	@echo "Release EXE build complete: $(TARGET_EXE_RELEASE)"

# Rule to build the debug EXE
$(TARGET_EXE_DEBUG): $(COMMON_SRCS) $(EXE_SRC) $(HEADERS)
	$(CC) $(CFLAGS_DEBUG) $(filter %.c,$^) -o $(TARGET_EXE_DEBUG) $(LDFLAGS_EXE)
	@echo "Debug EXE build complete: $(TARGET_EXE_DEBUG)"

# Rule to build the release DLL
$(TARGET_DLL_RELEASE): $(COMMON_SRCS) $(DLL_SRC) $(HEADERS)
	$(CC) $(CFLAGS_RELEASE) $(filter %.c,$^) -o $@ $(LDFLAGS_DLL) -s
	@echo "Release DLL build complete: $@"

# Rule to build the debug DLL
$(TARGET_DLL_DEBUG): $(COMMON_SRCS) $(DLL_SRC) $(HEADERS)
	$(CC) $(CFLAGS_DEBUG) $(filter %.c,$^) -o $@ $(LDFLAGS_DLL)
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