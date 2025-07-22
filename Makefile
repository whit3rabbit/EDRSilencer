# Compiler and Linker
CC = x86_64-w64-mingw32-gcc

# Source files
SRCS = EDRSilencer.c utils.c
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET_RELEASE = EDRSilencer.exe
TARGET_DEBUG = EDRSilencer_debug.exe

# Flags
# CFLAGS are for compiling C code
# LDFLAGS are for the linking stage
# -Wall: Enable all warnings
# -Wextra: Enable extra warnings
# -O2: Optimization level 2
# -s: Strip all symbols from the output file (crucial for release)
# -lfwpuclnt: Link against the Windows Filtering Platform library
CFLAGS_RELEASE = -Wall -Wextra -O2
LDFLAGS_RELEASE = -s -lfwpuclnt

# -g: Include debug symbols
CFLAGS_DEBUG = -Wall -Wextra -g
LDFLAGS_DEBUG = -lfwpuclnt

.PHONY: all release debug clean

all: release

# Target for building the release version
release: $(TARGET_RELEASE)

$(TARGET_RELEASE): $(SRCS)
	$(CC) $(CFLAGS_RELEASE) $^ -o $@ $(LDFLAGS_RELEASE)
	@echo "Release build complete: $(TARGET_RELEASE)"

# Target for building the debug version
debug: $(TARGET_DEBUG)

$(TARGET_DEBUG): $(SRCS)
	$(CC) $(CFLAGS_DEBUG) $^ -o $@ $(LDFLAGS_DEBUG)
	@echo "Debug build complete: $(TARGET_DEBUG)"

# Target for cleaning up build files
clean:
	rm -f $(TARGET_RELEASE) $(TARGET_DEBUG) *.o
	@echo "Cleanup complete."
