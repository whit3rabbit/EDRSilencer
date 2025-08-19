import re
import os
from typing import Optional
import sys

# --- Configuration ---
XOR_KEY = 0x42
# Default locations to try for the generated C++ source
DEFAULT_SOURCE_CANDIDATES = [
    'src/process.cpp',          # if running from repo root
    '../src/process.cpp',       # if running from utils/
]
# --- End of Configuration ---

# Simple ANSI color codes for better output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'

def resolve_source_file(explicit_path: Optional[str]) -> Optional[str]:
    """Resolve the source file path. Prefer an explicit CLI path, otherwise try defaults."""
    if explicit_path:
        return explicit_path if os.path.exists(explicit_path) else None
    for candidate in DEFAULT_SOURCE_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    return None


def verify_full_integrity(source_path: Optional[str] = None):
    """
    Performs a two-pass verification on the source file:
    1. Verifies that each `data_X` byte array correctly decrypts to its comment.
    2. Verifies that the `processData` struct correctly maps each `data_X` to its
       corresponding comment.
    """
    # Resolve the source file path
    resolved = resolve_source_file(source_path)
    if not resolved:
        print(f"{Colors.RED}Error: Could not locate src/process.cpp. Provide a path argument or run from repo root/utils.{Colors.RESET}")
        return

    print(f"{Colors.CYAN}--- Full Integrity Verification for '{resolved}' ---{Colors.RESET}")
    print(f"Using XOR key: {hex(XOR_KEY)}\n")

    with open(resolved, 'r', encoding='utf-8') as f:
        content = f.read()

    # --- PASS 1: Verify the `const unsigned char` definitions ---
    print(f"{Colors.MAGENTA}--- Pass 1: Verifying Byte Array Definitions ---{Colors.RESET}")
    
    definition_regex = re.compile(
        r"const unsigned char\s+([a-zA-Z0-9_]+)\[\]\s*=\s*\{(.*?)\};.*//\s*(.*)"
    )
    
    verified_definitions = {}
    total_definitions = 0
    error_count = 0

    for match in definition_regex.finditer(content):
        total_definitions += 1
        var_name, hex_string, expected_name = match.groups()
        expected_name = expected_name.strip()

        try:
            hex_values = re.findall(r'0x[0-9a-fA-F]+', hex_string)
            if not hex_values:
                print(f"{Colors.YELLOW}[WARNING] {var_name}: No hex values found inside braces.{Colors.RESET}")
                continue

            encrypted_bytes = bytes([int(h, 16) for h in hex_values])
            decrypted_bytes = bytes([b ^ XOR_KEY for b in encrypted_bytes])
            decrypted_string = decrypted_bytes.decode('utf-8')

            if decrypted_string == expected_name:
                print(f"{Colors.GREEN}[OK]      Definition {var_name} correctly decrypts to '{decrypted_string}'.{Colors.RESET}")
                verified_definitions[var_name] = decrypted_string
            else:
                error_count += 1
                print(f"{Colors.RED}[MISMATCH] Definition {var_name}:{Colors.RESET}")
                print(f"  - Comment says: '{expected_name}'")
                print(f"  - Decrypts to:  '{decrypted_string}'")

        except Exception as e:
            error_count += 1
            print(f"{Colors.RED}[ERROR]   Definition {var_name}: Could not process. Details: {e}{Colors.RESET}")

    print(f"\n{Colors.MAGENTA}--- Pass 2: Verifying `processData` Struct Initialization ---{Colors.RESET}")

    # --- PASS 2: Verify the `processData` struct ---
    struct_regex = re.compile(
        r"\{\s*([a-zA-Z0-9_]+),\s*sizeof\(\1\)\s*\},.*//\s*(.*)"
    )
    
    # Isolate the content within the processData struct
    # Support either `struct EncryptedString` or `EncryptedString` (C vs C++) and optional namespace wrapping
    struct_content_match = re.search(r"(?:struct\s+)?EncryptedString\s+processData\[\]\s*=\s*\{(.*?)\};", content, re.DOTALL)
    
    total_struct_entries = 0
    if struct_content_match:
        struct_block = struct_content_match.group(1)
        for line_num, line in enumerate(struct_block.splitlines(), 1):
            match = struct_regex.search(line)
            if not match:
                continue

            total_struct_entries += 1
            var_name, comment_name = match.groups()
            comment_name = comment_name.strip()

            if var_name not in verified_definitions:
                error_count += 1
                print(f"{Colors.RED}[ERROR]   Struct Entry #{total_struct_entries}: Variable '{var_name}' is used but was not defined or failed verification in Pass 1.{Colors.RESET}")
                continue
            
            actual_name = verified_definitions[var_name]
            if actual_name == comment_name:
                print(f"{Colors.GREEN}[OK]      Struct Entry #{total_struct_entries}: '{var_name}' correctly maps to '{comment_name}'.{Colors.RESET}")
            else:
                error_count += 1
                print(f"{Colors.RED}[MISMATCH] Struct Entry #{total_struct_entries} ('{var_name}'):{Colors.RESET}")
                print(f"  - Comment says: '{comment_name}'")
                print(f"  - Variable actually is: '{actual_name}'")
    else:
        print(f"{Colors.YELLOW}[WARNING] Could not find the `processData` struct block. Skipping Pass 2.{Colors.RESET}")


    # --- FINAL SUMMARY ---
    print("\n" + "="*50)
    print("Full Integrity Verification Summary")
    print("="*50)
    print(f"Byte Array Definitions Checked: {total_definitions}")
    print(f"Struct Initializers Checked:  {total_struct_entries}")

    if error_count == 0 and total_definitions > 0 and total_struct_entries > 0:
        print(f"{Colors.GREEN}\nSuccess! All definitions and struct entries are correct and consistent.{Colors.RESET}")
    else:
        print(f"{Colors.RED}\nFound {error_count} error(s) or mismatch(es). Please review the output above.{Colors.RESET}")
        if total_definitions == 0 or total_struct_entries == 0:
             print(f"{Colors.YELLOW}Warning: One or more sections were not found. Check the script's regex and file path.{Colors.RESET}")

if __name__ == "__main__":
    # Optional CLI: python verify_xor.py [path/to/src/process.cpp]
    path_arg = sys.argv[1] if len(sys.argv) > 1 else None
    verify_full_integrity(path_arg)