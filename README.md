# EDRSilencer
Inspired by the closed source FireBlock tool [FireBlock](https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/) from MdSec NightHawk, I decided to create my own version and this tool was created with the aim of blocking the outbound traffic of running EDR processes. It supports two distinct operational modes: Windows Filtering Platform (WFP) and Windows Firewall.

The tool identifies EDR processes by comparing running processes against a list of known EDR executable names. To bypass potential EDR controls that prevent opening handles to their own processes (`CreateFileW`), `EDRSilencer` uses a custom method to get the application ID required for WFP rules without needing a file handle.

**Disclaimer:** This tool is intended for authorized red team operations and security research. As I do not have access to all EDRs for testing, the included process list may not be exhaustive. Contributions and corrections are welcome.

---

## Operational Modes

EDRSilencer can operate in two modes, offering different trade-offs in terms of stealth, system integration, and forensic artifacts.

### 1. Windows Filtering Platform (WFP) Mode (Default)

-   **Mechanism:** Uses low-level WFP APIs to create kernel-mode filters that block network traffic.
-   **Pros:** Highly effective and difficult to bypass. Can be more stealthy as it doesn't create visible artifacts in the Windows Firewall GUI.
-   **Cons:** WFP activity can be monitored by sophisticated EDRs. The created provider and filters, if not named carefully, can be a forensic indicator.

### 2. Windows Firewall Mode

-   **Mechanism:** Uses the standard Windows Firewall COM API (`INetFwPolicy2`) to add rules.
-   **Pros:** Blends in with legitimate system activity, as creating firewall rules is a common administrative task. Less likely to be flagged as suspicious by EDRs.
-   **Cons:** Rules are visible in the Windows Defender Firewall GUI (though placed in a hidden group by default). May be less resilient against tampering by an EDR with sufficient privileges.

---

## Building and Customization

This project uses a flexible `Makefile` for easy compilation of both an executable and a DLL payload.

### Prerequisites (MinGW-w64 cross-compiler)

You need a Windows cross-compiler: `x86_64-w64-mingw32-gcc` (MinGW-w64) to build the EXE/DLL from macOS/Linux, and the MinGW-w64 toolchain on Windows.

- __Verify__: after installation, ensure the compiler is available:

  ```bash
  x86_64-w64-mingw32-gcc --version
  ```

- __macOS (Homebrew)__:
  ```bash
  brew install mingw-w64
  ```

- __Linux__:
  - Debian/Ubuntu:
    ```bash
    sudo apt update && sudo apt install -y mingw-w64
    ```
  - Fedora/RHEL/CentOS (with dnf):
    ```bash
    sudo dnf install -y mingw64-gcc mingw64-winpthreads
    ```
  - Arch Linux:
    ```bash
    sudo pacman -S --needed mingw-w64-gcc
    ```

- __Windows (MSYS2)__:
  1) Install MSYS2 from https://www.msys2.org/ and open the "MSYS2 MINGW64" shell.
  2) Update and install toolchain:
     ```bash
     pacman -Syu
     pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-toolchain
     ```
  3) Optionally add `C:\msys64\mingw64\bin` to your PATH to use from Cmd/PowerShell.

- __Tip__: If your compiler prefix differs, you can override the compiler when building:
  ```bash
  make CC=x86_64-w64-mingw32-gcc
  make dll CC=x86_64-w64-mingw32-gcc
  ```

### Build Instructions

The following `make` targets are available from the project root:

-   `make` or `make release`: Compiles the release version of the executable (`EDRSilencer.exe`).
-   `make dll`: Compiles the release DLL (`EDRSilencer.dll`).
-   `make debug` / `make dll-debug`: Compiles debug versions of the EXE or DLL.
-   `make clean`: Removes all compiled artifacts.

Additional convenience targets for OPSEC builds:

-   `make stealth`: Builds the release EXE with generic, stealthy names/descriptions suitable for blending into enterprise environments.
-   `make stealth-dll`: Builds the release DLL with the same stealth defines.

**To build the executable:**

```bash
make
```

**To build the DLL:**

```bash
make dll
```

### Improving Stealth (Pre-Compilation)

For better operational security, it is highly recommended to change the default provider name before compiling. A static provider name is a clear forensic indicator.

1.  Open the `utils.h` file.
2.  Locate and modify the following lines:

    ```c
    #define EDR_PROVIDER_NAME L"EDR Silencer Provider"
    #define EDR_SUBLAYER_NAME L"EDR Silencer SubLayer"
    ```
3.  Replace the default values with more generic names to blend in with legitimate system activity. Suggestions:
    *   `"Microsoft Corporation"`
    *   `"Windows Network Diagnostics"`
    *   `"System Telemetry Service"`
4.  Save the file and recompile the project.

#### WFP Provider/Sublayer Descriptions

The WFP provider and sublayer also have descriptions that are persisted on the target when created. These can now be overridden at compile time for better stealth.

1. The defaults live in `core.h` and are guarded for override:

    ```c
    #ifndef EDR_PROVIDER_DESCRIPTION
    #define EDR_PROVIDER_DESCRIPTION L"Provider for EDR Silencer to manage network filters."
    #endif

    #ifndef EDR_SUBLAYER_DESCRIPTION
    #define EDR_SUBLAYER_DESCRIPTION L"Sublayer for EDR Silencer to ensure filter precedence."
    #endif
    ```

2. Override at build time. Examples:

    - Using `make` (append to release flags):

      ```bash
      make clean && make CFLAGS_RELEASE+=' -DEDR_PROVIDER_NAME=L"Windows Diagnostics Provider" -DEDR_SUBLAYER_NAME=L"Network Telemetry SubLayer" -DEDR_PROVIDER_DESCRIPTION=L"Windows diagnostics components" -DEDR_SUBLAYER_DESCRIPTION=L"Telemetry flow arbitration" '
      ```

    - Direct `gcc` example:

      ```bash
      x86_64-w64-mingw32-gcc -O2 -D_WIN32_WINNT=0x0601 \
        -DEDR_PROVIDER_NAME=L"Windows Diagnostics Provider" \
        -DEDR_SUBLAYER_NAME=L"Network Telemetry SubLayer" \
        -DEDR_PROVIDER_DESCRIPTION=L"Windows diagnostics components" \
        -DEDR_SUBLAYER_DESCRIPTION=L"Telemetry flow arbitration" \
        ...
      ```

3. Notes:

    - These values are written into the WFP provider and sublayer objects when they are first created. If you recompile with new names, you must manually clean up the old provider and sublayer on the target system for the new names to be used.
    - Remember to use wide-string literals (prefix with `L`).

#### Overrideable Macros (Quick Reference)

The following macros can be overridden at compile time to improve stealth. Defaults are shown below and many are already guarded with `#ifndef` in the source.

```c
// utils.h (names)
#ifndef EDR_PROVIDER_NAME
#define EDR_PROVIDER_NAME L"EDR Silencer Provider"
#endif

#ifndef EDR_SUBLAYER_NAME
#define EDR_SUBLAYER_NAME L"EDR Silencer SubLayer"
#endif

#ifndef EDR_FILTER_NAME
#define EDR_FILTER_NAME L"EDRSilencer Generic Block Rule"
#endif

#ifndef FIREWALL_RULE_NAME_FORMAT
#define FIREWALL_RULE_NAME_FORMAT L"Block Rule for %s"
#endif
```

Purpose:

- `EDR_PROVIDER_NAME` / `EDR_SUBLAYER_NAME`: WFP display names for the provider and sublayer.
- `EDR_FILTER_NAME`: Display name for the WFP filters created for each process.
- `FIREWALL_RULE_NAME_FORMAT`: Format string for Windows Firewall rule display names (filename is inserted at `%s`).

You can override these with `-D<NAME>=L"..."` during compilation or use the convenience make targets below.

### Stealth Build Targets

The Makefile provides preconfigured stealth targets that set commonly useful values. Example values used:

- Provider name: `Windows Diagnostics Provider`
- Sublayer name: `Network Telemetry SubLayer`
- Provider description: `Windows diagnostics components`
- Sublayer description: `Telemetry flow arbitration`
- Firewall group: `@Windows Diagnostics` (leading `@` hides group in GUI)
- Firewall rule format: `Block Rule for %s`

Commands:

```bash
# Stealth EXE build
make clean && make stealth

# Stealth DLL build
make clean && make stealth-dll
```

#### Firewall Rule Naming

Similarly, the default firewall rule name is a static indicator. You can change the format used for all firewall rules.

1.  Open `utils.h`.
2.  Locate and modify the following line:
    ```c
    #define FIREWALL_RULE_NAME_FORMAT L"EDRSilencer Block Rule for %s"
    ```
3.  Change the format to something more generic, for example:
    *   `L"System Network Rule %s"`
    *   `L"Microsoft Defender Rule %s"`
4.  Save and recompile.

#### Firewall Rule Group (Stealth)

By default, Windows Firewall rules created by this tool are placed in the group `"@EDRSilencer Rules"`. The leading `@` hides the group from the Windows Firewall control panel UI. For stealth and attribution reduction, you can override this group name at compile time.

1. The default is defined in `firewall.h` as:

    ```c
    #ifndef FIREWALL_RULE_GROUP
    #define FIREWALL_RULE_GROUP L"@EDRSilencer Rules"
    #endif
    ```

2. Override it at build time with a more generic value. Examples:

    - Using `make` (append to release flags):

      ```bash
      make clean && make CFLAGS_RELEASE+=' -DFIREWALL_RULE_GROUP=L"@Windows Diagnostics" '
      ```

    - Direct `gcc` example:

      ```bash
      x86_64-w64-mingw32-gcc -O2 -D_WIN32_WINNT=0x0601 -DFIREWALL_RULE_GROUP=L"@System Telemetry" ...
      ```

3. Notes:

    - Keep the leading `@` to maintain hidden grouping in the GUI. Without it, the group will be visible to users.
    - Choose names that blend with the environment (e.g., `@Windows Network Diagnostics`, `@Microsoft Defender Policies`).

---

## Executable Usage

The tool can also be compiled as a standalone executable for testing or direct execution.

```
Usage: EDRSilencer.exe [--quiet | -q] [--firewall] <command>

Commands:
- `blockedr`: Add network rules to block traffic of all detected target processes.
- `add <path>`: Add a network rule to block traffic for a specific process.
  - Example: EDRSilencer.exe add "C:\Windows\System32\curl.exe"
- `remove <id_or_path>`: Remove a network rule. The required argument depends on the selected mode.
  - In **WFP mode (default)**, you must provide the numeric **Filter ID** of the rule. Use the `list` command to find the correct ID.
  - In **Firewall mode (`--firewall`)**, you must provide the exact process path.
  - WFP Example: EDRSilencer.exe remove 1234567890
  - Firewall Example: EDRSilencer.exe --firewall remove "C:\Windows\System32\curl.exe"
- `list`: List all network rules applied by this tool.

Options:
- `--firewall`: Use the Windows Firewall API instead of WFP.
- `--quiet, -q`: Suppress output messages.
- `help, -h`: Show this help message.
```

### DLL Usage

```bash
rundll32 EDRSilencer.dll,Initialize
```

### Example

![HowTo](https://github.com/netero1010/EDRSilencer/raw/main/example.png)

---

## Customizing the Target Process List

All target process names are XOR-obfuscated within the binary. You can change the XOR key or modify the list of targeted processes by following these steps.

### Key Components

-   **`gen_xor.py`**: A Python script that takes a list of plaintext process names from its `PROCESS_NAMES` array and outputs a ready-to-compile C file (`process.c`) containing the XOR-encrypted data.
-   **`process.c`**: An **auto-generated** file containing the encrypted process names. **Do not edit this file manually.**
-   **`verify_xor.py`**: A utility script to verify that the data in `process.c` can be correctly decrypted with the key.

### How to Regenerate

1.  **Modify Configuration (Optional):**
    *   To change the process list, edit the `PROCESS_NAMES` array in `gen_xor.py`.
    *   To change the XOR key, update the `XOR_KEY` variable in **both** `gen_xor.py` and `utils.c`.
2.  **Generate New C Source File:**
    ```bash
    python3 gen_xor.py > process.c
    ```
3.  **Verify Integrity (Optional but Recommended):**
    ```bash
    python3 verify_xor.py
    ```
4.  **Recompile the Project:**
    ```bash
    make clean && make
    ```

---

## Credits
- This project was inspired by the research and concepts demonstrated in the [FireBlock tool by MdSec](https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/).

---

### Full Process List

The following is a comprehensive list of all EDR-related process names targeted by this tool:

| Process Name | Process Name | Process Name |
| --- | --- | --- |
| 360ain.exe | 360dump.exe | 360insthelper.exe |
| 360LeakRepair.exe | 360leakfix.exe | 360Netman.exe |
| 360NetRepair.exe | 360rp.exe | 360safe.exe |
| 360safetray.exe | 360sd.exe | 360sdrun.exe |
| 360sdtooldata.exe | 360sdup.exe | 360sec.exe |
| 360secext.exe | 360SPTool.exe | 360taskmgr.exe |
| 360Toasts.exe | 360UDisk.exe | ZhuDongFangYu.exe |
| softup.notify.exe | SoftMgr.exe | filebeat.exe |
| winlogbeat.exe | AvastSvc.exe | AvastUI.exe |
| avgsvc.exe | avgui.exe | avgwdsvc.exe |
| vsserv.exe | bdservicehost.exe | avp.exe |
| kvrt.exe | CSFalconService.exe | CylanceSvc.exe |
| BlackBerryProtect.exe | SAVService.exe | SAVAdminService.exe |
| SophosUI.exe | SophosFS.exe | ccSvcHst.exe |
| NortonSecurity.exe | mcshield.exe | mfecanary.exe |
| mfeann.exe | mfeelam.exe | mfeens.exe |
| mfeesp.exe | mfefire.exe | mfehcs.exe |
| mfehidin.exe | mfetp.exe | ekrn.exe |
| egui.exe | mbamservice.exe | WRSA.exe |
| PSANHost.exe | fsavgui.exe | fshoster32.exe |
| PccNTMon.exe | Ntrtscan.exe | TmListen.exe |
| SentinelAgent.exe | SentinelAgentWorker.exe | SentinelBrowserNativeHost.exe |
| SentinelHelperService.exe | SentinelMemoryScanner.exe | SentinelRemediation.exe |
| SentinelRemoteShell.exe | SentinelRemoteShellHost.exe | SentinelScanFromContextMenu.exe |
| SentinelServiceHost.exe | SentinelStaticEngine.exe | SentinelStaticEnginePatcher.exe |
| SentinelStaticEngineScanner.exe | SentinelUI.exe | MsMpEng.exe |
| MpCmdRun.exe | MsSense.exe | SenseCncProxy.exe |
| SenseIR.exe | SenseNdr.exe | SenseSampleUploader.exe |
| elastic-agent.exe | elastic-endpoint.exe | endgame.exe |
| esensor.exe | hurukai.exe | hipstray.exe |
| HealthService.exe | MonitoringHost.exe | hwsd.exe |
| xagt.exe |  |  |
