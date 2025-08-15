# EDRSilencer
Inspired by the closed source FireBlock tool [FireBlock](https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/) from MdSec NightHawk, I decided to create my own version and this tool was created with the aim of blocking the outbound traffic of running EDR processes using Windows Filtering Platform (WFP) APIs.

The tool identifies EDR processes by comparing running processes against a list of known EDR executable names. To bypass potential EDR controls that prevent opening handles to their own processes (`CreateFileW`), `EDRSilencer` uses a custom method to get the application ID required for WFP rules without needing a file handle.

**Disclaimer:** This tool is intended for authorized red team operations and security research. As I do not have access to all EDRs for testing, the included process list may not be exhaustive. Contributions and corrections are welcome.

---

## Building and Customization

This project uses a flexible `Makefile` for easy compilation of both an executable and a DLL payload.

### Build Instructions

The following `make` targets are available from the project root:

-   `make` or `make release`: Compiles the release version of the executable (`EDRSilencer.exe`).
-   `make dll`: **(Recommended for C2 use)** Compiles the release DLL (`EDRSilencer.dll`), builds the required BOF loader, and copies the DLL into the `cna_script/EDRSilencer/` directory, preparing the full Cobalt Strike module.
-   `make debug` / `make dll-debug`: Compiles debug versions of the EXE or DLL.
-   `make clean`: Removes all compiled artifacts.

**To build the executable:**

```bash
make
```

**To build the complete Cobalt Strike DLL package:**

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

---

## Cobalt Strike (Reflective DLL) Usage

Another use case for `EDRSilencer` is as a reflective DLL executed entirely in memory via a C2 framework. The project is pre-configured for Cobalt Strike using a Beacon Object File (BOF) loader.

### How it Works

The included Aggressor script in the `cna_script/` directory (`EDRSilencer.cna`) provides a set of user-friendly commands. When a command like `edr_block` is issued, the script sends the `EDRSilencer.dll` and a small BOF loader (`bof_loader.x64.o`) to your Beacon. The BOF then acts as a reflective loader, mapping the DLL into Beacon's memory and calling the appropriate exported function without ever writing the DLL to disk.

### Setup and Execution

1.  **Build the Module:** Run `make dll` from the project root. This will compile `EDRSilencer.dll`, `bof_loader.x64.o`, and place the DLL in the correct directory (`cna_script/EDRSilencer/`).
2.  **Load the Script:** In Cobalt Strike, go to `Scripting -> Load` and select the `cna_script/EDRSilencer.cna` file.
3.  **Execute Commands:** You can now use the following commands in any Beacon console:
    *   `edr_initialize`: Reflectively loads the DLL and calls the `Initialize()` function, which runs the main `blockedr` logic in a separate thread. This is the recommended "fire-and-forget" method.
    *   `edr_block`: Manually triggers the blocking of all known EDR processes.
    *   `edr_add C:\path\to\process.exe`: Adds a block rule for a specific process.
    *   `edr_removeall`: Removes all filtering rules created by the tool.
    *   `edr_remove_id <FilterID>`: Removes a specific rule by its ID.

### Exported Functions

For advanced use or integration with other C2 frameworks, the DLL exports the following functions:
-   `Initialize(void)`: **(Recommended)** Call this first. It runs the main EDR blocking logic in a new thread. Operates silently by default.
-   `BlockEDR(BOOL quiet)`: Manually triggers the blocking logic.
-   `AddRuleByPath(BOOL quiet, const char* processPath)`: Adds a rule for a specific process.
-   `RemoveAllRules(BOOL quiet)`: Removes all rules.
-   `RemoveRuleByID(BOOL quiet, const char* ruleIdStr)`: Removes a rule by ID.

---

## Executable Usage

The tool can also be compiled as a standalone executable for testing or direct execution.

```
Usage: EDRSilencer.exe [--quiet | -q] <command>

Commands:
- `blockedr`: Add network rules to block traffic of all detected target processes.
- `add <path>`: Add a network rule to block traffic for a specific process.
  - Example: EDRSilencer.exe add "C:\Windows\System32\curl.exe"
- `remove <id>`: Remove a network rule by its ID.
  - Example: EDRSilencer.exe remove 1234567890
- `remove --force <path>`: Force remove all WFP filters for a specific process path.
  - Example: EDRSilencer.exe remove --force "C:\Windows\System32\curl.exe"
- `removeall --force`: Force remove all WFP filters, sublayer, and provider.
- `list`: List all network rules applied by this tool.

Options:
- `--force`: Used with 'remove' or 'removeall' for aggressive cleanup.
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

### Full Process List

The following is a comprehensive list of all EDR-related process names currently targeted by this tool:

| Process Name                      | Process Name                           | Process Name              |
| --------------------------------- | -------------------------------------- | ------------------------- |
| 360LeakRepair.exe                 | SentinelStaticEnginePatcher.exe        | mc-mp-host.exe            |
| 360NetRepair.exe                  | SentinelStaticEngineScanner.exe        | mc-neo-a-host.exe         |
| ...                               | ...                                    | ...                       |
| (Full table from original README) |                                        |                           |
| ...                               | ...                                    | ...                       |
| SentinelStaticEngine.exe          | mc-inst-ui.exe                         |                           |


## Credits
-   This project was inspired by the research and concepts demonstrated in the [FireBlock tool by MdSec](https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/).
-   The reflective loader implementation is based on the original work by [Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection).

### Full Process List

The following is a comprehensive list of all EDR-related process names targeted by this tool:

| Process Name | Process Name | Process Name |
| --- | --- | --- |
| 360LeakRepair.exe | SentinelStaticEnginePatcher.exe | mc-mp-host.exe |
| 360NetRepair.exe | SentinelStaticEngineScanner.exe | mc-neo-a-host.exe |
| 360Netman.exe | SentinelUI.exe | mc-neo-host.exe |
| 360SPTool.exe | SuperKiller.exe | mc-neo-w-host.exe |
| 360Toasts.exe | Symantec Antivirus.exe | mcafee diagnose scan.exe |
| 360UDisk.exe | Symantec Endpoint Protection.exe | mcafee.exe |
| 360WD.exe | Symantec.exe | mccep.exe |
| 360WebDeff.exe | SymantecAgent.exe | mccepbrw.exe |
| 360ain.exe | SymantecUI.exe | mcinst.exe |
| 360dump.exe | WDSafeDown.exe | mclogs.exe |
| 360insthelper.exe | WscControl.exe | mcnetcfg.exe |
| 360leakfix.exe | ZhuDongFangYu.exe | mcnetman.exe |
| 360rp.exe | avast.exe | mcrepair.exe |
| 360safe.exe | avg.exe | mcsafe.exe |
| 360safetray.exe | bitdefender.exe | mcscan.exe |
| 360sd.exe | carbonblack.exe | mcsclog.exe |
| 360sdrun.exe | cb.exe | mcscreencapture.exe |
| 360sdtooldata.exe | cban.exe | mcshell.exe |
| 360sdup.exe | cbcloud.exe | mcshield.exe |
| 360sec.exe | cbcomms.exe | mcsync.exe |
| 360secext.exe | cbdaemon.exe | mctp.exe |
| 360taskmgr.exe | cbpsc.exe | mcuicnt.exe |
| 4m.exe | cbsensor.exe | mcuihost.exe |
| CbDefense-Audit.exe | cbt.exe | mcupd.exe |
| CbDefense-Recorder.exe | crowdstrike.exe | mcvs.exe |
| CbDefense-Sensor.exe | csagent.exe | mcvsscn.exe |
| CbDefense-Service.exe | csconnector.exe | mfeamcin.exe |
| CbDefense-UI.exe | csfalcon.exe | mfeann.exe |
| CbDefense.exe | csfalconservice.exe | mfeaps.exe |
| HealthService.exe | cylance.exe | mfeavsvc.exe |
| LogProcessorService.exe | eadr.exe | mfecanary.exe |
| MonitoringHost.exe | eamsi.exe | mfeelam.exe |
| MpCmdRun.exe | edpa.exe | mfeens.exe |
| MsMpEng.exe | ehurukai.exe | mfeesp.exe |
| MsSense.exe | ekrn.exe | mfefire.exe |
| QualysAgent.exe | elastic-agent.exe | mfehcs.exe |
| RepCLI.exe | elastic-endpoint.exe | mfehidin.exe |
| RepSvc.exe | endgame.exe | mfemms.exe |
| RepUtils.exe | epp.exe | mfeskin.gr.exe |
| RepUx.exe | eppconsole.exe | mfetp.exe |
| SenseCncProxy.exe | eppremediate.exe | norton.exe |
| SenseIR.exe | eppservice.exe | panda.exe |
| SenseNdr.exe | esensor.exe | repair.exe |
| SenseSampleUploader.exe | eset.exe | soft.gr.exe |
| SentinelAgent.exe | f-secure.exe | softup.notify.exe |
| SentinelAgentWorker.exe | filebeat.exe | sophos.exe |
| SentinelBrowserNativeHost.exe | hips4ray.exe | trend micro.exe |
| SentinelHelperService.exe | hipsdaemon.exe | wdp.exe |
| SentinelRemediation.exe | hwsd.exe | webroot.exe |
| SentinelRemoteShell.exe | kaspersky.exe | winlogbeat.exe |
| SentinelRemoteShellHost.exe | mc fab.exe | wsctrlsvc.exe |
| SentinelScanFromContextMenu.exe | mc feedback.exe | xagt.exe |
| SentinelServiceHost.exe | mc-fw-host.exe | zhongshenlong.exe |
| SentinelStaticEngine.exe | mc-inst-ui.exe |  |

## Credits
https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/