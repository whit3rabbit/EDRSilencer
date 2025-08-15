### Part 1: How the Program Works (Step-by-Step)

The program, `EDRSilencer.exe`, is a command-line utility with three main modes of operation (`blockedr`, `remove`, `removeall`), which are handled by the `main` function in `EDRSilencer.c`. It requires running with high integrity (as an Administrator) to function correctly.

#### Command: `blockedr`

This is the primary, automated function of the tool, designed for high performance and low operational footprint.

1.  **One-Time Decryption:** The tool's first action is to decrypt its entire internal list of ~160 target process names. This is done **once** at the beginning of the operation, allocating an in-memory list of plaintext names to ensure maximum performance.
2.  **Process Enumeration:** It then takes a "snapshot" of all processes currently running on the system using the `CreateToolhelp32Snapshot` API.
3.  **Iterate and Compare:** It walks through the list of running processes. For each process, it performs a fast, case-insensitive comparison of its executable name (e.g., `MsMpEng.exe`) against the decrypted in-memory list.
4.  **Find a Match:** If a running process name matches a name in the target list, the tool proceeds to the blocking phase. It keeps track of executables it has already processed to avoid creating redundant rules.
5.  **Get Full Path:** It retrieves the full file path of the detected target process (e.g., `C:\ProgramData\Microsoft\Windows Defender\Platform\...\MsMpEng.exe`).
6.  **Initiate Block:** It then calls the core blocking logic (`applyStealthFilters`) for the matched process, passing the full path to create the necessary network filters.

#### Commands: `remove` and `removeall`

These commands are for cleanup.

*   **`remove <ID>`:** This is a precise removal. It takes a specific numerical filter ID and calls the `FwpmFilterDeleteById0` API to delete that single, exact rule from the Windows Filtering Platform.
*   **`removeall`:** This is the comprehensive cleanup function. It does not iterate through individual rules. Instead, it directly deletes the custom **Sublayer** by its unique GUID. By deleting the sublayer, all associated filters created by the tool are automatically and **atomically** removed by the WFP engine. It then removes the tool's provider to erase its registration from the system.

---

### Part 2: The Core Mechanism: How It Blocks Communication

The tool offers two distinct modes to block network communication. The default mode uses the **Windows Filtering Platform (WFP)**, a low-level and powerful framework. The alternative mode uses the higher-level **Windows Firewall COM API**, which offers different trade-offs in terms of stealth and system integration.

### Mechanism A: Windows Filtering Platform (Default Mode)

The WFP mode creates a simple but effective "stealth" block that prevents all outbound connections for the target application.

Here’s the specific mechanism:

1.  **Initialize WFP Engine:** The program opens a handle to the main WFP Filter Engine.

2.  **Create Provider and Sublayer:** It first ensures its own components are registered within WFP using hardcoded, unique GUIDs:
    *   **Provider (`EDR Silencer Provider`):** A container that identifies the tool as the source of the rules.
    *   **Sublayer (`EDR Silencer SubLayer`):** A custom layer that allows the tool's rules to be grouped. This is key to the logic, as filters within a sublayer are evaluated together.
    Both the provider and sublayer are created as **persistent**, meaning they are reloaded by Windows after a reboot.

3.  **Targeting the Right Layers:** The tool targets the **`FWPM_LAYER_ALE_AUTH_CONNECT_V4`** and **`FWPM_LAYER_ALE_AUTH_CONNECT_V6`** layers. These layers are triggered whenever an application attempts to make a new outbound **IPv4** or **IPv6** connection, allowing the tool to block traffic based on the application's identity.

4.  **Get Application ID:** The tool's custom `CustomFwpmGetAppIdFromFileName0` function converts the full path of the target process (e.g., `C:\...`) into a special binary blob (an AppID) that WFP uses to uniquely identify the application. This is done without calling `CreateFileW`, bypassing potential blocks from the EDR itself.

5.  **Applying the Block Filter:** For each targeted application, the tool adds a high-priority block filter to its custom sublayer.

    *   **The Block Rule**
        *   **Action:** `FWP_ACTION_BLOCK`.
        *   **Weight:** High (15).
        *   **Condition:** A single condition: The Application ID matches the target EDR process (`FWPM_CONDITION_ALE_APP_ID`).
        *   **Result:** This rule blocks any and all outbound traffic from the EDR agent.

6.  **Evaluation Logic:** When the targeted EDR process (e.g., `MsSense.exe`) tries to send any outbound data, WFP evaluates the rules. It finds the matching high-weight block rule and **silently drops the packets**. The EDR process is never notified that its external traffic is being blocked; the connection simply fails to establish.

---

### Mechanism B: Windows Firewall (Alternative Mode)

This mode uses the standard Windows Firewall COM interfaces (`INetFwPolicy2`) to achieve the same goal. This method is less stealthy from a technical perspective but may blend in better with normal administrative activity.

1.  **Initialize COM:** The program initializes the Component Object Model (COM) library by calling `CoInitializeEx`.
2.  **Instantiate Firewall Policy:** It creates an instance of the `INetFwPolicy2` object, which is the primary interface for managing the firewall.
3.  **Create a New Rule Object:** For each target EDR process, it creates a new `INetFwRule` object.
4.  **Configure the Rule:** The rule is configured with the following properties:
    *   **Name:** A descriptive name (e.g., `Block-MsSense.exe`).
    *   **Application Name:** The full path to the EDR executable.
    *   **Action:** `NET_FW_ACTION_BLOCK`.
    *   **Direction:** `NET_FW_RULE_DIR_OUT` (outbound traffic).
    *   **Grouping:** All rules are assigned to a group named `EDR Silencer Rules` for easy identification and cleanup.
    *   **Profiles:** The rule applies to all network profiles (Domain, Private, Public).
5.  **Add the Rule:** The configured rule is added to the system's firewall policy.
6.  **Cleanup:** All COM objects are released.

When `removeall` is used in this mode, the tool enumerates all rules belonging to its group (`EDR Silencer Rules`) and removes them one by one.

---

### Part 3: Forensic Footprints: Logs and Artifacts Left Behind

A prepared defender can identify the tool's activity. The artifacts differ significantly depending on the mode used.

#### WFP Mode Artifacts

Assuming default security auditing is enabled, the WFP mode generates high-confidence evidence in the **Windows Security Event Log**.

#### High-Confidence Logs (Direct Evidence)

*   **Event ID 5156: A provider has been added to the Windows Filtering Platform.**
    *   This is logged when the tool is run for the first time. The log will show the **Provider Name**, which defaults to `EDR Silencer Provider` but can be easily changed in `utils.h` before compilation to blend in with legitimate software.
*   **Event ID 5154: A filter has been permitted to the filter engine.**
    *   This is the smoking gun. It is logged for **every single rule** added. An analyst will see a **BLOCK** filter for each protocol (IPv4 and IPv6) added for a silenced EDR process. The event details specify the Application ID being targeted, which directly identifies the silenced executable.
*   **Event ID 5152: The Windows Filtering Platform has blocked a packet.**
    *   This is the most common log generated *after* the tool has run. Every time the silenced EDR attempts to send traffic, this event will be logged. It contains the Application ID of the blocked process and the **Filter ID** of the rule that caused the block.
*   **Event ID 5161: A sublayer has been deleted from the Windows Filtering Platform.**
    *   Running `EDRSilencer.exe removeall` will generate this event. Since deleting WFP sublayers is a less common administrative action, this can be a suspicious indicator.

#### Behavioral and Indirect Artifacts

*   **Static Analysis:** The compiled executable does not import functions from the standard C Runtime Library (e.g., `printf`, `malloc`). Instead, it uses direct Win32 API calls (`WriteFile`, `HeapAlloc`), which gives it a smaller, more unusual signature compared to typical programs.
*   **Process Execution:** The execution of `EDRSilencer.exe` with its command-line arguments can be logged by security tools that are not yet silenced or by tools like Sysmon.
*   **Low CPU Profile:** Due to the optimized "decrypt-once" logic, the `blockedr` command runs very quickly and avoids causing a noticeable CPU spike, making it less likely to be flagged by performance-based monitoring tools.
*   **Loss of Agent Telemetry:** This is the most critical operational indicator for a security operations center (SOC). On their central dashboard, they will observe that one or more endpoint agents have suddenly stopped sending heartbeat signals and telemetry. This is a high-priority alert that guarantees an investigation.

#### Windows Firewall Mode Artifacts

This mode generates different, more conventional artifacts.

*   **GUI Visibility:** The rules are **directly visible** to anyone who opens the "Windows Defender Firewall with Advanced Security" management console (wf.msc). They will appear as outbound block rules under the group "EDR Silencer Rules".
*   **Event ID 4946/4947 (Security Log):** When a rule is added or modified, the system may log Event ID 4946 ("A change has been made to the Windows Firewall exception list. A rule was added.") or 4947 ("A rule was modified."). These logs are less detailed than their WFP counterparts but clearly indicate firewall manipulation.
*   **Registry Keys:** Firewall rules are stored in the registry under `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`. An analyst can find the block rules here, where the rule name and properties are stored as values.

---

### Part 4: Security Hardening and Architectural Improvements

The current version of the tool includes significant improvements over its conceptual predecessors, focusing on security, stealth, and robustness.

*   **Memory Safety:** The tool has been hardened against memory corruption vulnerabilities. The `add` command, which takes user-supplied input, uses safe Win32 API functions (`MultiByteToWideChar`) with explicit buffer size checks to prevent stack-based buffer overflows.

*   **Performance and Stealth:** The process searching logic was re-architected to be highly performant. By decrypting the target list once into memory, it avoids a computationally expensive nested loop, minimizing CPU usage and shortening its execution time to reduce the window for detection.

*   **Architectural Soundness:** The tool uses WFP best practices. Instead of adding filters to a generic provider, it creates its own persistent **sublayer**. This allows for robust management and, most importantly, enables the `removeall` command to atomically delete all of its components with a single, safe API call, preventing accidental removal of legitimate system filters.

*   **Operational Security (OPSEC) Features:**
    *   **No CRT Dependency:** The final executable is compiled without linking the C Runtime Library, reducing its static analysis footprint.
    *   **Quiet Mode:** A `--quiet` flag suppresses all non-essential output, making it suitable for execution via C2 frameworks.
    *   **Robust I/O:** The tool separates standard output from error output and uses specific exit codes to allow for reliable automation and scripting.