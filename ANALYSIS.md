### Part 1: How the Program Works (Step-by-Step)

The program, `EDRSilencer.exe`, is a command-line utility with three main modes of operation (`blockedr`, `remove`, `removeall`), which are handled by the `main` function in `EDRSilencer.c`. It requires running with high integrity (as an Administrator) to function correctly.

#### Command: `blockedr`

This is the primary, automated function of the tool.

1.  **Process Enumeration:** It begins by taking a "snapshot" of all processes currently running on the system using the `CreateToolhelp32Snapshot` API.
2.  **Iterate and Compare:** It walks through the list of running processes. For each process, it gets its executable name (e.g., `MsMpEng.exe`).
3.  **On-the-Fly Decryption:** It compares the running process name against its internal, hardcoded list. This list is not stored in plaintext; it is an array of XOR-encrypted byte arrays. To perform a comparison, the tool decrypts one target name at a time into memory using a simple XOR cipher.
4.  **Find a Match:** If a running process name matches a freshly decrypted target name, the tool proceeds to the blocking phase.
5.  **Get Full Path:** It retrieves the full file path of the detected target process (e.g., `C:\ProgramData\Microsoft\Windows Defender\Platform\...\MsMpEng.exe`).
6.  **Initiate Block:** It then calls the core blocking logic (`applyStealthFilters`) for the matched process, passing the full path to create the necessary network filters.

#### Commands: `remove` and `removeall`

These commands are for cleanup.

*   **`remove <ID>`:** This is a precise removal. It takes a specific numerical filter ID and calls the `FwpmFilterDeleteById0` API to delete that single, exact rule from the Windows Filtering Platform.
*   **`removeall`:** This is the comprehensive cleanup function. It does not iterate through individual rules. Instead, it directly deletes the custom **Sublayer** and **Provider** that the tool created. By deleting the sublayer, all associated filters created by the tool are automatically and atomically removed. It then removes the provider to erase the tool's registration from the system.

---

### Part 2: The Core Mechanism: How It Blocks Communication

The tool blocks network communication by leveraging the **Windows Filtering Platform (WFP)**, a powerful framework for interacting with the Windows networking stack. The mechanism creates a simple but effective "stealth" block that prevents all outbound connections for the target application.

Here’s the specific mechanism:

1.  **Initialize WFP Engine:** The program opens a handle to the main WFP Filter Engine.

2.  **Create Provider and Sublayer:** It first ensures its own components are registered within WFP:
    *   **Provider (`EDR Silencer Provider`):** A container that identifies the tool as the source of the rules.
    *   **Sublayer (`EDR Silencer SubLayer`):** A custom layer that allows the tool's rules to be grouped. This is key to the logic, as filters within a sublayer are evaluated together.
    Both the provider and sublayer are created as **persistent**, meaning they are reloaded by Windows after a reboot.

3.  **Targeting the Right Layer:** The tool targets the **`FWPM_LAYER_ALE_AUTH_CONNECT_V4`** layer. This layer is triggered whenever an application attempts to make a new outbound **IPv4** connection, allowing the tool to block traffic based on the application's identity.

4.  **Get Application ID:** The tool's custom `CustomFwpmGetAppIdFromFileName0` function converts the full path of the target process (e.g., `C:\...`) into a special binary blob (an AppID) that WFP uses to uniquely identify the application. This is done without calling `CreateFileW`, bypassing potential blocks from the EDR itself.

5.  **Applying the Block Filter:** For each targeted application, the tool adds a single, high-priority block filter to its custom sublayer for both IPv4 and IPv6 traffic.

    *   **The Block Rule**
        *   **Action:** `FWP_ACTION_BLOCK`.
        *   **Weight:** High (15).
        *   **Condition:** A single condition:
            1.  The Application ID matches the target EDR process (`FWPM_CONDITION_ALE_APP_ID`).
        *   **Result:** This rule blocks any and all outbound traffic from the EDR agent.

6.  **Evaluation Logic:** When the targeted EDR process (e.g., `MsSense.exe`) tries to send any outbound data, WFP evaluates the rules. It finds the matching high-weight block rule and **silently drops the packets**.

The EDR process is never notified that its external traffic is being blocked; the connection simply fails to establish. Because the sublayer is persistent, these rules are automatically re-enforced after a system reboot.

---

### Part 3: Forensic Footprints: Logs and Artifacts Left Behind

A prepared defender can identify the tool's activity through specific logs and behavioral changes. Assuming default security auditing is enabled, the tool generates high-confidence evidence in the **Windows Security Event Log**.

#### High-Confidence Logs (Direct Evidence)

*   **Event ID 5156: A provider has been added to the Windows Filtering Platform.**
    *   This is logged when the tool is run for the first time. The log will show the specific Provider Name: `EDR Silencer Provider`. This is a strong indicator of the tool's presence.
*   **Event ID 5154: A filter has been permitted to the filter engine.**
    *   This is the smoking gun. It is logged for **every single rule** added. An analyst will see a **BLOCK** filter for each protocol (IPv4 and IPv6) added for a silenced EDR process.
    *   The event details specify the filter conditions, including the Application ID being targeted, which directly identifies the silenced executable.
*   **Event ID 5152: The Windows Filtering Platform has blocked a packet.**
    *   This is the most common log generated *after* the tool has run. Every time the silenced EDR attempts to send traffic to its external servers, this event will be logged. It contains the Application ID of the blocked process, the destination IP/Port, and the **Filter ID** of the `Block Outbound for EDR` rule that caused the block.
*   **Event ID 5155 / 5161: A filter/sublayer has been deleted.**
    *   Running `EDRSilencer.exe remove <ID>` will generate **Event ID 5155**.
    *   Running `EDRSilencer.exe removeall` will generate **Event ID 5161** ("A sublayer has been deleted from the Windows Filtering Platform"), which is a less common and therefore more suspicious event.

#### Behavioral and Indirect Artifacts

*   **Process Execution:** The execution of `EDRSilencer.exe` with its command-line arguments (`blockedr`, etc.) can be logged by security tools that are not yet silenced or by tools like Sysmon.
*   **Process Enumeration:** The `blockedr` command's first action is to snapshot all running processes. While common, this behavior from an unknown, unsigned binary is a potential indicator for a behavioral detection engine.
*   **Loss of Agent Telemetry:** This is the most critical operational indicator for a security operations center (SOC). On their central dashboard, they will observe that one or more endpoint agents have suddenly stopped sending heartbeat signals and telemetry. This is a high-priority alert that guarantees an investigation, which would ultimately lead an analyst to discover the WFP rules on the affected machine.