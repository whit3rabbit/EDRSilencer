import sys

# --- Configuration ---
# This must match the key in your C and verification scripts.
XOR_KEY = 0x42

# For blockedr process names to detect
PROCESS_NAMES = [
    # --- Qihoo 360 Total Security ---
    "360ain.exe",                        # Qihoo 360 Total Security
    "360dump.exe",                       # Qihoo 360 Total Security
    "360insthelper.exe",                 # Qihoo 360 Total Security
    "360LeakRepair.exe",                 # Qihoo 360 Total Security
    "360leakfix.exe",                    # Qihoo 360 Total Security
    "360Netman.exe",                     # Qihoo 360 Total Security
    "360NetRepair.exe",                  # Qihoo 360 Total Security
    "360rp.exe",                         # Qihoo 360 Total Security
    "360safe.exe",                       # Qihoo 360 Total Security
    "360safetray.exe",                   # Qihoo 360 Total Security
    "360sd.exe",                         # Qihoo 360 Total Security
    "360sdrun.exe",                      # Qihoo 360 Total Security
    "360sdtooldata.exe",                 # Qihoo 360 Total Security
    "360sdup.exe",                       # Qihoo 360 Total Security
    "360sec.exe",                        # Qihoo 360 Total Security
    "360secext.exe",                     # Qihoo 360 Total Security
    "360SPTool.exe",                     # Qihoo 360 Total Security
    "360taskmgr.exe",                    # Qihoo 360 Total Security
    "360Toasts.exe",                     # Qihoo 360 Total Security
    "360UDisk.exe",                      # Qihoo 360 Total Security
    "ZhuDongFangYu.exe",                 # Qihoo 360 Total Security
    "softup.notify.exe",                 # Qihoo 360 Updater
    "SoftMgr.exe",                       # Qihoo 360 Software Manager (corrected soft.gr.exe)

    # --- Logging / Beats ---
    "filebeat.exe",                      # Elastic Filebeat
    "winlogbeat.exe",                    # Elastic Winlogbeat

    # --- Avast / AVG ---
    "AvastSvc.exe",                      # Avast Antivirus Service
    "AvastUI.exe",                       # Avast Antivirus UI
    "avgsvc.exe",                        # AVG Service
    "avgui.exe",                         # AVG UI
    "avgwdsvc.exe",                      # AVG Watchdog Service

    # --- Bitdefender ---
    "vsserv.exe",                        # Bitdefender Virus Shield Service
    "bdservicehost.exe",                 # Bitdefender Service Host

    # --- Kaspersky ---
    "avp.exe",                           # Kaspersky AV/Endpoint
    "kvrt.exe",                          # Kaspersky Virus Removal Tool

    # --- CrowdStrike ---
    "CSFalconService.exe",               # CrowdStrike Falcon Sensor

    # --- Cylance / BlackBerry ---
    "CylanceSvc.exe",                    # Cylance Protect
    "BlackBerryProtect.exe",             # BlackBerry Protect (post-Cylance)

    # --- Sophos ---
    "SAVService.exe",                    # Sophos Endpoint AV Service
    "SAVAdminService.exe",               # Sophos Admin Service
    "SophosUI.exe",                      # Sophos Endpoint UI
    "SophosFS.exe",                      # Sophos File Scanner

    # --- Symantec / Norton ---
    "ccSvcHst.exe",                      # Symantec/Norton Service Host
    "NortonSecurity.exe",                # Norton Security UI

    # --- McAfee ---
    "mcshield.exe",                      # McAfee VirusScan Service
    "mfecanary.exe",                     # McAfee Endpoint Security
    "mfeann.exe",                        # McAfee AV Notifier
    "mfeelam.exe",                       # McAfee Endpoint Security
    "mfeens.exe",                        # McAfee Endpoint Security
    "mfeesp.exe",                        # McAfee Endpoint Security
    "mfefire.exe",                       # McAfee Firewall
    "mfehcs.exe",                        # McAfee Host Compliance
    "mfehidin.exe",                      # McAfee Core Driver
    "mfetp.exe",                         # McAfee Threat Prevention

    # --- ESET ---
    "ekrn.exe",                          # ESET Service
    "egui.exe",                          # ESET UI

    # --- Malwarebytes ---
    "mbamservice.exe",                   # Malwarebytes Service

    # --- Webroot ---
    "WRSA.exe",                          # Webroot SecureAnywhere

    # --- Panda Security ---
    "PSANHost.exe",                      # Panda Security Agent

    # --- F-Secure ---
    "fsavgui.exe",                       # F-Secure GUI
    "fshoster32.exe",                    # F-Secure Host Process

    # --- Trend Micro ---
    "PccNTMon.exe",                      # Trend Micro Apex One Monitor
    "Ntrtscan.exe",                      # Trend Micro Real-Time Scan
    "TmListen.exe",                      # Trend Micro Listener

    # --- SentinelOne ---
    "SentinelAgent.exe",                 # SentinelOne Agent
    "SentinelAgentWorker.exe",           # SentinelOne Worker
    "SentinelBrowserNativeHost.exe",     # SentinelOne Browser Host
    "SentinelHelperService.exe",         # SentinelOne Helper
    "SentinelMemoryScanner.exe",         # SentinelOne Memory Scanner
    "SentinelRemediation.exe",           # SentinelOne Remediation
    "SentinelRemoteShell.exe",           # SentinelOne Remote Shell
    "SentinelRemoteShellHost.exe",       # SentinelOne Remote Shell Host
    "SentinelScanFromContextMenu.exe",   # SentinelOne Context Scan
    "SentinelServiceHost.exe",           # SentinelOne Service Host
    "SentinelStaticEngine.exe",          # SentinelOne Static Engine
    "SentinelStaticEnginePatcher.exe",   # SentinelOne Engine Patcher
    "SentinelStaticEngineScanner.exe",   # SentinelOne Engine Scanner
    "SentinelUI.exe",                    # SentinelOne UI

    # --- Microsoft Defender / MDE ---
    "MsMpEng.exe",                       # Microsoft Defender
    "MpCmdRun.exe",                      # Microsoft Defender Command Line
    "MsSense.exe",                       # Microsoft Defender for Endpoint
    "SenseCncProxy.exe",                 # MDE Component
    "SenseIR.exe",                       # MDE Component
    "SenseNdr.exe",                      # MDE Component
    "SenseSampleUploader.exe",           # MDE Component

    # --- Elastic / Endgame ---
    "elastic-agent.exe",                 # Elastic Agent
    "elastic-endpoint.exe",              # Elastic Endpoint
    "endgame.exe",                       # Endgame EDR
    "esensor.exe",                       # Endgame Sensor

    # --- HarfangLab ---
    "hurukai.exe",                       # HarfangLab EDR (corrected from ehurukai.exe)

    # --- Huorong / Firehunter ---
    "hipstray.exe",                      # Huorong HIPS Tray (corrected from hips4ray.exe)

    # --- Misc ---
    "HealthService.exe",                 # Microsoft OpsMgr Agent
    "MonitoringHost.exe",                # Microsoft Monitoring Host
    "hwsd.exe",                          # Huawei Security Daemon
    "xagt.exe"                           # Trellix/FireEye HX Agent
]

def generate_c_code():
    """
    Encrypts the process names and prints them in a complete, ready-to-use
    C++ source file format to standard output for src/process.cpp.
    """
    c_definitions = []
    struct_entries = []

    print("// This file was auto-generated by gen_xor.py", file=sys.stderr)
    print("// To update, modify the PROCESS_NAMES list in the script and re-run.", file=sys.stderr)

    # Use a dictionary to track unique plaintext names and their corresponding variable names.
    # This handles cases where the same process name appears multiple times in the list.
    unique_names_map = {}
    
    # First pass: Generate byte array definitions only for unique names
    for i, name in enumerate(PROCESS_NAMES):
        if name.lower() not in unique_names_map:
            var_name = f"data_{len(unique_names_map)}"
            unique_names_map[name.lower()] = var_name
            
            encrypted_bytes = [ord(char) ^ XOR_KEY for char in name]
            hex_string = ", ".join([f"0x{b:02x}" for b in encrypted_bytes])
            
            c_definitions.append(f"const unsigned char {var_name}[] = {{ {hex_string} }}; // {name}")

    # Second pass: Generate the struct entries in the correct order
    for name in PROCESS_NAMES:
        var_name = unique_names_map[name.lower()]
        struct_entries.append(f"    {{ {var_name}, sizeof({var_name}) }},   // {name}")

    # --- Print the final C code to the console ---
    
    print('#include "process.hpp"')
    print('// --- Auto-generated Encrypted Process Names (C++) ---')
    print('namespace EDRSilencer {')
    print('\n'.join(c_definitions))
    print('')
    print('// The array of structs pointing to the encrypted data.')
    print('EncryptedString processData[] = {')
    print('\n'.join(struct_entries))
    print('};')
    print('')
    print('const size_t PROCESS_DATA_COUNT = sizeof(processData) / sizeof(processData[0]);')
    print('')
    print('} // namespace EDRSilencer')

if __name__ == "__main__":
    generate_c_code()