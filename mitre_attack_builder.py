import pandas as pd

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('expand_frame_repr', False)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

# search_str1 | search_str2 |search_str3 | tactics | techniques | procedures | regex_value
data = [
    # ntdll.dll often used in low-level log tampering or hooking system functions
    ["ntdll.dll", None, None, "Defense Evasion", "Indicator Removal from Tools", "Disable or modify system logs (ntdll.dll)", False],

    # kernel32.dll usage in custom loaders or obfuscation of native API calls
    ["kernel32.dll", None, None, "Defense Evasion", "Obfuscated Files or Information", "Obfuscation of code or data (kernel32.dll)", False],

    # AMSI bypass commonly occurs by patching amsi.dll in-memory
    ["amsi.dll", None, None, "Defense Evasion", "Exploitation for Privilege Escalation", "Abusing or bypassing security defenses like AMSI (amsi.dll)", False],

    # Clearing logs using native tool
    ["wevtutil", None, None, "Defense Evasion", "Indicator Removal on Host: Clear Windows Event Logs", "Clear Security log using wevtutil cl Security silently (wevtutil)", False],

    # EventLog string often used in registry or command-line log tampering
    ["EventLog", None, None, "Defense Evasion", "Indicator Removal from Tools", "Disable or modify system logs (EventLog)", False],

    # winevt folder deletion or manipulation indicates event log tampering
    ["winevt", None, None, "Defense Evasion", "Indicator Removal from Tools", "Delete or manipulate event logs (winevt)", False],

    # Modifying auditing policy to evade detection
    ["auditpol", None, None, "Defense Evasion", "Indicator Removal from Tools", "Modify or disable auditing policy (auditpol)", False],

    # General log clearing activity
    ["clear", None, None, "Defense Evasion", "Indicator Removal from Tools", "Clear event logs (clear)", False],

    # Sysmon control command (e.g., stop logging or change config)
    ["sysmon -c", None, None, "Defense Evasion", "Impair Defenses: Disable or Modify Tools", "Attackers attempt to stop, uninstall, corrupt, or disable Sysmon to blind defenders and hide malicious activity (sysmon -c)", False],

    # Sysmon accept EULA flag, could indicate reinstallation or tampering
    ["sysmon", r"-accept", None, "Defense Evasion", "Impair Defenses: Disable or Modify Tools", "Attackers attempt to stop, uninstall, corrupt, or disable Sysmon to blind defenders and hide malicious activity (sysmon -accept)", False],

    # curl is commonly abused for payload delivery or exfil
    ["curl.exe", None, None, "Command and Control / Exfiltration", "Ingress Tool Transfer", "curl.exe downloading or uploading payloads or data", False],

    # certutil used to download files or encode data
    ["certutil.exe", None, None, "Command and Control / Defense Evasion / Exfiltration", "Ingress Tool Transfer", "certutil.exe was used  to download payloads, encode, or decode files", False],

    # cmd.exe is a generic shell used to run commands or scripts
    ["cmd.exe", None, None, "Execution", "Command and Scripting Interpreter: Windows Command Shell", "cmd.exe was used  to execute commands or scripts", False],

    # PowerShell is highly flexible and used for various malicious operations
    ["powershell", None, None, "Execution / Defense Evasion / Persistence", "Command and Scripting Interpreter: PowerShell", "PowerShell was used  for execution, obfuscation, or persistence", False],

    # wscript runs VBS or JS scripts
    ["wscript.exe", None, None, "Execution / Defense Evasion", "Command and Scripting Interpreter: Visual Basic", "wscript.exe was used  to execute VBS or JS files", False],

    # cscript is CLI version of wscript
    ["cscript.exe", None, None, "Execution", "Command and Scripting Interpreter: Visual Basic", "cscript.exe was used  to execute VBS or JS files", False],

    # wscript executing JavaScript
    ["wscript.exe", r".js", None, "Execution", "Command and Scripting Interpreter: JavaScript", "wscript.exe executed JavaScript file", False],

    # wscript executing VBS
    ["wscript.exe", r".vbs", None, "Execution", "Command and Scripting Interpreter: Visual Basic", "wscript.exe executed VBS file", False],

    # wscript executing VB files
    ["wscript.exe", r".vb", None, "Execution", "Command and Scripting Interpreter: Visual Basic", "wscript.exe executed VB file", False],

    # Handle access to lsass with 0x1010 permissions may indicate credential dumping
    ["grantedAccess", "0x1010", "lsass.exe", "Credential Access", "OS Credential Dumping: LSASS Memory", "grantedAccess 0x1010 lsass.exe (handle access)", False],

    # Service creation via Windows Event ID
    [r"eventID\":\"7045", None, None, "Persistence", "Create or Modify System Process: Windows Service", "Service Creation", False],

    # sc.exe used to create persistent services
    ["sc create", None , None, "Persistence", "Create or Modify System Process: Windows Service", "Service Creation via sc.exe", False],

    # Scheduled task creation via CLI
    ["schtasks", r"/create", None, "Persistence", "Scheduled Task/Job: Scheduled Task Creation", "Scheduled Task creation", False],

    # Event ID 4698 is associated with task creation
    [r"eventID\":\"4698", r"/create", None, "Persistence", "Scheduled Task/Job: Scheduled Task Creation", "Scheduled Task event and creation", False],

    # Sysmon Image Load Event ID 7 can indicate injection or sideloading
    [r"eventID\":\"7", None, None, "Execution and Defense Evasion", "Image Load", "Malicious or unauthorized images loaded into memory", False],

    # Registry key creation
    [r"eventID\":\"12", None, None, "Defense Evasion", "Modify Registry", "Registry key creation detected", False],

    # Registry key created in \Run for persistence
    [r"eventID\":\"12", r"\run", None, "Persistence", "Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder", "Persistence created in registry Run folder", False],

    # Registry value set
    [r"eventID\":\"13", None, None, "Defense Evasion", "Modify Registry", "Registry value set detected", False],

    # File written to Startup folder
    ["Start Menu", r"Startup", None, "Persistence", "Boot or Logon Autostart Execution: Startup Folder", "File added to Startup location", False],

    # Use of ZIP archives can indicate staging or exfil
    [".zip", None, None, "Defense Evasion", "Archive Collected Data", "Zip archive file was used  for evasion or exfiltration", False],

    # ISO files used to deliver payloads (e.g. CVE-2021-40444)
    [".iso", None, None, "Defense Evasion", "Archive Collected Data", "ISO file was used  for evasion or staging", False],

    # RAR archives for staging, transfer, or hiding
    [".rar", None, None, "Defense Evasion", "Archive Collected Data", "RAR archive file was used  for evasion", False],

    # LNK files often used to deliver malware via shortcuts
    [".lnk", None, None, "Execution", "User Execution: Malicious File", "Link file was used  to execute payloads", False],

    # BAT script execution
    [".bat", None, None, "Execution", "Command and Scripting Interpreter: Windows Command Shell", "Batch file was used  for execution", False],

    # User creation via net command
    ["net.exe", r"net user", None, "Persistence", "Account Manipulation: Create Account", "New user created via net.exe", False],

    # Add user to admin group
    ["net.exe", r"localgroup", r"admin", "Persistence", "Account Manipulation: Create Account", "Add user to administrators group", False],

    # Add user to domain admins
    ["net.exe", r"domain admins", None, "Persistence", "Account Manipulation: Create Account", "Add user to domain admins", False],

    # net.exe can enumerate users, groups, shares
    ["net.exe", None, None, "Discovery", "Account Discovery", "net.exe was used  for account or group enumeration", False],

    # mshta used to execute .hta (HTML-based attack payloads)
    ["mshta.exe", r".hta", None, "Execution", "System Binary Proxy Execution: Mshta", "mshta.exe executed HTA payload", False],

    # rundll32.exe used to execute malicious DLLs
    ["rundll32.exe", None, None, "Defense Evasion", "System Binary Proxy Execution: Rundll32", "rundll32.exe was used  to execute DLLs", False],

    # rundll32 calling external DLL over HTTP
    ["rundll32.exe", r"http", None, "Defense Evasion", "System Binary Proxy Execution: Rundll32", "rundll32.exe loading external payload over HTTP", False],

    # bitsadmin used for C2 or staging downloads
    ["bitsadmin.exe", r"http", None, "Defense Evasion", "Ingress Tool Transfer", "bitsadmin.exe pulling payload from external server", False],

    # bitsadmin transferring local or remote files
    ["bitsadmin.exe", None, None, "Defense Evasion", "Ingress Tool Transfer", "bitsadmin.exe was used  for file transfer", False],

    # esentutl used to copy database files over SMB
    ["esentutl.exe", None, None, "Lateral Movement", "Transfer Data to Remote System", "esentutl.exe copying data across SMB share", False],

    # msiexec installing suspicious MSI
    ["msiexec.exe", r".msi", None, "Execution", "System Binary Proxy Execution: Msiexec", "msiexec.exe installing MSI payload", False],

    # Named pipes created by Cobalt Strike (general)
    [r"Sysmon - Pipe Created", None, None, "Command and Control", "Non-Application Layer Protocol: Named Pipes", "Cobalt Strike uses named pipes", False],

    # Specific postex_ pipe
    [r"Sysmon - Pipe Created", r"postex_", None, "Command and Control", "Non-Application Layer Protocol: Named Pipes", "Cobalt Strike post-exploitation pipe", False],

    # msagent_ named pipe
    [r"Sysmon - Pipe Created", r"msagent_", None, "Command and Control", "Non-Application Layer Protocol: Named Pipes", "Cobalt Strike msagent_ pipe", False],

    # status_ pipe
    [r"Sysmon - Pipe Created", r"status_", None, "Command and Control", "Non-Application Layer Protocol: Named Pipes", "Cobalt Strike status_ pipe", False],

    # MSSE pipe is also commonly used by Cobalt Strike
    [r"Sysmon - Pipe Created", r"MSSE", None, "Command and Control", "Non-Application Layer Protocol: Named Pipes", "Cobalt Strike MSSE pipe", False],

    # Netscan used for internal discovery
    [r"netscan.exe", None, None, "Discovery", "Network Service Discovery", "netscan.exe was used  to discover network services", False],

    # notepad.exe masquerading or injection
    [r"notepad.exe", None, None, "Defense Evasion", "Masquerading: Masquerade Task or Service", "notepad.exe was used  for process injection", False],

    # netsh used to manipulate Windows Firewall
    [r"netsh.exe", None, None, "Defense Evasion / Command and Control", "Modify System Firewall", "netsh.exe modifying firewall rules", False],

    # netsh enabling RDP port 3389
    [r"netsh.exe", r"3389", None, "Command and Control", "Remote Services: RDP", "Firewall port 3389 opened", False],

    # enabling firewall rules
    [r"netsh.exe", r"firewall", r"enable", "Command and Control", "Modify System Firewall", "Firewall rule enabled", False],

    # SessionGopher used to pull RDP, SSH, VPN credentials
    [r"Invoke-SessionGopher", None, None, "Credential Access", "Unsecured Credentials: Private Keys", "Invoke-SessionGopher PowerShell credential tool", False],

    # smbexec used for lateral movement
    [r"smbexec", None, None, "Lateral Movement", "Remote Services: SMB/Windows Admin Shares", "smbexec lateral tool was used ", False],

    # PsExec is widely used for remote execution
    [r"psexec", None, None, "Lateral Movement", "Remote Services: SMB/Windows Admin Shares", "psexec tool usage", False],

    # Quiet cmd call with flags suggests scripted remote exec
    [r"cmd.exe", r"/Q", r"/c", "Lateral Movement", "Remote Services: SMB/Windows Admin Shares", "Impacket or psexec-like tool usage", False],

    # wmic used from cmd
    [r"cmd.exe", r"wmic", None, "Lateral Movement", "Remote Services: Windows Management Instrumentation", "WMIC was used  via cmd", False],

    # Pass-the-hash authentication indicators
    [r"cmd.exe", r"--username", None, "Credential Access", "Use Alternate Authentication Material: Pass the Hash", "Pass-the-Hash attack via cmd.exe", False],

    # whoami to check context
    [r"whoami", None, None, "Discovery", "System Owner/User Discovery", "whoami command was used ", False],

    # explorer.exe injecting a DLL
    [r"explorer.exe", r".dll", None, "Defense Evasion", "Process Injection", "explorer.exe injecting DLL", False],

    # Kerberos delegation abuse
    [r"msDS-AllowedToDelegateTo", None, None, "Credential Access", "Abuse Elevation Control Mechanism: Kerberos Delegation", "Check msDS-AllowedToDelegateTo attribute", False],

    # Cobalt Strike encoded command using rundll32
    [r"rundll32.exe", r",a /p:", None, "Command and Control", "System Binary Proxy Execution: Rundll32", "Cobalt Strike encoded command using rundll32", False],

    # wmic.exe execution directly
    [r"wmic.exe", None, None, "Execution", "Windows Management Instrumentation", "wmic.exe execution", False],

    # systeminfo used for environment recon
    [r"systeminfo", None, None, "Discovery", "System Information Discovery", "systeminfo command was used ", False],

    # ping used for discovery
    [r"ping.exe", None, None, "Discovery", "Network Service Discovery", "ping.exe network check", False],

    # Excel spawning PowerShell = suspicious
    [r"excel.exe", r"powershell", None, "Execution", "Command and Scripting Interpreter: PowerShell", "Suspicious Excel child process to PowerShell", False],

    # Excel spawning cmd.exe
    [r"excel.exe", r"cmd.exe", None, "Execution", "Command and Scripting Interpreter: Windows Command Shell", "Suspicious Excel child process to cmd.exe", False],

    # Word spawning PowerShell
    [r"word.exe", r"powershell", None, "Execution", "Command and Scripting Interpreter: PowerShell", "Suspicious Word child process to PowerShell", False],

    # Word spawning cmd.exe
    [r"word.exe", r"cmd.exe", None, "Execution", "Command and Scripting Interpreter: Windows Command Shell", "Suspicious Word child process to cmd.exe", False],

    # .one file can contain embedded payloads
    [r".one", None, None, "Execution", "User Execution: Malicious File", ".one file was potentially used  for payloads", False],

    # Downloads folder inspection
    [r"Download", None, None, "Collection", "Data from Local System", "Check Downloads directory for suspicious files", False],

    # Malicious scripts with http URLs
    [r"url=http", None, None, "Command and Control", "Ingress Tool Transfer", "url=http in command or script", False],

    # Shadow copy deletion
    [r"vssadmin", None, None, "Impact", "Inhibit System Recovery", "vssadmin was used  to delete or manipulate shadow copies", False],

    # General process access activity
    [r"Process Access", None, None, "Defense Evasion", "Process Injection", "Process Access flag may indicate injection attempt", False],

    # C2 beaconing to Pastebin
    [r"pastebin", None, None, "Command and Control", "Web Service: Upload Tool", "pastebin was used to host payloads or C2 data", False],
    
    # Process Creation: krbrelay, Rubeus, Set-DomainObject
    ["krbrelay", None, None, "Privilege Escalation", "Abuse Elevation Control Mechanism: Kerberos Delegation", "Use of krbrelay tool to abuse delegation", False],
    ["rubeus", "tgtdeleg", None, "Credential Access", "Steal or Forge Kerberos Tickets", "Rubeus TGT delegation to extract TGTs", False],
    ["rubeus", None, None, "Credential Access", "Steal or Forge Kerberos Tickets", "Rubeus TGT delegation to extract TGTs", False],
    ["Set-DomainObject", "msDS-AllowedToActOnBehalfOfOtherIdentity", None, "Privilege Escalation", "Abuse Elevation Control Mechanism: Kerberos Delegation", "Modify RBCD via PowerView or Set-DomainObject", False],
    ["Add-DomainObjectAcl", None, None, "Privilege Escalation", "Abuse Elevation Control Mechanism: Access Token Manipulation", "Add ACLs to grant delegation rights", False],

    # Named Pipe Creation
    ["pipe", "krbrelay", None, "Credential Access", "OS Credential Dumping", "Named pipe used by KrbRelay for impersonation or ticket replay", False],
    ["pipe", "lsass", None, "Credential Access", "OS Credential Dumping", "LSASS pipe for relay or ticket capture", False],
    ["pipe", "ntsvcs", None, "Lateral Movement", "Remote Services", "Named pipe used for service access during relay", False],

    # Registry Modification: RBCD
    ["msDS-AllowedToActOnBehalfOfOtherIdentity", None, None, "Privilege Escalation", "Abuse Elevation Control Mechanism: Kerberos Delegation", "Registry key modification for RBCD", False],

    # Network Connections to LDAP
    ["389", "krbrelay", None, "Credential Access", "Steal or Forge Kerberos Tickets", "LDAP connection from non-standard executable or krbrelay", False],
    ["ldap", "rubeus", None, "Credential Access", "Steal or Forge Kerberos Tickets", "LDAP queries during forged ticket use or s4u abuse", False],

    # File Dropping of Tools
    ["krbrelay.exe", r"AppData\Local\Temp", None, "Execution", "User Execution: Malicious File", "Dropping KrbRelay into temp directory", False],
    ["rubeus.exe", "Downloads", None, "Execution", "User Execution: Malicious File", "Rubeus dropped by user or attacker", False],

    # Suspicious Parent-Child Processes
    ["powershell.exe", "krbrelay.exe", None, "Execution", "Command and Scripting Interpreter: PowerShell", "PowerShell spawning krbrelay", False],
    ["cmd.exe", "rubeus.exe", None, "Execution", "Command and Scripting Interpreter: Windows Command Shell", "Command line usage of Rubeus", False],

    # Credential Access - Steal or Forge Certificates
    ["certreq.exe", r"-submit", None, "Credential Access", "Steal or Forge Certificates", "Abuse of certreq.exe to submit certificate requests", False],

    # Persistence - Abuse of Enrollment Agent template
    ["certreq.exe", r"-attrib \"CertificateTemplate:EnrollmentAgent\"", None, "Persistence", "Create or Modify System Process: Windows Service", "Enrollment agent abuse with certreq.exe", False],

    # Persistence - Abusing client-side certificate enrollment
    ["certutil.exe", r"-submit", None, "Persistence", "Scheduled Task/Job: Scheduled Task Creation", "Abuse of certutil.exe to request or issue certificates", False],

    # Lateral Movement - Certutil.exe used for certificate manipulation
    ["certutil.exe", r"-dump", None, "Lateral Movement", "Transfer Data to Remote System", "certutil.exe dumping certificates for lateral movement", False],

    # Credential Access - Abusing Certificate Templates
    ["certutil.exe", r"-importPFX", None, "Credential Access", "OS Credential Dumping: Certificates", "Abuse of certutil.exe to import PFX files", False],

    # Discovery - Enumerating Certificate Templates
    ["certutil.exe", r"-template", None, "Discovery", "System Information Discovery", "certutil.exe enumerating available certificate templates", False],

    # Discovery - Certutil Access to Web Enrollment Interface
    ["http", r"/certsrv/", None, "Discovery", "Remote System Discovery", "HTTP access to certificate services for certificate enrollment", False],

    # Execution - Abusing `web enrollment` process for requests
    ["cmd.exe", r"certutil.exe", None, "Execution", "Command and Scripting Interpreter: Windows Command Shell", "Command line execution of certutil.exe for enrollment", False],

    # Persistence - Web Enrollment abuse for CA key recovery
    ["certutil.exe", r"-recover", None, "Persistence", "Create or Modify System Process: Windows Service", "Certutil recovery abuse for compromised CA keys", False],

    # Defense Evasion - Disable CA logging (via registry)
    ["reg.exe", r"EnterpriseCertificates", None, "Defense Evasion", "Modify Registry", "Modifying CA-related registry keys to evade detection", False],

    # Discovery - Examining Certificate Authorities from `certutil`
    ["certutil.exe", r"-CAinfo", None, "Discovery", "System Information Discovery", "Enumerating available Certificate Authorities", False],

    # Defense Evasion - Certificate revocation list manipulation
    ["certutil.exe", r"-CRL", None, "Defense Evasion", "Indicator Removal from Tools", "Manipulating Certificate Revocation List (CRL)", False],

    # Lateral Movement - CA signing certificates for privilege escalation
    ["certutil.exe", r"-f", None, "Lateral Movement", "Transfer Data to Remote System", "Certutil abused for forced certificate signing", False],

    # Execution - Using CertEnroll to request certificates
    ["certenroll.exe", None, None, "Execution", "Command and Scripting Interpreter: PowerShell", "PowerShell abusing certenroll.exe for certificate requests", False],

    # Persistence - Template abuse for certificate creation (CSM)
    ["certutil.exe", r"-verify", None, "Persistence", "Create or Modify System Process: Windows Service", "Certutil template abuse for creating certificates", False],

    # Lateral Movement - Man-in-the-middle attack for certificate relay
    ["openssl", r"req", None, "Lateral Movement", "Application Layer Protocol: HTTPS", "OpenSSL command for certificate relay attack", False],

    # Discovery - Querying Active Directory for certificate templates
    ["ldapsearch", r"CN=EnrollmentAgent", None, "Discovery", "System Information Discovery", "Query for Enrollment Agent templates via LDAP", False],

    # Persistence - Use of `certutil` to maintain persistence via certificates
    ["certutil.exe", r"-importPFX", None, "Persistence", "Create or Modify System Process: Windows Service", "Importing PFX certificate for persistent backdoor", False],


]

mitre_attck_df = pd.DataFrame(data, columns=["search_str1","search_str2","search_str3","tactics", "techniques", "procedures", "regex_value"])
