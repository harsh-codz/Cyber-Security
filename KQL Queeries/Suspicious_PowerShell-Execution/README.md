**Objective
**
Detect potentially malicious PowerShell execution commonly associated with:

Encoded commands
Download cradles
Obfuscation
Defense evasion
Living-off-the-Land techniques
MITRE ATT&CK
Technique	Description
T1059.001	PowerShell
T1027	Obfuscated Files
T1105	Ingress Tool Transfer
T1140	Deobfuscation
Detection Logic

**This query identifies PowerShell processes containing suspicious command-line arguments such as:**

Encoded commands
IEX
DownloadString
Invoke-WebRequest
Hidden windows
NoProfile execution

**Investigation Steps**
Review PowerShell command line.
Identify parent process.
Check for Base64 payloads.
Review network activity.
Validate user activity.
Determine malicious or legitimate use.
False Positives
Administrative scripts
Software deployment tools
Automation frameworks
