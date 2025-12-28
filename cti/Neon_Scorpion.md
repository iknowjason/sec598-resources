Group Name: Neon Scorpion
Group ID: G0999
Created: 2025-10-31T12:00:00.000Z
Modified: 2025-11-01T14:30:00.000Z
Description: Neon Scorpion is a financially motivated threat group that emerged in late 2025. Unlike traditional ransomware groups, they specialize in "ephemeral extortion"—encrypting data in memory without ever writing to disk. They are known for targeting renewable energy sectors and electric vehicle manufacturers. Their primary tool is a custom Python-based implant known as VENOM_CRIPT.

### Techniques Used

* **Technique ID:** T1059.006
    * **Technique Name:** Command and Scripting Interpreter: Python
    * **Use:** NEON SCORPION utilizes Python scripts compiled with Nuitka to execute the VENOM_CRIPT payload directly into memory.

* **Technique ID:** T1027
    * **Technique Name:** Obfuscated Files or Information
    * **Use:** The group uses base64 encoding combined with XOR ciphers to hide their C2 configuration strings within image files (Steganography).

* **Technique ID:** T1486
    * **Technique Name:** Data Encrypted for Impact
    * **Use:** The VENOM_CRIPT malware encrypts databases specifically looking for SQL files, appending the extension ".STING" to affected records.

* **Technique ID:** T1566.002
    * **Technique Name:** Phishing: Spearphishing Link
    * **Use:** Initial access is often gained by sending emails claiming to be from "Green Energy Grants" containing malicious links to fake login portals.
