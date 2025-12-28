# Neon Scorpion - G0999

**Created**: 2025-10-31T12:00:00.000Z

**Modified**: 2025-11-01T14:30:00.000Z

**Contributors**: 

## Aliases

Neon Scorpion

## Description

[NEON SCORPION](https://attack.mitre.org/groups/G0999) is a financially motivated threat group that emerged in late 2025. Unlike traditional ransomware groups, they specialize in "ephemeral extortion"—encrypting data in memory without ever writing to disk. [NEON SCORPION](https://attack.mitre.org/groups/G0999) is known for targeting renewable energy sectors and electric vehicle manufacturers. Their primary tool is a custom Python-based implant known as VENOM_CRIPT.

## Techniques Used


[NEON SCORPION](https://attack.mitre.org/groups/G0999) utilizes Python scripts compiled with Nuitka to execute the VENOM_CRIPT payload directly into memory.(Citation: Internal CTI Report)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1059.006|Command and Scripting Interpreter: Python|


[NEON SCORPION](https://attack.mitre.org/groups/G0999) uses base64 encoding combined with XOR ciphers to hide their C2 configuration strings within image files (Steganography).(Citation: Internal CTI Report)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027|Obfuscated Files or Information|


[NEON SCORPION](https://attack.mitre.org/groups/G0999) encrypts databases specifically looking for SQL files, appending the extension ".STING" to affected records.(Citation: Internal CTI Report)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1486|Data Encrypted for Impact|


[NEON SCORPION](https://attack.mitre.org/groups/G0999) gains initial access by sending emails claiming to be from "Green Energy Grants" containing malicious links to fake login portals.(Citation: Internal CTI Report)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1566.002|Phishing: Spearphishing Link|
