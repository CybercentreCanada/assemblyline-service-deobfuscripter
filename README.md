# DeobfuScripter Service

NOTE: This service does not require you to buy any licence and is preinstalled and working after a default installation.

Static script de-obfuscator. The purpose is not to get surgical de-obfuscation, but rather to extract obfuscated IOCs.

### Stage 1 Modules (in order of execution):

1. HTML script extraction

### Stage 2 Modules (in order of execution):

1. MSOffice Embedded script
2. CHR and CHRB decode
3. String replace
4. Powershell carets
5. Array of strings
6. Fake array vars
7. Reverse strings
8. B64 Decode - This module may also extract files
9. Simple XOR function
10. Charcode hex
11. Powershell vars
12. MSWord macro vars
13. Concat strings
14. Charcode