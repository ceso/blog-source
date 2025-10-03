---
title: "Signature/Heuristics"
date: 2025-10-03
draft: false
type: wiki
---

# Signature Bypass

For example, we can obfuscate the code ciphering and/or encoding (having a decipher/decoding routine in the code), as also leverage tools dedicated for this purpose.
Another thing is to use NOT common name for functions, variable names, etc; lunfardos, slang, idioisms, weird words from the dictionary, etc.

-----------------------------

# Heuristics Bypass

As for the heuristics for example AV's tend to execute the malware inside a sandbox, we could have code for detecting if running inside a sandbox and exit if this is true.
I could use the following techniques:

* Sleep command and comparision of how real time has passed (AV's could NOT wait until the sleep and just fast-forward the time)
* A counter up to 1 billon (Same story than Sleep, could not wait until it finishes and just exits)
* Call Windows API's poor or not even documented (as AV's tend to emulate API's inside the sandboxes, but some of them will not, then at the malware trying to call it and not existing, it will be detected is running inside a Sandbox)
* Verifying the name of the malware (AV's could rename the file, if it has changed it might be running inside a sandbox)
* Veifying if I can allocate TOO MUCH memory
* Checking if a known user in the system exists, if it doesn't exit

-----------------------------
