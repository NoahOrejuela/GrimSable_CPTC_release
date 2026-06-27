# GrimSable_stable_2.1

You ever have something so good you think to yourself, why don't I have more of these? This is kinda like that. Why have one LPE when you can have 3?

An LPE made out of a combination of a few modern LPEs found. Rewritten by my hosted in-house LLM instance and cleaned up and fixed up by me. For use by the Rutgers University Collegaite Penetration Testing Team.
"oops All LPEs"

# FORMAT:

### Exploit	| CVE ID	
### Description     


### PwnKit	|  CVE-2021-4034
Exploits a vulnerability in pkexec (Polkit) to gain root privileges by manipulating the GCONV_PATH environment variable and loading a malicious gconv module.

### Dirty Pipe	|  CVE-2022-0847	
Uses the Linux kernel's pipe buffer corruption to overwrite a read‑only file (e.g., /bin/su) and execute arbitrary code with root privileges.

### OverlayFS	|  CVE-2021-3493	
Abuses unprivileged user namespaces and the OverlayFS mount to gain write access to files in /etc and create a setuid shell, leveraging a kernel bug.

### Dirty COW	|  CVE-2016-5195	
Uses the race condition in the Linux kernel's copy‑on‑write (COW) handling to write to a read‑only file (e.g., /etc/passwd) and overwrite the root password entry.
