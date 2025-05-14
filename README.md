
> *"The Holocron holds knowledge... but it's how you use it that defines your path."*
> 
**Holocron vEDR** is a minimal, educational Endpoint Detection and Response system designed to simulate real-world detection logic—and be evaded by attackers. It selectively hooks NTDLL functions to observe how certain behaviors manifest, and is intended for red teamers, malware analysts, and curious defenders looking to study evasion and detection in practice.

---

## 🌌 Overview

Holocron vEDR is not your typical EDR. It **does not aim to detect every possible bypass technique**, but rather to be subverted. Built for training, testing, and research, it provides visibility into specific NTDLL system calls through a controlled and observable interface.

It is an ideal platform to:

- Study common EDR hooking mechanisms
- Explore syscall-level visibility
- Practice EDR evasion techniques
- Compare unhooked vs. hooked behavior

---

## 🧱 Architecture

Holocron vEDR consists of 3 primary components:

[ fHooks.dll ] —> Installs userland hooks on select NTDLL syscalls

[ fAgent.exe ] —> Inits a named pip svr to view EDR output

[ NTDLL_Walker.exe ] —> Triggers syscalls that are monitored by fHooks


The agent hooks functions such as:

- `NtAllocateVirtualMemory`
- `NtProtectVirtualMemory`
- `NtMapViewOfSection`

Additional Features Include:

- `Custom threat scoring algorithm based on constants to determine if activity is malicious`
- `Ability to print potential shellcode upon attempts to make local process memory regions RWX`
- `Ability to determine NTDLL unhooking -> Via mapping from disk ONLY!`
  
More functions will be added or swapped as needed.

---

## 🚀 Getting Started

### 1. Clone the Repository

```cmd
git clone https://github.com/{username}/holocron_vedr.git

```

### 2. Build Project in Visual Studio for x64
```Note
Requires Windows 10/11 with Windows SDK. MinHook Library and DLL already included in proj files
```
### 3. Run fAgent
```cmd
fAgent.exe
```

### 4. Execute NTDLL_Walker
```cmd
NTDLL_Walker.exe
```


**Note**
Holocron is not an all-seeing sentinel—it is vulnerable by design. It does not employ:

- Kernel drivers

- ETW consumers

- Behavioral heuristics

(Although, with more time and practice these may become features in future releases)


⚠ Disclaimer

Holocron vEDR is for educational and research purposes only.
Do not deploy on production systems.
Always comply with local laws and security policies when testing security tools.


🤝 Contributions

Want to add new syscall hooks or evasion techniques?
PRs and forks welcome!
