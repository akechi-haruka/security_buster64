security_buster64
2022-2024 Haruka

Licensed under GPLv3.

---

WinHTTP proxy dll. Used for certain games from K***** and C*****. Redirects network to somewhere else and optionally ignores certificate errors or uses plain HTTP.

Put dll next to game .exe and a copy of security_buster.ini with desired configuration. Debug output is visible from an attached debugger.

Other games may need to have the other functions correctly redirected. JumpToASM is not 100% stable on x64.

A note on HostIsHeapAllocated:
sv6c.exe needs this on 1, Rev_v11.exe needs this on 0.
For other games, check in your disassembler if the buffer passed as pwszUrl is created by HeapAlloc, then set this to 1.
