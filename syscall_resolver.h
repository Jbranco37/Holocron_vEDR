#ifndef SYSCALL_RESOLVER_H_
#define SYSCALL_RESOLVER_H_

#include <iostream>
#include <Windows.h>
#include <iomanip>
#include "Unmapper.h"

DWORD stubFinder(const void* ntFuncBase) {
    if (!ntFuncBase) return 0;
    DWORD ssn = 0;
    DWORD offset = 0;
    SIZE_T maxBytes = 22;
    SIZE_T bytesRead = 0;
    BYTE* stub = (BYTE*)ntFuncBase;
    // Looking at the first 20 bytes should be enough for syscall stub
    while (bytesRead < maxBytes) {
        if (*stub == 0xB8) {
            std::cout << "Found a mov eax instruction...Now locating SSN...." << std::endl;
            ssn = *(DWORD*)(stub + 1);
            std::cout << "SSN Found: 0x" << std::hex << std::setw(2) << ssn << std::endl;
            return ssn;
        }// mov eax -> just need SSN
        // But what if we are hooked? -> We should expect E9 (jmp) to a relative offset (i.e. our hooked function)
		else if (*stub == 0xE9) {
			std::cout << "Found a jmp instruction...We are likely hooked!" << std::endl;
            // Perhaps invoke call to unhook function
            std::cout << "Now attempting to unhook by remapping clean NTDLL copy..." << std::endl;
            return -1;
		}
        else if (*stub == 0x05) {
            std::cout << "Hit syscall instruction...We've gone too far!" << std::endl;
            return 0;
        }
        stub++; // increment to next byte
        bytesRead++;
    }


    return 0; // failed to find syscall number
}

#endif // !SYSCALL_RESOLVER_H_
