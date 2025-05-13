// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <string>
#include <iomanip>
#include <vector>
#include <thread>
#include <mutex>
#include <cstdint>
#include <algorithm>
#include "Struct_Defs.h"
#include "PipeLogger.h"
#include "MinHook.h"
#include "ThreatCriteria.h"

// Statically link MinHook Library for MH Macros and Hooking API's
// Only focused on x64 for now
#ifdef _WIN64
#pragma comment (lib, "minhook.x64.lib")
#else error "Unspported Architecture"
#endif


// TODO: Develop a function that uses std::mutex and std::thread to update a threat score
// Threat score will follow this criteria:
// Global variable that will represent the total value
// TLS wll be used to each Detour function can calculate their own unique threat score
// The aggregate score will be used to determine if the process should be terminated
// Define global_var g_threatScore -- aggregate score
// Define global variable to represent the local threat score
UINT g_threatScore = 0;
thread_local UINT g_localThreatScore = 0; // thread dependent
thread_local PVOID* susMem = nullptr;
thread_local PHANDLE susSectionHandle = nullptr;
thread_local PHANDLE susProcHandle = nullptr;
static bool g_hooksInitialized = false;

// Flags will represent the number of suspcicious crtieria each time the function is called within the detour function
UINT updateScore(UINT uFlags) {
    // Dependent on the number of flags present - hardcoded logic for now
    // We determine how much to add to the threat score
    MUTEXES mutexes;
    g_localThreatScore += uFlags;
    // Acquire a mutex lock
    std::lock_guard<std::mutex> lock(mutexes.gScoreMutex);
    // Now we update the global threat score
    g_threatScore += g_localThreatScore;
    g_localThreatScore = 0;

    return g_threatScore;
}
// Function to find base address of NTDLL from within the local process
// This way we can use it to compare and see if the program we are monitoring
// Is attempting to access the .text section -> 0x1000 + base
PVOID FindNTBase() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PVOID pNtdllBase{ nullptr };
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pLdrListEntry = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurr = pLdrListEntry->Flink;
    while (pCurr != pLdrListEntry) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pCurr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        PWCHAR fullPath = pEntry->FullDllName.Buffer;
        PWCHAR fileName = wcsrchr(fullPath, L'\\');
        fileName = (fileName != nullptr) ? fileName + 1 : fullPath;
        if (_wcsicmp(fileName, L"ntdll.dll") == 0) {
            pNtdllBase = pEntry->DllBase;
            break;
        }
        pCurr = pCurr->Flink;
    }

    if (pNtdllBase == nullptr) {
		Logger::LogOuput("Failed to find NTDLL base address\n");
	}
    return pNtdllBase;
}
// Detour Function
NTSTATUS WINAPI HookedNtAlloc(HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) {
    if (!g_hooksInitialized) {
        return OriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }
    MUTEXES mutexes;
    // Let's hook the NtVirtualAllocate Memory Function Call, and if its RWX let's allow the call to happen, we want to do this so that
    // We can examine the true memory base address and perhaps what will be written to it later via future function calls
    if (Protect == PAGE_EXECUTE_READWRITE) {
        Logger::LogOuput("\nEDR: Memory Allocated with RWX permissions using NtAllocateVirtualMemory Call!\n");
        // Call our threat score function
        updateScore(THREATCRITERIA_MEMORY_ALLOCATED_RWX); // +1
        // Our current score value should only be one if RWX, 0 otherwise

    }
    // Thread specific and acquire a mutex lock on memory address so concurrent threads are not writing to it
    std::lock_guard<std::mutex> memLock(mutexes.gMemMutex);
    susMem = BaseAddress;
    // If the user attempts to allocate memory without RWX permissions, we "allow" the call to continue since we will hook likely later calls to update its permissions and write/execute code
    return OriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

// Detour Function - NtWrite
NTSTATUS WINAPI HookedNtWrite(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumOfBytesToWrite, PSIZE_T NumOfBytesWritten) {

    if (!g_hooksInitialized) {
		return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumOfBytesToWrite, NumOfBytesWritten);
	}
    updateScore(THREATCRITERIA_MEMORY_UPDATED_RWX);
    Logger::LogOuput("\nEDR: Attempt to write data to allocated memory using NtWriteVirtualMemory call!\n");
    // Examine bytes at Base Adress so we know what was written to it
    // Determine if NTWrite is being called on memory that was allocated with RWX permissions

    return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumOfBytesToWrite, NumOfBytesWritten);
}

// Detour Function
NTSTATUS WINAPI HookedNtProtect(HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtection,
    PULONG      OldProtection) {

    if (!g_hooksInitialized) {
        return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection); // Call original function
    }
    // Determine if memory allocated was allocated with RWX permissions
    if (NewProtection == PAGE_EXECUTE_READWRITE || NewProtection == PAGE_EXECUTE_WRITECOPY) // Working with the same memory address as the one allocated {
        Logger::LogOuput("\nEDR: Memory Permissions updated to EXECUTABLE using NtProtectVirtualMemory Call!\n");
        if (NT_SUCCESS(OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection))) {
            PVOID ntBase = FindNTBase();
            PVOID textSectionAddress = (PVOID)((uintptr_t)ntBase + 0x1000); // Compare if .text
            if (*BaseAddress == textSectionAddress) {
                // Call to update score
                if (updateScore(THREATCRITERIA_BASEADDRESS_TEXT_SECTION) >= 8) { // +5
                    Logger::LogOuput("EDR: Attempt to alter memory permissions on .text section!\n");
                    Logger::LogOuput("EDR: NTDLL Unhooking Detected. Terminating Process...\n");
                    // Terminate process
                    TerminateProcess(ProcessHandle, 1337);
                }
            }
            // Extract bytes from memory address that NtWrite wrote to
            unsigned char* byte_ptr = reinterpret_cast<unsigned char*>(*BaseAddress);
            size_t byte_count = 0;
            size_t max_bytes = 512; // safety cap
            Logger::LogOuput("EDR: Loading Bytes...\n");

            while (*byte_ptr != 0x00 && byte_count < max_bytes) {
                std::stringstream ss;
                ss << "Byte Value: 0x"
                    << std::uppercase
                    << std::setfill('0') << std::setw(2)
                    << std::hex << static_cast<int>(*byte_ptr);

                Logger::LogOuput(ss.str());  // Log one hex-formatted byte
                byte_ptr++;
                byte_count++;
            }
            // We should terminate process here so we can prevent thread from being invoked or shellcode address being called indirectly
            if (updateScore(THREATCRITERIA_MEMORY_UPDATED_RWX) >= 4) {
                Logger::LogOuput("Detected Attempt to alter memory permissions to RWX following suspicious write! Terminating Process...\n");
                TerminateProcess(ProcessHandle, 1337);
            }

        }
        return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
 }
    

// Detour Function - NtCreateSection
NTSTATUS WINAPI HookedNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES	ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    if (!g_hooksInitialized) {
        return OriginalNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle); // Call original function
    }
    // Implement logic to first determine if filehandle != NULL and SectionPageProtection == SEC_IMAGE | SEC_IMAGE_NO_EXECUTE
    Logger::LogOuput("Hooked Call to NtCreateSection\n");
    if (FileHandle != NULL || (SectionPageProtection & (SEC_IMAGE | SEC_IMAGE_NO_EXECUTE))) {
        Logger::LogOuput("Potential File Mapping Created with PE Image on Disk\n");

        Logger::LogOuput("Now examining which file was mapped...\n");
        // Call to WinAPI that will get us path from file handle
        TCHAR FilePath[MAX_PATH];
        DWORD dwReturn = 0;
        if (dwReturn = GetFinalPathNameByHandle(FileHandle, FilePath, MAX_PATH, FILE_NAME_OPENED) < MAX_PATH) {
            std::wstring wstr(FilePath);
            // logic to only acuire module name, not full path
            PWCHAR modName = wcsrchr(FilePath, L'\\');
            modName = (modName != nullptr) ? modName + 1 : FilePath;
            DWORD modNameSz = WideCharToMultiByte(CP_ACP, 0, modName, -1, NULL, 0, NULL, NULL);
            std::string pathFormatted(modNameSz, 0);
            WideCharToMultiByte(CP_ACP, 0, modName, -1, &pathFormatted[0], modNameSz, NULL, NULL);
            if (_wcsicmp(modName, L"ntdll.dll") == 0) {
                Logger::LogOuput("Attempt to create file mapping of NTDLL from disk!\n");
                // Not inherently malicious but we need to expect a call to NtMapViewOfSection -> if we are working with the .text section, yeahhh its bad
                // Save pointer to SectionHandle
                susSectionHandle = SectionHandle;
            }
        }
        else {
            Logger::LogOuput("Invalid Buffer size. Required Number of Bytes: " + dwReturn);
        }
    }
    return OriginalNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

// Detour Function - NtMapViewOfSection
NTSTATUS WINAPI HookedNtMapViewOfSection(HANDLE ProcessHandle, HANDLE SectionHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect) {
    if (!g_hooksInitialized) {
        return OriginalNtMapViewOfSection(ProcessHandle, SectionHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect); // Call original function
    }
	Logger::LogOuput("Hooked Call to NtMapViewOfSection\n");
	// Implement logic to track 2 items
    // 1: Section handle -> compare if we are still working with NTDLL
    // 2: Log BaseAddress so we can determine if it is the .text section or used as a base to calculate the text section
    if (ProcessHandle == *susSectionHandle) // in other words, if we are working with the previous PE image that was hooked in last function
    {
        updateScore(THREATCRITERIA_PE_IMAGE_MAPPED_NTDLL); // +4
        Logger::LogOuput("EDR: Detected attempt to map PE image from disk to memory!\n");
    }
	return OriginalNtMapViewOfSection(ProcessHandle, SectionHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
}

// Init Hooks
VOID InitHooks() {

    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        Logger::LogOuput("[!] Failed to initialize hooks\n");
        return;
    }
    status = MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory", &HookedNtAlloc, (LPVOID*)&OriginalNtAllocateVirtualMemory);
    if (status!= MH_OK) {
        Logger::LogOuput("[!] Failed to Create Hook for NtAllocateVirtualMemory\n");
        return;
    }

    status = MH_CreateHookApi(L"ntdll", "NtWriteVirtualMemory", &HookedNtWrite, (LPVOID*)&OriginalNtWriteVirtualMemory);
    if (status != MH_OK) {
        Logger::LogOuput("[!] Failed to Create Hook for NtAllocateVirtualMemory\n");
        return;
    }

    status = MH_CreateHookApi(L"ntdll", "NtProtectVirtualMemory", &HookedNtProtect, (LPVOID*)&OriginalNtProtectVirtualMemory);
    if (status != MH_OK) {
        Logger::LogOuput("[!] Failed to Create Hook for NtAllocateVirtualMemory\n");
        return;
    }

    status = MH_CreateHookApi(L"ntdll", "NtCreateSection", &HookedNtCreateSection, (LPVOID*)&OriginalNtCreateSection);
    if (status != MH_OK) {
        Logger::LogOuput("[!] Failed to Create Hook for NtAllocateVirtualMemory\n");
        return;
    }
    
    status = MH_CreateHookApi(L"ntdll", "NtMapViewOfSection", &HookedNtMapViewOfSection, (LPVOID*)&OriginalNtMapViewOfSection);
    if (status != MH_OK) {
        Logger::LogOuput("[!] Failed to Create Hook for NtAllocateVirtualMemory\n");
        return;
    }

    // Enable Hooks
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        Logger::LogOuput("[!] Failed to enable hooks\n");
        return;
    }
    g_hooksInitialized = true;
    Logger::LogOuput("EDR Agent: DLL Process Attached\n");
    Logger::LogOuput("\n[+] Function hooks initialized successfully!\n");
}

DWORD WINAPI EnableEDR(LPVOID lpParam) {
    //Sleep(50000); // Delay to let the host process stabilize
    Logger::LogOuput("EDR Agent: Initlaizing Hooks\n");
    InitHooks();
    return 0;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        EnableEDR(nullptr);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

