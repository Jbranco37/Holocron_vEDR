#ifndef STRUCT_DEFS_H_
#define STRUCT_DEFS_H_

#include <Windows.h>
#include <winternl.h>

// User-defined structs
typedef struct _MUTEXES
{
	std::mutex gScoreMutex;
	std::mutex gMemMutex;
	std::mutex gSecMutex;
} MUTEXES, * PMUTEXES;

// Define Necessary Structures so we can appropriately hook Nt Function Calls
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
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

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
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

// TODO: Define NT function prototypes for funcs we want to hook
// NtAllocateVirtualMemory
// NtProtectVirtualMemory
// NtWriteVirtualMemory
// NtCreateThreadEx
// NtCreateSection -> Testing to see if we can detect NTDLL unhooking
// NtMapViewOfSection -> So we can track what the user does with the file handle or section memory via BaseAddress
// NtCreateUserProcess -> Examine potentially malicious process creation
// NtAllocateVirualMemoryEx -> Examine if memory is being allocated within the context of the process
// 
// NtAllocateVirtualMemory
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

// NtProtectVirtualMemory
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtection,
    PULONG      OldProtection
    );

// NtWriteVirtualMemory
typedef NTSTATUS(NTAPI* pNtWriteVirtualMem)(
    HANDLE		ProcessHandle,
    PVOID		BaseAddress,
    PVOID		Buffer,
    SIZE_T		NumOfBytesToWrite,
    PSIZE_T		NumOfBytesWritten
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

// NtCreateSection
typedef NTSTATUS(NTAPI* pNtCreateSection)(
	PHANDLE				SectionHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes,
	PLARGE_INTEGER		MaximumSize,
	ULONG				SectionPageProtection,
	ULONG				AllocationAttributes,
	HANDLE				FileHandle
	);

// NtMapViewOfSection
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Protect
	);

// NtCreateUserProcess
typedef NTSTATUS(NTAPI* pNtCreateUserProcessEx)(
	PHANDLE ProcessHandle,
	ACCESS_MASK ProcessDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	HANDLE ParentProcess,
	ULONG Flags,
	HANDLE SectionHandle,
	HANDLE TokenHandle,
	ULONG JobMemberLevel
	);


// Assign function pointers
// NtAlloc
pNtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = nullptr;

// NtProtect
pNtProtectVirtualMemory OriginalNtProtectVirtualMemory = nullptr;

// NtWriteVirtualMemory
pNtWriteVirtualMem OriginalNtWriteVirtualMemory = nullptr;

// NtCreateUserProcess
pNtCreateUserProcessEx OriginalNtCreateUserProcess = nullptr;

// NtCreateThreadEx
pNtCreateThreadEx OriginalNtCreateThreadEx = nullptr;

// NtCreateSection
pNtCreateSection OriginalNtCreateSection = nullptr;


// NtMapViewOfSection
pNtMapViewOfSection OriginalNtMapViewOfSection = nullptr;

#endif

