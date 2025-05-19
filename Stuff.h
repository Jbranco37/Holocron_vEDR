#ifndef STUFF_H_
#define STUFF_H_

#include <Windows.h>

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

extern "C" NTSTATUS NtAlloc(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

extern "C" NTSTATUS NtWrite(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumOfBytesToWrite,
	PSIZE_T NumOfBytesWritten
);

extern "C" NTSTATUS NtProtect(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtection,
	PULONG OldProtection
);

extern "C" NTSTATUS NtThread(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList
);
#endif