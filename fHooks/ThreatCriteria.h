#ifndef THREATCRITIERA_H_
#define THREATCRITIERA_H_

// Criteria for Threat Score
// 1. Memory Allocated with RWX permissions Immediately: +1
// 2. Memory Updated with RWX permissions using NtProtect after NtWrite: +4
// 3. PE Image Mapped from Disk: +2 || +3 if NTDLL.dll
// 4. If BaseAddress of PE Image signifies .text section at offset 0x1000: +5
// 
typedef enum THREATCRITERIA {
	THREATCRITERIA_MEMORY_ALLOCATED_RWX = 1,
	THREATCRITERIA_MEMORY_UPDATED_RWX = 2,
	THREATCRITERIA_PE_IMAGE_MAPPED_DISK = 3,
	THREATCRITERIA_PE_IMAGE_MAPPED_NTDLL = 4,
	THREATCRITERIA_BASEADDRESS_TEXT_SECTION = 5,
	THREATCRITERIA_MEMORY_ALLOCATED_RWX_NTWRITE = 6,
	THREATCRITERIA_CREATETHREAD_CALLED_ON_RWX_MEM = 7,

} THREATCRITERIA, *PTHREATCRITERIA;

#endif
