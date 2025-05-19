; Code that will be called to invoke direct system calls after we determine SSNs

.data
; ----------------------------------
; ---------- GLOBALS ---------------

	EXTERN ntAllocSSN:DWORD
	EXTERN ntWriteSSN:DWORD
	EXTERN ntProtectSSN:DWORD
	EXTERN ntThreadSSN:DWORD


; ---------- GLOBALS ---------------
; ----------------------------------

PUBLIC NtAlloc
PUBLIC NtWrite
PUBLIC NtProtect
PUBLIC NtThread

.code
; ----------------------------------
; ---- NtAllocateVirtualMem --------

NtAlloc PROC
	mov r10, rcx
	mov eax, ntAllocSSN
	syscall
	ret
NtAlloc ENDP

; ----------------------------------
; ---- NtWriteVirtualMem -----------

NtWrite PROC
	mov r10, rcx
	mov eax, ntWriteSSN
	syscall
	ret

NtWrite ENDP
; ----------------------------------

; ----------------------------------
; ---- NtProtectVirtualMem ---------

NtProtect PROC
	mov r10, rcx
	mov eax, ntProtectSSN
	syscall
	ret

NtProtect ENDP
; ----------------------------------

; ----------------------------------
; ---- NtCreateThreadEx ------------

NtThread PROC
	mov r10, rcx
	mov eax, ntThreadSSN
	syscall
	ret

NtThread ENDP
; ----------------------------------

END
