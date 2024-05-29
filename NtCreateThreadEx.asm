.code
	NtCreateThreadEx PROC
		mov r10, rcx
		mov eax, 00bdh
		syscall
		ret
	NtCreateThreadEx ENDP
end