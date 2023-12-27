; Reference: https://gist.github.com/Barakat/89002a26937a2da353868fc5130812a5
;            https://forum.osdev.org/viewtopic.php?f=1&t=56978
.data
    extern origHandlers: qword
	extern hookDivideErrorImpl: qword
	hookDVStub dq offset hookDVStub_

public hookDVStub

.code
hookDVStub_ proc
	; Windows 10 19H1
	; Stack layout for #GP interrupt handler
	;   0x00     0x08      0x10        0x18     0x20 
	; |  RIP  |   CS   |  RFLAGS   |   RSP   |   SS   |
	push fs
	pushfq
	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
    ; Call our hook
	mov rcx, rsp
	sub rsp, 8 ; arg
	lea rax, hookDivideErrorImpl
	call rax
	add rsp, 8 ; arg
	cmp	 al, 0
	; Interrupt not handled
	jz oldHandler 
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
	popfq
	pop fs
	;swapgs
	iretq
oldHandler:
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
	popfq
	pop fs
    ; Jump to the real routine
    jmp origHandlers
hookDVStub_ endp

End