	.file	"forkbomb_v5.c"
	.text
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	leal	4(%esp), %ecx
	.cfi_def_cfa 1, 0
	andl	$-16, %esp
	pushl	-4(%ecx)
	pushl	%ebp
	.cfi_escape 0x10,0x5,0x2,0x75,0
	movl	%esp, %ebp
	movl	%esp, %ebp
	pushl	%ebx
	pushl	%ecx
	.cfi_escape 0xf,0x3,0x75,0x78,0x6
	.cfi_escape 0x10,0x3,0x2,0x75,0x7c
	addl	$-16, %esp
	call	__x86.get_pc_thunk.bx
	addl	$_GLOBAL_OFFSET_TABLE_, %ebx
#APP
# 5 "forkbomb_v5.c" 1
	nop
# 0 "" 2
#NO_APP
	movl	$42, -16(%ebp)
	movl	$42, -16(%ebp)
#APP
# 7 "forkbomb_v5.c" 1
	nop
# 0 "" 2
#NO_APP
	movl	$0, -12(%ebp)
	movl	$0, -12(%ebp)
	jmp	.L2
.L3:
#APP
# 9 "forkbomb_v5.c" 1
	nop
# 0 "" 2
#NO_APP
	movl	-12(%ebp), %eax
	movl	-12(%ebp), %eax
	addl	%eax, -16(%ebp)
#APP
# 11 "forkbomb_v5.c" 1
	nop
# 0 "" 2
#NO_APP
	subl	$-1, -12(%ebp)
.L2:
	cmpl	$9, -12(%ebp)
	jle	.L3
#APP
# 13 "forkbomb_v5.c" 1
	nop
# 0 "" 2
#NO_APP
.L4:
	call	fork@PLT
	jmp	.L4
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.data
	.align 4
	.type	b.2082, @object
	.size	b.2082, 4
b.2082:
	.long	1
	.section	.text.__x86.get_pc_thunk.bx,"axG",@progbits,__x86.get_pc_thunk.bx,comdat
	.globl	__x86.get_pc_thunk.bx
	.hidden	__x86.get_pc_thunk.bx
	.type	__x86.get_pc_thunk.bx, @function
__x86.get_pc_thunk.bx:
.LFB1:
	.cfi_startproc
	movl	(%esp), %ebx
	movl	(%esp), %ebx
	ret
	.cfi_endproc
.LFE1:
	.ident	"GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0"
	.section	.note.GNU-stack,"",@progbits
