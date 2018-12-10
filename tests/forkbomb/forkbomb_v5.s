	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 10, 14
	.globl	_main                   ## -- Begin function main
	.p2align	4, 0x90
_main:                                  ## @main
	.cfi_startproc
## %bb.0:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset %ebp, -8
	movl	%esp, %ebp
	movl	%esp, %ebp
	.cfi_def_cfa_register %ebp
	subl	$24, %esp
	movl	$0, -4(%ebp)
	## InlineAsm Start
	nop
	## InlineAsm End
	movl	$42, -8(%ebp)
	## InlineAsm Start
	nop
	## InlineAsm End
	movl	$0, -12(%ebp)
LBB0_1:                                 ## =>This Inner Loop Header: Depth=1
	cmpl	$10, -12(%ebp)
	jge	LBB0_4
## %bb.2:                               ##   in Loop: Header=BB0_1 Depth=1
	## InlineAsm Start
	nop
	## InlineAsm End
	movl	-12(%ebp), %eax
	addl	-8(%ebp), %eax
	movl	%eax, -8(%ebp)
	## InlineAsm Start
	nop
	## InlineAsm End
## %bb.3:                               ##   in Loop: Header=BB0_1 Depth=1
	movl	-12(%ebp), %eax
	subl	$-1, %eax
	movl	%eax, -12(%ebp)
	jmp	LBB0_1
LBB0_4:
	## InlineAsm Start
	nop
	## InlineAsm End
LBB0_5:                                 ## =>This Inner Loop Header: Depth=1
	calll	_fork
	movl	%eax, -16(%ebp)         ## 4-byte Spill
	jmp	LBB0_5
	.cfi_endproc
                                        ## -- End function
	.section	__DATA,__data
	.p2align	2               ## @main.b
_main.b:
	.long	1                       ## 0x1

	.no_dead_strip	_main.b

.subsections_via_symbols
