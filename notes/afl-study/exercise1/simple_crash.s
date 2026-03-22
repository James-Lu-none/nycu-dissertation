	.file	"simple_crash.cpp"
	.intel_syntax noprefix
	.text
#APP
	.globl _ZSt21ios_base_library_initv
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"enter input string: "
#NO_APP
	.section	.text.unlikely,"ax",@progbits
.LCOLDB1:
	.section	.text.startup,"ax",@progbits
.LHOTB1:
	.p2align 4
	.globl	main
	.type	main, @function
main:
.LFB2086:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA2086
	endbr64
	push	rbx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	mov	edx, 20
	lea	rsi, .LC0[rip]
	lea	rdi, _ZSt4cout[rip]
	sub	rsp, 48
	.cfi_def_cfa_offset 64
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR 40[rsp], rax
	xor	eax, eax
	lea	rax, 16[rsp]
	mov	BYTE PTR 16[rsp], 0
	mov	QWORD PTR [rsp], rax
	mov	QWORD PTR 8[rsp], 0
.LEHB0:
	call	_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l@PLT
.LEHE0:
	mov	rdi, rsp
	call	_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_disposeEv@PLT
	mov	rax, QWORD PTR 40[rsp]
	sub	rax, QWORD PTR fs:40
	jne	.L9
	add	rsp, 48
	.cfi_remember_state
	.cfi_def_cfa_offset 16
	xor	eax, eax
	pop	rbx
	.cfi_def_cfa_offset 8
	ret
.L9:
	.cfi_restore_state
	call	__stack_chk_fail@PLT
.L5:
	endbr64
	mov	rbx, rax
	jmp	.L2
	.globl	__gxx_personality_v0
	.section	.gcc_except_table,"a",@progbits
.LLSDA2086:
	.byte	0xff
	.byte	0xff
	.byte	0x1
	.uleb128 .LLSDACSE2086-.LLSDACSB2086
.LLSDACSB2086:
	.uleb128 .LEHB0-.LFB2086
	.uleb128 .LEHE0-.LEHB0
	.uleb128 .L5-.LFB2086
	.uleb128 0
.LLSDACSE2086:
	.section	.text.startup
	.cfi_endproc
	.section	.text.unlikely
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDAC2086
	.type	main.cold, @function
main.cold:
.LFSB2086:
.L2:
	.cfi_def_cfa_offset 64
	.cfi_offset 3, -16
	mov	rdi, rsp
	call	_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_disposeEv@PLT
	mov	rax, QWORD PTR 40[rsp]
	sub	rax, QWORD PTR fs:40
	jne	.L10
	mov	rdi, rbx
.LEHB1:
	call	_Unwind_Resume@PLT
.LEHE1:
.L10:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE2086:
	.section	.gcc_except_table
.LLSDAC2086:
	.byte	0xff
	.byte	0xff
	.byte	0x1
	.uleb128 .LLSDACSEC2086-.LLSDACSBC2086
.LLSDACSBC2086:
	.uleb128 .LEHB1-.LCOLDB1
	.uleb128 .LEHE1-.LEHB1
	.uleb128 0
	.uleb128 0
.LLSDACSEC2086:
	.section	.text.unlikely
	.section	.text.startup
	.size	main, .-main
	.section	.text.unlikely
	.size	main.cold, .-main.cold
.LCOLDE1:
	.section	.text.startup
.LHOTE1:
	.hidden	DW.ref.__gxx_personality_v0
	.weak	DW.ref.__gxx_personality_v0
	.section	.data.rel.local.DW.ref.__gxx_personality_v0,"awG",@progbits,DW.ref.__gxx_personality_v0,comdat
	.align 8
	.type	DW.ref.__gxx_personality_v0, @object
	.size	DW.ref.__gxx_personality_v0, 8
DW.ref.__gxx_personality_v0:
	.quad	__gxx_personality_v0
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
