.code

mix64 PROC
    mov rax, rcx
    add rax, rdx
    jc carry_out
    jo signed_overflow
    xor rax, r8
    jmp mix_exit
carry_out:
    sub rax, r9
    jmp mix_exit
signed_overflow:
    or rax, r8
mix_exit:
    ret
mix64 ENDP
mix64_end PROC
    int 3
mix64_end ENDP

fold32 PROC
    xor eax, eax
    and r8d, 31
    jz fold_exit
fold_step:
    add eax, ecx
    xor eax, edx
    sub r8d, 1
    jne fold_step
fold_exit:
    ret
fold32 ENDP
fold32_end PROC
    int 3
fold32_end ENDP

classify64 PROC
    cmp rcx, rdx
    jl signed_less
    ja unsigned_above
    mov rax, -1
    ret
signed_less:
    add rcx, -2
    mov rax, rcx
    ret
unsigned_above:
    test r8, r8
    js negative_third_arg
    mov rax, r9
    ret
negative_third_arg:
    mov rax, 1122334455667788h
    ret
classify64 ENDP
classify64_end PROC
    int 3
classify64_end ENDP

check_condition MACRO jump_instruction, bit_value
    LOCAL add_bit, skip_bit
    cmp ecx, edx
    jump_instruction add_bit
    jmp skip_bit
add_bit:
    or eax, bit_value
skip_bit:
ENDM

condition_mask32 PROC
    xor eax, eax
    check_condition je, 1
    check_condition jne, 2
    check_condition ja, 4
    check_condition jae, 8
    check_condition jb, 16
    check_condition jbe, 32
    check_condition jg, 64
    check_condition jge, 128
    check_condition jl, 256
    check_condition jle, 512
    check_condition jo, 1024
    check_condition jno, 2048
    check_condition js, 4096
    check_condition jns, 8192
    ret
condition_mask32 ENDP
condition_mask32_end PROC
    int 3
condition_mask32_end ENDP

rip_relative PROC
    db 48h, 8Bh, 05h
    dd image_constant - $ - 4
    add rax, rcx
    ret
rip_relative ENDP
image_constant dq 1122334455667788h
rip_relative_end PROC
    int 3
rip_relative_end ENDP

prefixed_nop PROC
    nop word ptr [rax + rax]
    mov rax, rcx
    ret
prefixed_nop ENDP
prefixed_nop_end PROC
    int 3
prefixed_nop_end ENDP

extend_values PROC
    movzx r8d, cx
    movsx rdx, r8b
    mov eax, ecx
    cdqe
    add rax, rdx
    add rax, r8
    ret
extend_values ENDP
extend_values_end PROC
    int 3
extend_values_end ENDP

shift_values PROC
    mov rax, rcx
    shl rax, 3
    mov rdx, rcx
    shr rdx, 5
    add rax, rdx
    mov rdx, rcx
    sar rdx, 7
    add rax, rdx
    ret
shift_values ENDP
shift_values_end PROC
    int 3
shift_values_end ENDP

shift_flags PROC
    mov rax, rcx
    shl rax, 1
    jo shift_overflow
    jc shift_carry
    shr rax, 2
    jc shift_carry
    sar rax, 1
    ret
shift_overflow:
    mov rax, -1
    ret
shift_carry:
    mov rax, 55h
    ret
shift_flags ENDP
shift_flags_end PROC
    int 3
shift_flags_end ENDP

neg_not PROC
    mov rax, rcx
    neg rax
    not rdx
    add rax, rdx
    mov edx, ecx
    neg edx
    add rax, rdx
    ret
neg_not ENDP
neg_not_end PROC
    int 3
neg_not_end ENDP

sign_masks PROC
    mov rax, rcx
    cqo
    add rax, rdx
    mov eax, ecx
    cdq
    add rax, rdx
    ret
sign_masks ENDP
sign_masks_end PROC
    int 3
sign_masks_end ENDP

partial_registers PROC
    mov rax, rcx
    mov ax, dx
    mov r8b, cl
    neg r8b
    not r9w
    add rax, r8
    add rax, r9
    ret
partial_registers ENDP
partial_registers_end PROC
    int 3
partial_registers_end ENDP

partial_flags PROC
    mov eax, ecx
    xor al, al
    jz partial_zero
    add rax, rdx
    ret
partial_zero:
    mov rax, 55h
    ret
partial_flags ENDP
partial_flags_end PROC
    int 3
partial_flags_end ENDP

partial_cmp PROC
    cmp cx, dx
    jl partial_signed_less
    mov rax, rcx
    ret
partial_signed_less:
    mov rax, -1
    ret
partial_cmp ENDP
partial_cmp_end PROC
    int 3
partial_cmp_end ENDP

set_conditions PROC
    mov eax, ecx
    cmp ecx, edx
    sete al
    setne r8b
    setg r9b
    setl r10b
    setge r11b
    movzx eax, al
    movzx r8d, r8b
    shl r8d, 1
    or eax, r8d
    movzx r9d, r9b
    shl r9d, 2
    or eax, r9d
    movzx r10d, r10b
    shl r10d, 3
    or eax, r10d
    movzx r11d, r11b
    shl r11d, 4
    or eax, r11d
    ret
set_conditions ENDP
set_conditions_end PROC
    int 3
set_conditions_end ENDP

bit_tests PROC
    mov eax, ecx
    bt eax, 24
    setb r8b
    shr cl, 1
    movzx ecx, cl
    movzx r8d, r8b
    shl r8d, 8
    or eax, r8d
    ret
bit_tests ENDP
bit_tests_end PROC
    int 3
bit_tests_end ENDP

imul_flags PROC
    imul rcx, rdx
    mov rax, rcx
    jo imul_signed_overflow
    ret
imul_signed_overflow:
    mov rax, -1
    ret
imul_flags ENDP
imul_flags_end PROC
    int 3
imul_flags_end ENDP

conditional_move PROC
    test rdx, rdx
    mov rax, rcx
    cmovnz rax, r8
    ret
conditional_move ENDP
conditional_move_end PROC
    int 3
conditional_move_end ENDP

memory_read PROC
    mov rax, [rcx]
    ret
memory_read ENDP
memory_read_end PROC
    int 3
memory_read_end ENDP

memory_write PROC
    mov [rcx], rdx
    mov rax, [rcx]
    ret
memory_write ENDP
memory_write_end PROC
    int 3
memory_write_end ENDP

stack_roundtrip PROC
    push rbp
    mov rbp, rcx
    mov [rbp], rdx
    mov rax, [rbp]
    pop rbp
    ret
stack_roundtrip ENDP
stack_roundtrip_end PROC
    int 3
stack_roundtrip_end ENDP

stack_argument PROC
    mov rax, [rsp + 28h]
    add rax, rcx
    ret
stack_argument ENDP
stack_argument_end PROC
    int 3
stack_argument_end ENDP

xmm_roundtrip PROC
    movups [rsp + 8], xmm6
    movups xmm6, [rcx]
    movaps xmm7, xmm6
    xorps xmm6, xmm6
    movups [rdx], xmm7
    movups [r8], xmm6
    movups xmm6, [rsp + 8]
    mov rax, [rdx]
    ret
xmm_roundtrip ENDP
xmm_roundtrip_end PROC
    int 3
xmm_roundtrip_end ENDP

scalar_moves PROC
    movdqu [rsp + 8], xmm6
    movss xmm6, dword ptr [rcx]
    movdqa xmm7, xmm6
    movss dword ptr [rdx], xmm6
    movsd xmm6, qword ptr [rcx + 8]
    movsd qword ptr [r8], xmm6
    movdqu xmm6, [rsp + 8]
    mov rax, [r8]
    ret
scalar_moves ENDP
scalar_moves_end PROC
    int 3
scalar_moves_end ENDP

narrow_memory PROC
    movzx eax, byte ptr [rcx]
    movzx edx, word ptr [rcx + 2]
    add rax, rdx
    mov byte ptr [r8], al
    mov word ptr [r8 + 2], ax
    movzx eax, word ptr [r8]
    ret
narrow_memory ENDP
narrow_memory_end PROC
    int 3
narrow_memory_end ENDP

compare_float PROC
    movss xmm5, dword ptr [rcx]
    comiss xmm5, dword ptr [rcx + 4]
    jp compare_unordered
    je compare_equal
    jb compare_below
    mov eax, 2
    ret
compare_equal:
    xor eax, eax
    ret
compare_below:
    mov eax, 1
    ret
compare_unordered:
    mov eax, 4
    ret
compare_float ENDP
compare_float_end PROC
    int 3
compare_float_end ENDP

float_startup PROC
    movups [rsp + 8], xmm6
    movsd xmm6, qword ptr [rcx]
    cvtsd2ss xmm6, xmm6
    mulss xmm6, dword ptr [rcx + 16]
    cvttss2si eax, xmm6
    mov [rdx], eax
    cvtsi2ss xmm6, dword ptr [rcx + 24]
    addss xmm6, dword ptr [rcx + 16]
    movss dword ptr [r8], xmm6
    movups xmm6, [rsp + 8]
    ret
float_startup ENDP
float_startup_end PROC
    int 3
float_startup_end ENDP

vector_general PROC
    movd xmm5, ecx
    movd dword ptr [rdx], xmm5
    movq xmm5, r8
    movq qword ptr [r9], xmm5
    movd eax, xmm5
    ret
vector_general ENDP
vector_general_end PROC
    int 3
vector_general_end ENDP

vector_float PROC
    movups xmm5, [rcx]
    mulps xmm5, [rdx]
    addps xmm5, [rcx]
    subps xmm5, [rdx]
    andps xmm5, [rcx]
    movups [r8], xmm5
    mov rax, [r8]
    ret
vector_float ENDP
vector_float_end PROC
    int 3
vector_float_end ENDP

vector_int PROC
    movups xmm5, [rcx]
    cvtdq2ps xmm5, xmm5
    movups [rdx], xmm5
    mov rax, [rdx]
    ret
vector_int ENDP
vector_int_end PROC
    int 3
vector_int_end ENDP

direct_call PROC
    sub rsp, 20h
    call mix64
    add rsp, 20h
    ret
direct_call ENDP
direct_call_end PROC
    int 3
direct_call_end ENDP

direct_stack_call PROC
    sub rsp, 28h
    mov [rsp + 20h], r8
    call stack_argument
    add rsp, 28h
    ret
direct_stack_call ENDP
direct_stack_call_end PROC
    int 3
direct_stack_call_end ENDP

indirect_call PROC
    sub rsp, 20h
    db 0ffh, 015h
    dd indirect_target - $ - 4
    add rsp, 20h
    ret
indirect_call ENDP
indirect_call_end PROC
    int 3
indirect_call_end ENDP

indirect_register_call PROC
    sub rsp, 20h
    db 48h, 8Bh, 05h
    dd indirect_register_target - $ - 4
    call rax
    add rsp, 20h
    ret
indirect_register_call ENDP
indirect_register_call_end PROC
    int 3
indirect_register_call_end ENDP

tail_call PROC
    jmp mix64
tail_call ENDP
tail_call_end PROC
    int 3
tail_call_end ENDP

indirect_tail PROC
    db 0ffh, 025h
    dd tail_target - $ - 4
indirect_tail ENDP
indirect_tail_end PROC
    int 3
indirect_tail_end ENDP

register_tail PROC
    db 48h, 8Bh, 05h
    dd register_tail_target - $ - 4
    jmp rax
register_tail ENDP
register_tail_end PROC
    int 3
register_tail_end ENDP

unsupported_indirect_call PROC
    call rax
    ret
unsupported_indirect_call ENDP
unsupported_indirect_call_end PROC
    int 3
unsupported_indirect_call_end ENDP

undefined_path PROC
    test rcx, rcx
    jz join_point
    mov r10, rdx
join_point:
    mov rax, r10
    ret
undefined_path ENDP
undefined_path_end PROC
    int 3
undefined_path_end ENDP

branch_outside PROC
    jmp short branch_outside_end
branch_outside ENDP
branch_outside_end PROC
    int 3
branch_outside_end ENDP

relocated_constant PROC
    mov rax, OFFSET mix64
    ret
relocated_constant ENDP
relocated_constant_end PROC
    int 3
relocated_constant_end ENDP

.code
indirect_target dq mix64
indirect_register_target dq mix64
tail_target dq mix64
register_tail_target dq mix64

END
