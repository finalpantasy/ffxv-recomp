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
    db 0F3h, 0C3h
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
    db 67h
    lea r9d, [rcx + rdx]
    add rax, r9
    db 64h
    push rax
    pop r10
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
    mov r10, rcx
    mov rcx, rdx
    shl r10b, cl
    shr r10w, cl
    sar r10b, cl
    add rax, r10
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

rotate_flags PROC
    mov rax, rcx
    rol rax, 1
    jo rotate_overflow
    jc rotate_carry
    ror rax, 1
    jo rotate_overflow
    jc rotate_carry
    rol rax, 4
    ret
rotate_overflow:
    mov rax, -1
    ret
rotate_carry:
    mov rax, 55h
    ret
rotate_flags ENDP
rotate_flags_end PROC
    int 3
rotate_flags_end ENDP

rotate_flag_preservation PROC
    mov eax, 1
    test eax, eax
    ror eax, 1
    sets r8b
    movzx r8d, r8b
    mov eax, 1
    test eax, eax
    mov eax, 0
    ror eax, 1
    setz r9b
    movzx r9d, r9b
    shl r9d, 1
    or r8d, r9d
    mov eax, 1
    test eax, eax
    rol eax, 31
    sets r9b
    movzx r9d, r9b
    shl r9d, 2
    or r8d, r9d
    mov eax, 1
    test eax, eax
    mov eax, 0
    rol eax, 1
    setz r9b
    movzx r9d, r9b
    shl r9d, 3
    or r8d, r9d
    mov eax, r8d
    ret
rotate_flag_preservation ENDP
rotate_flag_preservation_end PROC
    int 3
rotate_flag_preservation_end ENDP

neg_not PROC
    mov rax, rcx
    neg rax
    pushfq
    pop r8
    and r8d, 10h
    not rdx
    add rax, rdx
    mov edx, ecx
    neg edx
    pushfq
    pop r9
    and r9d, 10h
    add rax, rdx
    add rax, r8
    add rax, r9
    inc eax
    pushfq
    pop r10
    and r10d, 10h
    dec eax
    pushfq
    pop r11
    and r11d, 10h
    add rax, r10
    add rax, r11
    ret
neg_not ENDP
neg_not_end PROC
    int 3
neg_not_end ENDP

xchg_andnot PROC
    mov rax, rcx
    xchg rax, rdx
    add rax, rdx
    ret
xchg_andnot ENDP
xchg_andnot_end PROC
    int 3
xchg_andnot_end ENDP

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

sign_extend16 PROC
    mov eax, ecx
    cwde
    ret
sign_extend16 ENDP
sign_extend16_end PROC
    int 3
sign_extend16_end ENDP

partial_registers PROC
    mov rax, rcx
    mov ax, dx
    mov r8b, cl
    neg r8b
    not r9w
    add rax, r8
    add rax, r9
    mov r10, rcx
    mov ah, dl
    mov ecx, r8d
    mov edx, r9d
    mov ch, cl
    mov dh, dl
    add rax, r10
    mov al, ah
    movzx r10d, al
    add rax, r10
    mov al, ch
    movzx r10d, al
    add rax, r10
    mov al, dh
    movzx r10d, al
    add rax, r10
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

dynamic_bits PROC
    mov eax, ecx
    bt eax, edx
    setb r8b
    btr eax, edx
    bts eax, edx
    btc eax, edx
    bt eax, edx
    setb r9b
    movzx r8d, r8b
    movzx r9d, r9b
    shl r9d, 1
    or eax, r8d
    or eax, r9d
    ret
dynamic_bits ENDP
dynamic_bits_end PROC
    int 3
dynamic_bits_end ENDP

bit_scans PROC
    bsr rax, rcx
    jz bit_scans_zero
    bsf rdx, rcx
    add rax, rdx
    ret
bit_scans_zero:
    mov rax, -1
    ret
bit_scans ENDP
bit_scans_end PROC
    int 3
bit_scans_end ENDP

imul_three PROC
    imul rax, rcx, 30
    jo imul_three_overflow
    imul rdx, r8, 3
    jo imul_three_overflow
    add rax, rdx
    ret
imul_three_overflow:
    mov rax, -1
    ret
imul_three ENDP
imul_three_end PROC
    int 3
imul_three_end ENDP

bit_reset PROC
    mov eax, ecx
    btr eax, 3
    bts eax, 7
    bt eax, 7
    setb r8b
    movzx r8d, r8b
    shl r8d, 8
    or eax, r8d
    ret
bit_reset ENDP
bit_reset_end PROC
    int 3
bit_reset_end ENDP

imul_one64 PROC
    mov rax, rcx
    imul r8
    jo imul_one64_overflow
    add rax, rdx
    ret
imul_one64_overflow:
    mov rax, -1
    ret
imul_one64 ENDP
imul_one64_end PROC
    int 3
imul_one64_end ENDP

imul_one32 PROC
    mov eax, ecx
    imul r8d
    jo imul_one32_overflow
    add rax, rdx
    ret
imul_one32_overflow:
    mov rax, -1
    ret
imul_one32 ENDP
imul_one32_end PROC
    int 3
imul_one32_end ENDP

mul_one64 PROC
    mov rax, rcx
    mul r8
    jo mul_one64_overflow
    add rax, rdx
    ret
mul_one64_overflow:
    mov rax, -1
    ret
mul_one64 ENDP
mul_one64_end PROC
    int 3
mul_one64_end ENDP

mul_one32 PROC
    mov eax, ecx
    mul r8d
    jo mul_one32_overflow
    add rax, rdx
    ret
mul_one32_overflow:
    mov rax, -1
    ret
mul_one32 ENDP
mul_one32_end PROC
    int 3
mul_one32_end ENDP

sbb_flags PROC
    mov rax, rcx
    bt rax, 0
    sbb rax, rdx
    jo sbb_overflow
    jc sbb_carry
    ret
sbb_carry:
    mov rax, 55h
    ret
sbb_overflow:
    mov rax, -1
    ret
sbb_flags ENDP
sbb_flags_end PROC
    int 3
sbb_flags_end ENDP

adc_flags PROC
    mov rax, rcx
    bt rax, 0
    adc rax, rdx
    pushfq
    pop r8
    and r8d, 811h
    shl r8, 32
    or rax, r8
    ret
adc_flags ENDP
adc_flags_end PROC
    int 3
adc_flags_end ENDP

double_shifts PROC
    mov eax, ecx
    shld eax, edx, 1
    pushfq
    pop r8
    and r8d, 8C5h
    mov r9d, ecx
    shrd r9d, edx, 1
    pushfq
    pop r10
    and r10d, 8C5h
    or r8, r10
    shl r8, 32
    mov r11d, ecx
    shld r11d, edx, 31
    setc cl
    movzx ecx, cl
    add r11d, ecx
    shrd eax, edx, 31
    setc cl
    movzx ecx, cl
    add eax, ecx
    add rax, r9
    add rax, r11
    add rax, r8
    ret
double_shifts ENDP
double_shifts_end PROC
    int 3
double_shifts_end ENDP

carry_rotates PROC
    mov eax, ecx
    bt eax, 0
    rcl eax, 1
    setc r8b
    seto r9b
    rcr eax, 1
    setc r10b
    seto r11b
    movzx r8d, r8b
    movzx r9d, r9b
    movzx r10d, r10b
    movzx r11d, r11b
    rcl eax, 17
    setc cl
    movzx ecx, cl
    add r8d, ecx
    rcr eax, 29
    setc cl
    movzx ecx, cl
    add r8d, ecx
    shl r9d, 1
    shl r10d, 2
    shl r11d, 3
    or r8d, r9d
    or r8d, r10d
    or r8d, r11d
    mov eax, r8d
    ret
carry_rotates ENDP
carry_rotates_end PROC
    int 3
carry_rotates_end ENDP

rotate_values PROC
    mov r8d, ecx
    bt r8d, 0
    rcl r8d, 1
    mov r9d, ecx
    bt r9d, 0
    rcr r9d, 1
    mov r10d, ecx
    bt r10d, 0
    rcl r10d, 17
    mov r11d, ecx
    bt r11d, 0
    rcr r11d, 29
    mov eax, r8d
    add rax, r9
    add rax, r10
    add rax, r11
    ret
rotate_values ENDP
rotate_values_end PROC
    int 3
rotate_values_end ENDP

bit_operations PROC
    mov rax, rcx
    bswap rax
    mov r8, rcx
    popcnt r8, rcx
    setz r9b
    movzx r9d, r9b
    mov r10d, ecx
    bswap r10d
    mov r11d, ecx
    popcnt r11d, r11d
    shl r10, 32
    add rax, r10
    add rax, r8
    add rax, r11
    shl r9, 63
    or rax, r9
    ret
bit_operations ENDP
bit_operations_end PROC
    int 3
bit_operations_end ENDP

crc32_values PROC
    mov eax, ecx
    crc32 eax, edx
    mov r8d, ecx
    crc32 r8d, dx
    add rax, r8
    mov r8d, ecx
    crc32 r8d, dl
    add rax, r8
    mov r8, rcx
    crc32 r8, rdx
    add rax, r8
    ret
crc32_values ENDP
crc32_values_end PROC
    int 3
crc32_values_end ENDP

jump_rcx PROC
    mov rax, rcx
    db 2eh
    jrcxz jump_rcx_zero
    add rax, rdx
    ret
jump_rcx_zero:
    mov rax, -1
    ret
jump_rcx ENDP
jump_rcx_end PROC
    int 3
jump_rcx_end ENDP

ret_immediate PROC
    mov rax, rcx
    ret 8
ret_immediate ENDP
ret_immediate_end PROC
    int 3
ret_immediate_end ENDP

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
    db 3eh, 3bh, 51h, 01h
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

push_stack_sources PROC
    mov r8, rsp
    push rsp
    pop rax
    sub rax, r8
    mov r9, [rsp]
    push qword ptr [rsp]
    pop r10
    cmp r9, r10
    sete r9b
    movzx r9d, r9b
    shl r9d, 1
    or rax, r9
    ret
push_stack_sources ENDP
push_stack_sources_end PROC
    int 3
push_stack_sources_end ENDP

push_flags PROC
    xor eax, eax
    stc
    pushfq
    pop rax
    and rax, 0FFFh
    cmc
    pushfq
    pop rdx
    and rdx, 0FFFh
    shl rdx, 12
    or rax, rdx
    mov r9, rcx
    and r9d, 8D5h
    or r9d, 2
    push r9
    popfq
    pushfq
    pop r8
    and r8d, 0FFFh
    shl r8, 24
    or rax, r8
    mov r11, rax
    mov ah, cl
    sahf
    pushfq
    pop r10
    and r10d, 0D5h
    shl r10, 36
    or r11, r10
    mov rax, r11
    ret
push_flags ENDP
push_flags_end PROC
    int 3
push_flags_end ENDP

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

string_scans PROC
    mov rdi, rcx
    mov ax, r8w
    mov rcx, rdx
    repne scasw
    mov rax, rdi
    ret
string_scans ENDP
string_scans_end PROC
    int 3
string_scans_end ENDP

string_copies PROC
    cld
    mov r10, rcx
    mov r11, rdx
    mov rcx, r8
    mov rsi, r10
    mov rdi, r11
    rep movsq
    mov rcx, r8
    mov rsi, r10
    mov rdi, r11
    rep movsd
    mov rcx, r8
    mov rsi, r10
    mov rdi, r11
    rep movsw
    mov rcx, r8
    mov rsi, r10
    mov rdi, r11
    rep movsb
    mov rcx, r8
    lea rdi, [r11 + 40h]
    mov rax, 1122334455667788h
    rep stosq
    mov rcx, r8
    lea rdi, [r11 + 60h]
    mov rax, 1122334455667788h
    rep stosd
    mov rcx, r8
    lea rdi, [r11 + 70h]
    mov rax, 1122334455667788h
    rep stosw
    mov rcx, r8
    lea rdi, [r11 + 78h]
    mov rax, 1122334455667788h
    rep stosb
    mov rsi, r10
    mov rdi, r11
    movsd
    mov rax, r11
    ret
string_copies ENDP
string_copies_end PROC
    int 3
string_copies_end ENDP

lock_xadd PROC
    lock xadd dword ptr [rcx], edx
    jc lock_xadd_carry
    lock inc dword ptr [rcx]
    lock dec dword ptr [rcx]
    jc lock_xadd_bad_carry
    lock add dword ptr [rcx], 1
    lock or dword ptr [rcx], 0
    lock and dword ptr [rcx], -1
    lock and byte ptr [rcx], 0FFh
    mov eax, [rcx]
    lock cmpxchg dword ptr [rcx], edx
    setz r8b
    movzx r8d, r8b
    mov eax, [rcx]
    inc eax
    lock cmpxchg dword ptr [rcx], edx
    setz r9b
    movzx r9d, r9b
    shl r9d, 1
    or r8d, r9d
    mov rax, [rcx]
    add rax, rdx
    add rax, r8
    ret
lock_xadd_carry:
    lock inc dword ptr [rcx]
    lock dec dword ptr [rcx]
    jnc lock_xadd_bad_carry
    lock add dword ptr [rcx], 1
    lock or dword ptr [rcx], 0
    lock and dword ptr [rcx], -1
    lock and byte ptr [rcx], 0FFh
    mov rax, -1
    ret
lock_xadd_bad_carry:
    mov rax, -2
    ret
lock_xadd ENDP
lock_xadd_end PROC
    int 3
lock_xadd_end ENDP

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
    cvtss2si r10d, xmm6
    mov [rdx + 4], r10d
    cvtss2si r11, xmm6
    mov [rdx + 8], r11
    cvtsi2ss xmm6, dword ptr [rcx + 24]
    addss xmm6, dword ptr [rcx + 16]
    movss dword ptr [r8], xmm6
    movups xmm6, [rsp + 8]
    sub rsp, 20h
    stmxcsr dword ptr [rsp]
    mov r10d, [rsp]
    xor r10d, 6000h
    mov [rsp + 4], r10d
    ldmxcsr dword ptr [rsp + 4]
    stmxcsr dword ptr [r8 + 8]
    ldmxcsr dword ptr [rsp]
    add rsp, 20h
    ret
float_startup ENDP
float_startup_end PROC
    int 3
float_startup_end ENDP

scalar_double_convert PROC
    movss xmm0, dword ptr [rcx]
    cvtss2sd xmm0, xmm0
    movsd qword ptr [rdx], xmm0
    movsd xmm0, qword ptr [rcx + 8]
    comisd xmm0, qword ptr [rcx + 16]
    jp scalar_double_unordered
    je scalar_double_equal
    jb scalar_double_below
    mov eax, 2
    ret
scalar_double_equal:
    xor eax, eax
    ret
scalar_double_below:
    mov eax, 1
    ret
scalar_double_unordered:
    mov eax, 4
    ret
scalar_double_convert ENDP
scalar_double_convert_end PROC
    int 3
scalar_double_convert_end ENDP

scalar_int_double PROC
    movsd xmm0, qword ptr [rcx]
    cvttsd2si eax, xmm0
    mov [rdx], eax
    cvtsi2sd xmm0, dword ptr [rcx + 16]
    movsd qword ptr [r8], xmm0
    movsd xmm0, qword ptr [rcx + 8]
    cvttsd2si rax, xmm0
    ret
scalar_int_double ENDP
scalar_int_double_end PROC
    int 3
scalar_int_double_end ENDP

scalar_double PROC
    movsd xmm0, qword ptr [rcx]
    subsd xmm0, qword ptr [rdx]
    divsd xmm0, qword ptr [rcx + 8]
    addsd xmm0, qword ptr [rdx + 8]
    mulsd xmm0, qword ptr [rcx + 8]
    movsd qword ptr [r8], xmm0
    mov rax, [r8]
    ret
scalar_double ENDP
scalar_double_end PROC
    int 3
scalar_double_end ENDP

vector_general PROC
    movd xmm5, ecx
    movd dword ptr [rdx], xmm5
    movq xmm5, r8
    movq qword ptr [r9], xmm5
    movq xmm1, xmm5
    movq qword ptr [r9], xmm1
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
    divps xmm5, [rdx]
    andps xmm5, [rcx]
    movups [r8], xmm5
    mov rax, [r8]
    ret
vector_float ENDP
vector_float_end PROC
    int 3
vector_float_end ENDP

vector_andnot PROC
    movups xmm0, [rcx]
    movups xmm1, [rdx]
    andnps xmm0, [rdx]
    orps xmm0, xmm1
    pand xmm0, [rcx]
    orps xmm0, [rdx]
    pandn xmm0, xmm1
    por xmm0, [rcx]
    pxor xmm0, xmm1
    xorpd xmm0, xmm1
    andpd xmm0, xmm1
    movups [r8], xmm0
    mov rax, [r8]
    ret
vector_andnot ENDP
vector_andnot_end PROC
    int 3
vector_andnot_end ENDP

vector_shuffle PROC
    movups xmm0, [rcx]
    movups xmm1, [rdx]
    shufps xmm0, xmm1, 0
    shufps xmm0, xmm1, 1Bh
    unpcklps xmm0, xmm1
    unpckhps xmm0, [rcx]
    movups [r8], xmm0
    mov rax, [r8]
    ret
vector_shuffle ENDP
vector_shuffle_end PROC
    int 3
vector_shuffle_end ENDP

vector_unpack64 PROC
    movups xmm0, [rcx]
    movups xmm1, [rdx]
    unpcklpd xmm0, xmm1
    movups [r8], xmm0
    movups xmm0, [rcx]
    unpckhpd xmm0, xmm1
    movups [r8 + 16], xmm0
    movups xmm0, [rcx]
    punpcklqdq xmm0, xmm1
    movups [r8 + 32], xmm0
    movups xmm0, [rcx]
    movhpd xmm0, qword ptr [rdx]
    movups [r8 + 48], xmm0
    movhpd qword ptr [r8 + 64], xmm0
    movlps xmm0, qword ptr [rdx + 8]
    movups [r8 + 72], xmm0
    movntps [r8 + 96], xmm0
    movapd xmm2, xmm0
    movups [r8 + 112], xmm2
    mov rax, [r8]
    ret
vector_unpack64 ENDP
vector_unpack64_end PROC
    int 3
vector_unpack64_end ENDP

vector_shuffle_double PROC
    movups xmm0, [rcx]
    movups xmm1, [rdx]
    movhlps xmm0, xmm1
    movups [r8], xmm0
    movups xmm0, [rcx]
    pshufd xmm0, xmm0, 1Bh
    movups [r8 + 16], xmm0
    movups xmm0, [rcx]
    cmpleps xmm0, xmm1
    movups [r8 + 32], xmm0
    movups xmm0, [rcx]
    subpd xmm0, xmm1
    movups [r8 + 48], xmm0
    movups xmm0, [rcx]
    addpd xmm0, [rdx]
    movups [r8 + 64], xmm0
    movups xmm0, [rcx]
    mulpd xmm0, xmm1
    movups [r8 + 80], xmm0
    movups xmm0, [rcx]
    divpd xmm0, [rdx]
    movups [r8 + 96], xmm0
    movups xmm0, [rcx]
    movlhps xmm0, xmm1
    movups [r8 + 112], xmm0
    movups xmm0, [rcx]
    cmpeqpd xmm0, [rdx]
    movups [r8 + 128], xmm0
    movups xmm0, [rcx]
    cmpltpd xmm0, xmm1
    movups [r8 + 144], xmm0
    movups xmm0, [rcx]
    cmpless xmm0, xmm1
    movups [r8 + 160], xmm0
    movups xmm0, [rcx]
    haddpd xmm0, xmm1
    movups [r8 + 176], xmm0
    movups xmm0, [rcx]
    shufpd xmm0, xmm1, 2
    movups [r8 + 192], xmm0
    movups xmm0, [rcx]
    cmpnltpd xmm0, xmm1
    movups [r8 + 208], xmm0
    mov rax, [r8]
    ret
vector_shuffle_double ENDP
vector_shuffle_double_end PROC
    int 3
vector_shuffle_double_end ENDP

vector_horizontal PROC
    movups xmm0, [rcx]
    movups xmm1, [rdx]
    haddps xmm0, xmm1
    hsubps xmm0, xmm1
    movups [r8], xmm0
    mov rax, [r8]
    ret
vector_horizontal ENDP
vector_horizontal_end PROC
    int 3
vector_horizontal_end ENDP

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

vector_integer PROC
    prefetcht0 byte ptr [rcx]
    prefetchnta byte ptr [rcx]
    prefetch byte ptr [rcx]
    pause
    wait
    movups xmm0, [rcx]
    punpckldq xmm0, [rdx]
    movups [r8], xmm0
    movups xmm0, [rcx]
    pcmpeqd xmm0, [rdx]
    movups [r8 + 16], xmm0
    movups xmm0, [rcx]
    psadbw xmm0, [rdx]
    movups [r8 + 32], xmm0
    movups xmm0, [rcx]
    pcmpgtd xmm0, [rdx]
    movups [r8 + 48], xmm0
    movups xmm0, [rcx]
    pextrw eax, xmm0, 0
    mov [r8 + 64], eax
    pextrw eax, xmm0, 1
    mov [r8 + 68], eax
    pextrw eax, xmm0, 2
    mov [r8 + 72], eax
    pextrw eax, xmm0, 3
    mov [r8 + 76], eax
    pextrw eax, xmm0, 4
    mov [r8 + 80], eax
    pextrw eax, xmm0, 5
    mov [r8 + 84], eax
    pextrw eax, xmm0, 6
    mov [r8 + 88], eax
    pextrw eax, xmm0, 7
    mov [r8 + 92], eax
    movups xmm0, [rcx]
    punpcklwd xmm0, [rdx]
    movups [r8 + 96], xmm0
    movups xmm0, [rcx]
    pmulld xmm0, [rdx]
    movups [r8 + 112], xmm0
    movups xmm0, [rcx]
    pinsrw xmm0, word ptr [rdx], 3
    mov esi, [rdx]
    pinsrw xmm0, esi, 7
    movups [r8 + 128], xmm0
    movups xmm0, [rcx]
    vpminsw xmm2, xmm0, [rdx]
    movups [r8 + 144], xmm2
    mov rax, [r8]
    ret
vector_integer ENDP
vector_integer_end PROC
    int 3
vector_integer_end ENDP

vector_int_arith PROC
    movups xmm0, [rcx]
    paddd xmm0, [rdx]
    psubd xmm0, [rdx]
    psrld xmm0, 4
    pslld xmm0, 8
    movups [r8], xmm0
    movups xmm0, [rcx]
    paddq xmm0, [rdx]
    psubq xmm0, [rdx]
    psrlq xmm0, 4
    psllq xmm0, 8
    movups [r8 + 16], xmm0
    movups xmm0, [rcx]
    psrad xmm0, 0
    movups [r8 + 32], xmm0
    movups xmm0, [rcx]
    psrad xmm0, 1
    movups [r8 + 48], xmm0
    movups xmm0, [rcx]
    psrad xmm0, 31
    movups [r8 + 64], xmm0
    movups xmm0, [rcx]
    psrad xmm0, 32
    movups [r8 + 80], xmm0
    movups xmm0, [rcx]
    psrad xmm0, 255
    movups [r8 + 96], xmm0
    movups xmm0, [rcx]
    psllw xmm0, 1
    movups [r8 + 112], xmm0
    mov eax, 3
    movq xmm1, rax
    movups xmm0, [rcx]
    psllw xmm0, xmm1
    movups [r8 + 128], xmm0
    mov eax, 16
    movq xmm1, rax
    movups xmm0, [rcx]
    psllw xmm0, xmm1
    movups [r8 + 144], xmm0
    mov eax, 3
    movq xmm1, rax
    movups xmm0, [rcx]
    pslld xmm0, xmm1
    movups [r8 + 160], xmm0
    movups xmm0, [rcx]
    psllq xmm0, xmm1
    movups [r8 + 176], xmm0
    mov eax, 32
    movq xmm1, rax
    movups xmm0, [rcx]
    pslld xmm0, xmm1
    movups [r8 + 192], xmm0
    movups xmm0, [rcx]
    paddw xmm0, [rdx]
    movups [r8 + 208], xmm0
    mov rax, [r8]
    ret
vector_int_arith ENDP
vector_int_arith_end PROC
    int 3
vector_int_arith_end ENDP

vector_int_double PROC
    movdqu xmm0, [rcx]
    cvtdq2pd xmm0, xmm0
    movups [r8], xmm0
    pmovsxdq xmm0, qword ptr [rcx]
    movups [r8 + 16], xmm0
    mov rax, [r8]
    ret
vector_int_double ENDP
vector_int_double_end PROC
    int 3
vector_int_double_end ENDP

vector_convert PROC
    cvtps2pd xmm0, qword ptr [rcx]
    movups [r8], xmm0
    movups xmm1, [rdx]
    cvtpd2ps xmm1, xmm1
    movups [r9], xmm1
    movups xmm1, [rdx]
    cvttpd2dq xmm1, xmm1
    movups [r9 + 16], xmm1
    mov rax, [r8]
    ret
vector_convert ENDP
vector_convert_end PROC
    int 3
vector_convert_end ENDP

vector_mixed PROC
    movups xmm0, [rcx]
    addsubps xmm0, [rdx]
    movups [r8], xmm0
    movups xmm0, [rcx]
    cvtps2dq xmm0, xmm0
    movups [r8 + 16], xmm0
    movups xmm0, [rcx]
    cvttps2dq xmm0, [rcx]
    movups [r8 + 32], xmm0
    mov rax, [r8]
    ret
vector_mixed ENDP
vector_mixed_end PROC
    int 3
vector_mixed_end ENDP

vector_compare PROC
    movups xmm0, [rcx]
    movups xmm1, [rdx]
    cmpeqps xmm0, xmm1
    movups [r8], xmm0
    movups xmm0, [rcx]
    cmpltps xmm0, xmm1
    movups [r8 + 16], xmm0
    movups xmm0, [rcx]
    cmpneqps xmm0, xmm1
    movups [r8 + 32], xmm0
    movmskps eax, xmm0
    pmovmskb edx, xmm0
    shl eax, 16
    or eax, edx
    movmskpd ecx, xmm0
    shl rcx, 32
    or rax, rcx
    ret
vector_compare ENDP
vector_compare_end PROC
    int 3
vector_compare_end ENDP

vector_minmax PROC
    movups xmm0, [rcx]
    minps xmm0, [rdx]
    movups [r8], xmm0
    movups xmm0, [rcx]
    maxps xmm0, [rdx]
    movups [r8 + 16], xmm0
    movsd xmm0, qword ptr [rcx]
    minsd xmm0, qword ptr [rdx]
    movsd qword ptr [r8 + 32], xmm0
    movsd xmm0, qword ptr [rcx]
    maxsd xmm0, qword ptr [rdx]
    movsd qword ptr [r8 + 40], xmm0
    mov rax, [r8]
    ret
vector_minmax ENDP
vector_minmax_end PROC
    int 3
vector_minmax_end ENDP

vector_approx PROC
    movups xmm0, [rcx]
    rsqrtps xmm0, xmm0
    movups [r8], xmm0
    movups xmm0, [rcx]
    rcpps xmm0, xmm0
    movups [r8 + 16], xmm0
    movups xmm0, [rcx]
    sqrtps xmm0, xmm0
    movups [r8 + 32], xmm0
    movups xmm0, [rdx]
    sqrtpd xmm0, xmm0
    movups [r8 + 48], xmm0
    mov rax, [r8]
    ret
vector_approx ENDP
vector_approx_end PROC
    int 3
vector_approx_end ENDP

vector_byteshift PROC
    movups xmm0, [rcx]
    psrldq xmm0, 4
    pslldq xmm0, 12
    movups [r8], xmm0
    psrldq xmm0, 16
    movups [r8 + 16], xmm0
    mov rax, [r8]
    ret
vector_byteshift ENDP
vector_byteshift_end PROC
    int 3
vector_byteshift_end ENDP

signed_division PROC
    mov rax, rcx
    idiv r8
    mov [r9], rdx
    ret
signed_division ENDP
signed_division_end PROC
    int 3
signed_division_end ENDP

unsigned_division PROC
    mov rax, rcx
    div r8
    mov [r9], rdx
    ret
unsigned_division ENDP
unsigned_division_end PROC
    int 3
unsigned_division_end ENDP

scalar_minmax PROC
    movss xmm5, dword ptr [rcx]
    maxss xmm5, dword ptr [rcx + 4]
    movss dword ptr [rdx], xmm5
    movss xmm5, dword ptr [rcx]
    minss xmm5, dword ptr [rcx + 4]
    movss dword ptr [r8], xmm5
    mov rax, [rdx]
    ret
scalar_minmax ENDP
scalar_minmax_end PROC
    int 3
scalar_minmax_end ENDP

scalar_sqrt PROC
    movss xmm0, dword ptr [rcx]
    sqrtss xmm0, xmm0
    movss dword ptr [rdx], xmm0
    movsd xmm0, qword ptr [rcx + 8]
    sqrtsd xmm0, xmm0
    movsd qword ptr [r8], xmm0
    movups xmm0, [rcx]
    rcpss xmm0, dword ptr [rcx]
    movups [rdx], xmm0
    mov rax, [r8]
    ret
scalar_sqrt ENDP
scalar_sqrt_end PROC
    int 3
scalar_sqrt_end ENDP

tls_read PROC
    mov rax, qword ptr gs:[58h]
    ret
tls_read ENDP
tls_read_end PROC
    int 3
tls_read_end ENDP

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

cpu_identification PROC
    push rbx
    mov rax, rcx
    mov rcx, rdx
    cpuid
    mov [r8], eax
    mov [r8 + 4], ebx
    mov [r8 + 8], ecx
    mov [r8 + 12], edx
    pop rbx
    mov ecx, 0
    xgetbv
    mov [r8 + 16], eax
    mov [r8 + 20], edx
    ret
cpu_identification ENDP
cpu_identification_end PROC
    int 3
cpu_identification_end ENDP

trap_instruction PROC
    int 3
    ret
trap_instruction ENDP
trap_instruction_end PROC
    int 3
trap_instruction_end ENDP

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
