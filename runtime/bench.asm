; runtime/bench.asm — offline benchmark harness for select_top8_clusters.
;
; Built with -DBENCH_BUILD; api.asm omits its own _start in that case so this
; file owns the entry point and reuses every other symbol from api.asm.
;
; Usage:
;   INDEX_PATH=resources/index.bin ./build/bench perf
;   INDEX_PATH=resources/index.bin ./build/bench diff
;
; perf: PERF_ITERS calls of select_top8_clusters with LCG-generated queries,
;       reports cycles/iter via rdtscp.
; diff: DIFF_ITERS iterations comparing select_top8_clusters vs *_legacy on
;       the same query, reports total mismatches across all 8 top-K slots.

%include "syscalls.inc"

%define PERF_ITERS     1000000
%define DIFF_ITERS     10000
%define SCANDIFF_ITERS 5000
%define SCANPERF_ITERS 50000

global _start

extern load_socket_path_from_env
extern load_index_optional
extern select_top8_clusters
extern select_top8_clusters_legacy
extern scan_cluster_soa_avx2
extern scan_cluster_soa_scalar
extern query_i16
extern cluster_best_id
extern best_dist
extern best_label
extern best_id
extern index_loaded
extern index_clusters
extern index_format

section .rodata
usage_msg:        db 'usage: bench perf|diff|scandiff|scanperf', 10
usage_msg_len    equ $ - usage_msg
no_index_msg:     db 'no index loaded; set INDEX_PATH=...', 10
no_index_msg_len equ $ - no_index_msg
no_sivf_msg:      db 'scandiff requires SIVF index (format=3)', 10
no_sivf_msg_len  equ $ - no_sivf_msg
perf_label:       db 'cycles_per_iter='
perf_label_len   equ $ - perf_label
diff_label:       db 'differences='
diff_label_len   equ $ - diff_label
scandiff_label:   db 'scan_differences='
scandiff_label_len equ $ - scandiff_label
scanperf_label:   db 'scan_cycles_per_iter='
scanperf_label_len equ $ - scanperf_label
nl_byte:          db 10

section .bss
itoa_buf:    resb 32
diff_snap_a: resq 8
diff_snap_b: resq 8
; Snapshot of best_dist[5] (40B) + best_label[5] (5B) + best_id[5] (20B) = 65B.
; Round to 80 for clean comparison loops.
scandiff_snap_a: resb 80
scandiff_snap_b: resb 80

section .text

; ============================================================
; _start — parse argv[1], dispatch to perf or diff.
; ============================================================
_start:
    mov rdi, rsp
    call load_socket_path_from_env       ; reads INDEX_PATH=, IVF_NPROBE=, etc.
    call load_index_optional

    cmp qword [rel index_loaded], 0
    je .die_no_index

    mov rax, [rsp]                       ; argc
    cmp rax, 2
    jl .die_usage

    mov rsi, [rsp + 16]                  ; argv[1]
    mov al, [rsi]
    cmp al, 'p'
    je .run_perf
    cmp al, 'd'
    je .run_diff
    cmp al, 's'
    je .scan_dispatch
    jmp .die_usage

.scan_dispatch:
    ; "scandiff" vs "scanperf": disambiguate on the 5th char.
    mov al, [rsi + 4]
    cmp al, 'd'
    je .run_scandiff
    cmp al, 'p'
    je .run_scanperf
    jmp .die_usage

.run_perf:
    call bench_perf
    xor edi, edi
    jmp .exit

.run_diff:
    call bench_diff
    xor edi, edi
    jmp .exit

.run_scandiff:
    cmp qword [rel index_format], 3
    jne .die_no_sivf
    call bench_scandiff
    xor edi, edi
    jmp .exit

.run_scanperf:
    cmp qword [rel index_format], 3
    jne .die_no_sivf
    call bench_scanperf
    xor edi, edi
    jmp .exit

.die_no_sivf:
    mov edi, 2
    lea rsi, [rel no_sivf_msg]
    mov edx, no_sivf_msg_len
    call write_all
    mov edi, 1
    jmp .exit

.die_no_index:
    mov edi, 2
    lea rsi, [rel no_index_msg]
    mov edx, no_index_msg_len
    call write_all
    mov edi, 1
    jmp .exit

.die_usage:
    mov edi, 2
    lea rsi, [rel usage_msg]
    mov edx, usage_msg_len
    call write_all
    mov edi, 1

.exit:
    mov eax, SYS_exit
    syscall

; ============================================================
; bench_perf — time PERF_ITERS calls of select_top8_clusters.
; ============================================================
bench_perf:
    push rbx
    push r12
    push r13

    mov rbx, 0xdeadbeefcafef00d         ; xorshift64* state

    rdtscp
    shl rdx, 32
    or rax, rdx
    mov r12, rax                         ; start tsc

    mov r13, PERF_ITERS

.loop:
    test r13, r13
    jz .done

    call write_query_random
    call select_top8_clusters

    dec r13
    jmp .loop

.done:
    rdtscp
    shl rdx, 32
    or rax, rdx
    sub rax, r12                         ; total cycles

    mov rcx, PERF_ITERS
    xor edx, edx
    div rcx                              ; rax = cycles/iter

    mov r12, rax
    mov edi, 1
    lea rsi, [rel perf_label]
    mov edx, perf_label_len
    call write_all

    mov rdi, r12
    call print_u64
    call print_newline

    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; bench_diff — DIFF_ITERS iterations comparing legacy vs current.
;   Counts mismatches across all 8 top-K cluster_best_id slots.
; ============================================================
bench_diff:
    push rbx
    push r12
    push r13

    mov rbx, 0xc0ffeed00fdeadbe          ; xorshift64* state, distinct seed

    xor r12, r12                         ; total mismatches
    mov r13, DIFF_ITERS

.loop:
    test r13, r13
    jz .done

    call write_query_random

    call select_top8_clusters_legacy
    lea rdi, [rel diff_snap_a]
    lea rsi, [rel cluster_best_id]
    mov ecx, 8
.snap_a:
    mov rax, [rsi]
    mov [rdi], rax
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz .snap_a

    call select_top8_clusters
    lea rdi, [rel diff_snap_b]
    lea rsi, [rel cluster_best_id]
    mov ecx, 8
.snap_b:
    mov rax, [rsi]
    mov [rdi], rax
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz .snap_b

    lea rdi, [rel diff_snap_a]
    lea rsi, [rel diff_snap_b]
    mov ecx, 8
.cmp_loop:
    mov rax, [rdi]
    cmp rax, [rsi]
    je .skip
    inc r12
.skip:
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz .cmp_loop

    dec r13
    jmp .loop

.done:
    mov rbx, r12
    mov edi, 1
    lea rsi, [rel diff_label]
    mov edx, diff_label_len
    call write_all

    mov rdi, rbx
    call print_u64
    call print_newline

    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; bench_scanperf — time SCANPERF_ITERS calls of scan_cluster_soa_avx2.
;   Cycles each iteration: write a fresh random query, pick a random
;   cluster id, reset best_*, call scan, repeat. The reset keeps each
;   call doing real work (otherwise insert_best skips on warm best_*).
; ============================================================
bench_scanperf:
    push rbx
    push r12
    push r13
    push r14

    mov rbx, 0x9e3779b97f4a7c15          ; xorshift64* state

    rdtscp
    shl rdx, 32
    or rax, rdx
    mov r12, rax                         ; start tsc

    mov r13, SCANPERF_ITERS

.loop:
    test r13, r13
    jz .done

    call write_query_random

    call lcg_next
    xor edx, edx
    mov rcx, [rel index_clusters]
    div rcx
    mov r14, rdx                         ; cluster id

    call reset_best_buffers
    mov rdi, r14
    call scan_cluster_soa_avx2

    dec r13
    jmp .loop

.done:
    rdtscp
    shl rdx, 32
    or rax, rdx
    sub rax, r12

    mov rcx, SCANPERF_ITERS
    xor edx, edx
    div rcx                              ; cycles/iter

    mov r12, rax
    mov edi, 1
    lea rsi, [rel scanperf_label]
    mov edx, scanperf_label_len
    call write_all
    mov rdi, r12
    call print_u64
    call print_newline

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; bench_scandiff — compare scan_cluster_soa_avx2 vs *_scalar across N
;   (random query, random cluster id) pairs. Reports total mismatches in
;   best_dist[5] + best_label[5] + best_id[5] across all iterations.
;   Requires SIVF index format (cluster_offsets layout matches).
; ============================================================
bench_scandiff:
    push rbx
    push r12
    push r13
    push r14

    mov rbx, 0xfeedface12345678          ; xorshift64* state

    xor r12, r12                         ; total mismatches
    mov r13, SCANDIFF_ITERS

.loop:
    test r13, r13
    jz .done

    call write_query_random

    call lcg_next                        ; rax = entropy
    xor edx, edx
    mov rcx, [rel index_clusters]
    test rcx, rcx
    jz .done
    div rcx                              ; rdx = cluster_id
    mov r14, rdx

    call reset_best_buffers
    mov rdi, r14
    call scan_cluster_soa_scalar
    lea rdi, [rel scandiff_snap_a]
    call snapshot_best

    call reset_best_buffers
    mov rdi, r14
    call scan_cluster_soa_avx2
    lea rdi, [rel scandiff_snap_b]
    call snapshot_best

    lea rdi, [rel scandiff_snap_a]
    lea rsi, [rel scandiff_snap_b]
    call compare_snapshots_best
    add r12, rax

    dec r13
    jmp .loop

.done:
    mov rbx, r12
    mov edi, 1
    lea rsi, [rel scandiff_label]
    mov edx, scandiff_label_len
    call write_all
    mov rdi, rbx
    call print_u64
    call print_newline

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; reset_best_buffers — match knn_count_first_clusters init exactly.
;   best_dist[0..5]  = -1   (max u64)
;   best_label[0..5] = 0
;   best_id[0..5]    = -1   (i32)
; ============================================================
reset_best_buffers:
    push rdi
    push rcx
    push rax
    lea rdi, [rel best_dist]
    mov rax, -1
    mov ecx, 5
.dist:
    mov [rdi], rax
    add rdi, 8
    loop .dist

    lea rdi, [rel best_label]
    xor eax, eax
    mov ecx, 5
.label:
    mov [rdi], al
    inc rdi
    loop .label

    lea rdi, [rel best_id]
    mov eax, -1
    mov ecx, 5
.id:
    mov [rdi], eax
    add rdi, 4
    loop .id

    pop rax
    pop rcx
    pop rdi
    ret

; ============================================================
; snapshot_best — copy best_dist (40B) + best_label (5B) + best_id (20B)
;   into the buffer pointed to by rdi (must hold ≥ 65 bytes).
; ============================================================
snapshot_best:
    push rsi
    push rcx
    push rax
    push rdi

    lea rsi, [rel best_dist]
    mov ecx, 5
.cd:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .cd

    lea rsi, [rel best_label]
    mov ecx, 5
.cl:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .cl

    lea rsi, [rel best_id]
    mov ecx, 5
.ci:
    mov eax, [rsi]
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .ci

    pop rdi
    pop rax
    pop rcx
    pop rsi
    ret

; ============================================================
; compare_snapshots_best — count mismatches between two best_* snapshots.
;   In : rdi = a, rsi = b.  Out: rax = mismatch count (0..15).
; ============================================================
compare_snapshots_best:
    push rcx
    push r8
    xor eax, eax

    mov ecx, 5
.cmp_d:
    mov r8, [rdi]
    cmp r8, [rsi]
    je .nx_d
    inc rax
.nx_d:
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz .cmp_d

    mov ecx, 5
.cmp_l:
    mov r8b, [rdi]
    cmp r8b, [rsi]
    je .nx_l
    inc rax
.nx_l:
    inc rdi
    inc rsi
    dec ecx
    jnz .cmp_l

    mov ecx, 5
.cmp_i:
    mov r8d, [rdi]
    cmp r8d, [rsi]
    je .nx_i
    inc rax
.nx_i:
    add rdi, 4
    add rsi, 4
    dec ecx
    jnz .cmp_i

    pop r8
    pop rcx
    ret

; ============================================================
; lcg_next — xorshift64* with state in rbx, returns rax = next value.
;   Clobbers: rax, r10. Modifies rbx. Preserves all other GPRs.
; ============================================================
lcg_next:
    mov rax, rbx
    shr rax, 12
    xor rbx, rax
    mov rax, rbx
    shl rax, 25
    xor rbx, rax
    mov rax, rbx
    shr rax, 27
    xor rbx, rax
    mov rax, rbx
    mov r10, 0x2545F4914F6CDD1D
    imul rax, r10
    ret

; ============================================================
; write_query_random — fill query_i16[0..14] with pseudo-random i16 lanes.
;   Uses + advances rbx (xorshift64* state). Lanes 14, 15 stay zero.
;   Clobbers: rax, r10.
; ============================================================
write_query_random:
    push rcx
    push rdx
    push rsi
    push rdi
    push r9

    lea rdi, [rel query_i16]
    xor edx, edx                         ; bits left in rsi
    mov r9d, 14
.fill:
    test edx, edx
    jnz .have_bits
    call lcg_next
    mov rsi, rax
    mov edx, 64
.have_bits:
    mov word [rdi], si
    add rdi, 2
    shr rsi, 16
    sub edx, 16
    dec r9d
    jnz .fill

    mov word [rel query_i16 + 28], 0
    mov word [rel query_i16 + 30], 0

    pop r9
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    ret

; ============================================================
; print_u64 — write rdi as decimal ASCII to stdout (no newline).
;   Clobbers: rax, rcx, rdx, r8, r9, r10, r11.
; ============================================================
print_u64:
    push rbx
    push r12

    lea r12, [rel itoa_buf + 32]
    mov rax, rdi
    mov rcx, 10
    mov rbx, r12
.loop:
    xor edx, edx
    div rcx
    add dl, '0'
    dec rbx
    mov [rbx], dl
    test rax, rax
    jnz .loop

    mov rsi, rbx
    mov rdx, r12
    sub rdx, rbx
    mov edi, 1
    call write_all

    pop r12
    pop rbx
    ret

print_newline:
    mov edi, 1
    lea rsi, [rel nl_byte]
    mov edx, 1
    call write_all
    ret

; ============================================================
; write_all — write(fd=edi, buf=rsi, len=rdx). Loops on partial writes.
;   Returns rax=0 on success, -1 on error.
; ============================================================
write_all:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .done
    mov eax, SYS_write
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    syscall
    test rax, rax
    js .err
    add r12, rax
    sub r13, rax
    jmp .loop
.done:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.err:
    mov eax, -1
    pop r13
    pop r12
    pop rbx
    ret
