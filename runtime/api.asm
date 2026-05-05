; runtime/api.asm
;
; Rinha de Backend 2026 — fraud detection API in pure x86_64 assembly.
;
; Stage 1 scaffold: synchronous accept loop, replies to every request with the
; "fraud_score=0.0" template. No HTTP parsing, no JSON, no IVF yet — those
; arrive in subsequent commits.
;
; Build: nasm -f elf64 -o build/runtime/api.o runtime/api.asm
;        ld -nostdlib -static -o build/api build/runtime/api.o
;
; Listens on 0.0.0.0:8080. ELF static, freestanding, no libc.

%include "syscalls.inc"

global _start

section .data
; struct sockaddr_in { uint16 family; uint16 port_be; uint32 addr; uint8[8] zero; }
sockaddr_in:
    dw  AF_INET            ; sin_family = 2 (little-endian short)
    db  0x1f, 0x90         ; sin_port  = htons(8080) = 0x1f90 in network order
    dd  0                  ; sin_addr  = INADDR_ANY (0.0.0.0)
    times 8 db 0           ; sin_zero
SOCKADDR_LEN equ $ - sockaddr_in

one_int: dd 1              ; setsockopt(SO_REUSEADDR, 1)

section .bss
recv_buf: resb 8192        ; per-connection scratch — single-threaded for now

; responses.inc declares its own `section .rodata`, so include it BEFORE
; switching to `section .text`. Otherwise _start lands in .rodata and the
; kernel can't execute it (SEGV_ACCERR).
%include "responses.inc"

section .text

; ----------------------------------------------------------------------
; _start: program entry. Sets up listening socket, then accept-serve loop.
; r12 = listen fd (callee-saved, lives forever)
; r13 = current client fd
; ----------------------------------------------------------------------
_start:
    mov eax, SYS_socket
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    syscall
    test rax, rax
    js .die
    mov r12, rax

    mov eax, SYS_setsockopt
    mov rdi, r12
    mov esi, SOL_SOCKET
    mov edx, SO_REUSEADDR
    lea r10, [rel one_int]
    mov r8d, 4
    syscall

    mov eax, SYS_bind
    mov rdi, r12
    lea rsi, [rel sockaddr_in]
    mov edx, SOCKADDR_LEN
    syscall
    test rax, rax
    js .die

    mov eax, SYS_listen
    mov rdi, r12
    mov esi, 4096
    syscall
    test rax, rax
    js .die

.accept_loop:
    mov eax, SYS_accept4
    mov rdi, r12
    xor esi, esi
    xor edx, edx
    xor r10, r10
    syscall
    test rax, rax
    js .accept_loop        ; EINTR / spurious — just retry
    mov r13, rax

.serve_loop:
    ; read(client, recv_buf, 8192)
    mov eax, SYS_read
    mov rdi, r13
    lea rsi, [rel recv_buf]
    mov edx, 8192
    syscall
    test rax, rax
    jle .close_client      ; 0 = EOF, <0 = error → drop connection

    ; STAGE 1: respond with resp0 unconditionally.
    ; STAGE 2 will: parse method/path, route /ready -> 204, /fraud-score ->
    ; parse JSON body, compute IVF k-NN, index resp_table[count].
    lea rsi, [rel resp0]
    mov edx, resp0_end - resp0
    mov eax, SYS_write
    mov rdi, r13
    syscall

    ; Loop on the same fd to honor HTTP/1.1 keep-alive (nginx upstream).
    jmp .serve_loop

.close_client:
    mov eax, SYS_close
    mov rdi, r13
    syscall
    jmp .accept_loop

.die:
    mov eax, SYS_exit_group
    mov edi, 1
    syscall
