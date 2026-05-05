; runtime/api.asm — Rinha 2026 fraud detection API in pure x86_64 asm
;
; Wave 1: HTTP/1.1 parser + routing.
;
; Loop:
;   accept4 → serve_one_request → (keep-alive) serve_one_request → ... → close
;
; serve_one_request reads until both `\r\n\r\n` and the full body (per
; Content-Length) are buffered, then routes:
;
;   GET  /ready          → ready_resp (204 No Content)
;   POST /fraud-score    → resp0     (Wave 5 will compute the real score)
;   anything else        → resp0     (mirrors Rust's approve-fallback)
;
; The body bytes are present at recv_buf[body_offset..total_len) but the
; JSON parser to consume them lands in Wave 2.

%include "syscalls.inc"

global _start

section .data
sockaddr_in:
    dw  AF_INET
    db  0x1f, 0x90         ; htons(8080)
    dd  0
    times 8 db 0
SOCKADDR_LEN equ $ - sockaddr_in

one_int: dd 1

section .bss
; Per-connection scratch. 16 KiB covers the largest payload we'll see (the
; Rinha references include ~500-byte JSON blobs; headers add ~200 bytes).
recv_buf:  resb 16384

%include "responses.inc"

; Patterns for path matching and header search.
section .rodata
ready_path:    db '/ready '
ready_path_len equ $ - ready_path
fs_path:       db '/fraud-score '
fs_path_len    equ $ - fs_path
cl_pattern:    db "content-length:"
cl_pattern_len equ $ - cl_pattern
tx_count_key:  db '"tx_count_24h"'
tx_count_key_len equ $ - tx_count_key

section .text

; ============================================================
; _start — setup listener, then accept-serve loop forever.
; ============================================================
_start:
    mov eax, SYS_socket
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    syscall
    test rax, rax
    js .die
    mov r12, rax              ; r12 = listen fd, lives forever

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
    js .accept_loop
    mov r13, rax              ; r13 = client fd, lives until close

.serve_loop:
    call serve_one_request
    test rax, rax
    js .close_client
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

; ============================================================
; serve_one_request — read+parse one HTTP request and write the response.
;   In : r13 = client fd
;   Out: rax = 0 (keep-alive), -1 (close)
;   Locals (callee-saved): rbx = body offset, r14 = bytes accumulated,
;                          r15 = total bytes needed
; ============================================================
serve_one_request:
    push rbx
    push r14
    push r15

    xor r14, r14              ; bytes accumulated in recv_buf

.read_until_headers:
    mov eax, SYS_read
    mov rdi, r13
    lea rsi, [rel recv_buf]
    add rsi, r14
    mov edx, 16384
    sub rdx, r14
    jle .conn_drop            ; buffer full without seeing \r\n\r\n
    syscall
    test rax, rax
    jle .conn_drop            ; EOF (0) or read error (<0)
    add r14, rax

    lea rdi, [rel recv_buf]
    mov rsi, r14
    call find_crlf_crlf
    test rax, rax
    js .read_until_headers

    ; rax = headers length (offset of \r\n\r\n start)
    lea rbx, [rax + 4]        ; rbx = body offset (after the \r\n\r\n)

    lea rdi, [rel recv_buf]
    mov rsi, rax              ; pass headers length
    call parse_content_length
    ; rax = content length (0 if header missing)

    add rax, rbx
    mov r15, rax              ; total bytes needed

    cmp r15, 16384
    ja .conn_drop             ; payload bigger than our buffer — drop

.read_until_body_done:
    cmp r14, r15
    jae .have_full_request

    mov eax, SYS_read
    mov rdi, r13
    lea rsi, [rel recv_buf]
    add rsi, r14
    mov edx, 16384
    sub rdx, r14
    syscall
    test rax, rax
    jle .conn_drop
    add r14, rax
    jmp .read_until_body_done

.have_full_request:
    lea rdi, [rel recv_buf]
    lea rsi, [rel recv_buf]
    add rsi, rbx              ; rsi = body ptr
    mov rdx, r14
    sub rdx, rbx              ; rdx = buffered body length
    call route_request        ; rax = response ptr, rdx = response length

    mov rsi, rax
    mov eax, SYS_write
    mov rdi, r13
    syscall
    ; If write fails the next read will return EOF/EPIPE and we'll close
    ; cleanly anyway; not worth a separate branch here.

    xor rax, rax
    pop r15
    pop r14
    pop rbx
    ret

.conn_drop:
    mov rax, -1
    pop r15
    pop r14
    pop rbx
    ret

; ============================================================
; route_request — inspect method + path, return (response_ptr, length).
;   In : rdi = pointer to request line (recv_buf)
;        rsi = body pointer
;        rdx = body length
;   Out: rax = response ptr, rdx = response length
; ============================================================
route_request:
    push rbx
    push r12
    mov rbx, rsi              ; preserve body ptr across path checks
    mov r12, rdx              ; preserve body len across path checks

    mov eax, [rdi]
    cmp eax, 0x20544547       ; 'GET ' little-endian
    je .is_get
    cmp eax, 0x54534f50       ; 'POST'
    jne .approve_fallback
    cmp byte [rdi + 4], ' '
    jne .approve_fallback

.is_post:
    lea rsi, [rdi + 5]
    lea r8, [rel fs_path]
    mov ecx, fs_path_len
    call bytes_eq
    test rax, rax
    jnz .approve_fallback
    mov rdi, rbx
    mov rsi, r12
    call parse_score_count_from_json
    shl rax, 4                ; resp_table stores 16-byte [ptr,len] slots
    lea r8, [rel resp_table]
    mov rdx, [r8 + rax + 8]
    mov rax, [r8 + rax]
    jmp .done

.is_get:
    lea rsi, [rdi + 4]
    lea r8, [rel ready_path]
    mov ecx, ready_path_len
    call bytes_eq
    test rax, rax
    jnz .approve_fallback
    lea rax, [rel ready_resp]
    mov edx, READY_RESP_LEN
    jmp .done

.approve_fallback:
    lea rax, [rel resp0]
    mov edx, resp0_end - resp0
.done:
    pop r12
    pop rbx
    ret

; ============================================================
; bytes_eq — case-sensitive byte compare.
;   In : rsi = ptr a, r8 = ptr b, rcx = length
;   Out: rax = 0 if equal, 1 otherwise
; ============================================================
bytes_eq:
.loop:
    test rcx, rcx
    jz .eq
    mov al, [rsi]
    mov r9b, [r8]
    cmp al, r9b
    jne .ne
    inc rsi
    inc r8
    dec rcx
    jmp .loop
.eq:
    xor rax, rax
    ret
.ne:
    mov rax, 1
    ret

; ============================================================
; find_crlf_crlf — locate the first \r\n\r\n in the buffer.
;   In : rdi = buffer, rsi = length
;   Out: rax = offset of \r\n\r\n, or -1 if not found
; ============================================================
find_crlf_crlf:
    cmp rsi, 4
    jb .not_found
    sub rsi, 3                ; rsi = max valid start + 1
    xor rcx, rcx
.loop:
    cmp rcx, rsi
    jae .not_found
    mov eax, [rdi + rcx]
    cmp eax, 0x0a0d0a0d       ; "\r\n\r\n" little-endian
    je .found
    inc rcx
    jmp .loop
.found:
    mov rax, rcx
    ret
.not_found:
    mov rax, -1
    ret

; ============================================================
; parse_content_length — case-insensitive scan for "content-length:" then
;   decode the decimal that follows.
;   In : rdi = headers buffer, rsi = headers length
;   Out: rax = decoded length, or 0 if header missing/malformed
; ============================================================
parse_content_length:
    mov r9, rdi
    mov r10, rsi

    cmp r10, cl_pattern_len
    jb .not_found

    mov r11, r10
    sub r11, cl_pattern_len   ; r11 = max start offset (inclusive)

    xor r8, r8                ; r8 = current offset

.scan:
    cmp r8, r11
    ja .not_found

    mov rcx, cl_pattern_len
    lea rsi, [r9 + r8]
    lea rdi, [rel cl_pattern]
.ci_cmp:
    test rcx, rcx
    jz .matched
    mov al, [rsi]
    or al, 0x20               ; lowercase the haystack byte
    mov dl, [rdi]
    cmp al, dl
    jne .next
    inc rsi
    inc rdi
    dec rcx
    jmp .ci_cmp
.next:
    inc r8
    jmp .scan

.matched:
    add r8, cl_pattern_len    ; r8 = first byte of the value

.skip_ws:
    cmp r8, r10
    jae .not_found
    movzx eax, byte [r9 + r8]
    cmp al, ' '
    je .ws
    cmp al, 9
    je .ws
    jmp .parse_int
.ws:
    inc r8
    jmp .skip_ws

.parse_int:
    xor rax, rax
.digit:
    cmp r8, r10
    jae .done
    movzx ecx, byte [r9 + r8]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul rax, rax, 10
    add rax, rcx
    inc r8
    jmp .digit
.done:
    ret

.not_found:
    xor rax, rax
    ret

; ============================================================
; parse_score_count_from_json — Wave 2 observable JSON parser.
;   In : rdi = body pointer, rsi = body length
;   Out: rax = count in 0..5
;
; This is deliberately a narrow, testable parser slice: it extracts the real
; `customer.tx_count_24h` field and maps it to one of the six response slots.
; Wave 3 expands this into the full 14-dimensional vectorization contract.
; ============================================================
parse_score_count_from_json:
    push rbx
    push r12

    mov rbx, rdi              ; body base
    mov r12, rsi              ; body length

    lea rdx, [rel tx_count_key]
    mov rcx, tx_count_key_len
    call find_bytes
    test rax, rax
    js .fallback_zero

    ; rax = offset of key. Move to byte after key and scan for ':'.
    add rax, tx_count_key_len
    mov rdi, rbx
    add rdi, rax              ; current ptr
    mov rsi, r12
    sub rsi, rax              ; remaining len
    call parse_u64_after_colon

    ; Clamp parsed integer into response count range 0..5.
    cmp rax, 5
    jbe .done
    mov eax, 5
    jmp .done

.fallback_zero:
    xor eax, eax

.done:
    pop r12
    pop rbx
    ret

; ============================================================
; find_bytes — naive exact substring search.
;   In : rdi = haystack ptr, rsi = haystack len, rdx = needle ptr, rcx = needle len
;   Out: rax = offset or -1
; ============================================================
find_bytes:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rdi              ; haystack
    mov r12, rsi              ; hay len
    mov r13, rdx              ; needle
    mov r14, rcx              ; needle len

    test r14, r14
    jz .found_zero
    cmp r12, r14
    jb .not_found

    mov r15, r12
    sub r15, r14              ; max start offset
    xor r8, r8                ; current offset

.outer:
    cmp r8, r15
    ja .not_found
    xor r9, r9                ; needle index

.inner:
    cmp r9, r14
    jae .found
    lea r10, [rbx + r8]
    mov al, [r10 + r9]
    cmp al, [r13 + r9]
    jne .next
    inc r9
    jmp .inner

.next:
    inc r8
    jmp .outer

.found_zero:
    xor eax, eax
    jmp .return

.found:
    mov rax, r8
    jmp .return

.not_found:
    mov rax, -1

.return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; parse_u64_after_colon — scan a short JSON suffix for ':' and parse uint.
;   In : rdi = ptr after key, rsi = remaining length
;   Out: rax = parsed integer, or 0 if missing/malformed
; ============================================================
parse_u64_after_colon:
    xor r8, r8

.find_colon:
    cmp r8, rsi
    jae .zero
    cmp byte [rdi + r8], ':'
    je .after_colon
    inc r8
    jmp .find_colon

.after_colon:
    inc r8

.skip_ws:
    cmp r8, rsi
    jae .zero
    mov al, [rdi + r8]
    cmp al, ' '
    je .skip_one
    cmp al, 9
    je .skip_one
    cmp al, 10
    je .skip_one
    cmp al, 13
    je .skip_one
    jmp .parse

.skip_one:
    inc r8
    jmp .skip_ws

.parse:
    xor rax, rax

.digit:
    cmp r8, rsi
    jae .done
    movzx ecx, byte [rdi + r8]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul rax, rax, 10
    add rax, rcx
    inc r8
    jmp .digit

.done:
    ret

.zero:
    xor eax, eax
    ret
