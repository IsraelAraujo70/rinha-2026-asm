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

section .data
socket_path_ptr: dq 0
socket_path_len: dq 0
index_loaded:      dq 0
index_format:      dq 0       ; 1=RINHA26 AoS32, 2=IVF6 AoS28+labels
index_base:        dq 0
index_len:         dq 0
index_count:       dq 0
index_clusters:    dq 0
centroids_ptr:     dq 0
cluster_offsets_ptr: dq 0
bbox_min_ptr:      dq 0
bbox_max_ptr:      dq 0
records_ptr:       dq 0
labels_ptr:        dq 0
ids_ptr:           dq 0
record_stride:     dq 0

section .bss
; Per-connection scratch. 16 KiB covers the largest payload we'll see (the
; Rinha references include ~500-byte JSON blobs; headers add ~200 bytes).
recv_buf:  resb 16384
sockaddr_un_buf: resb 110   ; sa_family_t + sun_path[108]
; Wave 3 quantized vector scratch: 16 i16 lanes so AVX2 can load one full ymm.
; Lanes 0..13 mirror the Rinha feature contract; lanes 14..15 stay zero.
query_i16: resw 16
best_dist: resq 5
best_label: resb 5
best_id: resd 5
cluster_best_dist: resq 8
cluster_best_id: resq 8
cluster_visited: resb 4096
dist_lanes: resd 8
dim_ptrs: resq 14
soa_tmp_lo: resq 4
soa_tmp_hi: resq 4
txn_ptr: resq 1
txn_len: resq 1
customer_ptr: resq 1
customer_len: resq 1
merchant_ptr: resq 1
merchant_len: resq 1
terminal_ptr: resq 1
terminal_len: resq 1
last_ptr: resq 1
last_len: resq 1
requested_at_ptr: resq 1
merchant_id_ptr: resq 1
merchant_id_len: resq 1
last_ts_ptr: resq 1

%include "responses.inc"

; Patterns for path matching and header search.
section .rodata
ready_path:    db '/ready '
ready_path_len equ $ - ready_path
fs_path:       db '/fraud-score '
fs_path_len    equ $ - fs_path
cl_pattern:    db "content-length:"
cl_pattern_len equ $ - cl_pattern
socket_path_prefix: db 'SOCKET_PATH='
socket_path_prefix_len equ $ - socket_path_prefix
tx_count_key:  db '"tx_count_24h"'
tx_count_key_len equ $ - tx_count_key
amount_key:    db '"amount"'
amount_key_len equ $ - amount_key
avg_amount_key: db '"avg_amount"'
avg_amount_key_len equ $ - avg_amount_key
installments_key: db '"installments"'
installments_key_len equ $ - installments_key
requested_at_key: db '"requested_at"'
requested_at_key_len equ $ - requested_at_key
transaction_key: db '"transaction"'
transaction_key_len equ $ - transaction_key
customer_key: db '"customer"'
customer_key_len equ $ - customer_key
merchant_key: db '"merchant"'
merchant_key_len equ $ - merchant_key
terminal_key: db '"terminal"'
terminal_key_len equ $ - terminal_key
id_key: db '"id"'
id_key_len equ $ - id_key
mcc_key: db '"mcc"'
mcc_key_len equ $ - mcc_key
known_merchants_key: db '"known_merchants"'
known_merchants_key_len equ $ - known_merchants_key
last_transaction_key: db '"last_transaction"'
last_transaction_key_len equ $ - last_transaction_key
timestamp_key: db '"timestamp"'
timestamp_key_len equ $ - timestamp_key
km_from_current_key: db '"km_from_current"'
km_from_current_key_len equ $ - km_from_current_key
km_from_home_key: db '"km_from_home"'
km_from_home_key_len equ $ - km_from_home_key
is_online_key: db '"is_online"'
is_online_key_len equ $ - is_online_key
card_present_key: db '"card_present"'
card_present_key_len equ $ - card_present_key
index_path: db '/index/data.bin', 0
index_magic: db 'RINHA26', 0
ivf6_magic: db 'IVF6'
f32_10000: dd 10000.0
weekday_month_offsets: db 0,3,2,5,0,3,5,1,4,6,2,4
month_days_before: dw 0,31,59,90,120,151,181,212,243,273,304,334
distance_mask_i16:
    times 14 dw -1
    times 2 dw 0

IVF_HEADER_LEN equ 32
IVF_VERSION equ 3
IVF6_HEADER_LEN equ 24
DIMS equ 14
IVF_RECORD_LEN equ 32
IVF6_RECORD_LEN equ 28

section .text

; ============================================================
; _start — setup listener, then accept-serve loop forever.
; ============================================================
_start:
    mov rdi, rsp
    call load_socket_path_from_env
    call load_index_optional

    cmp qword [rel socket_path_ptr], 0
    jne .setup_unix_socket

.setup_tcp_socket:
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
    jmp .accept_loop

.setup_unix_socket:
    mov eax, SYS_socket
    mov edi, AF_UNIX
    mov esi, SOCK_STREAM
    xor edx, edx
    syscall
    test rax, rax
    js .die
    mov r12, rax

    ; Best-effort unlink of stale socket path.
    mov eax, SYS_unlink
    mov rdi, [rel socket_path_ptr]
    syscall

    lea rdi, [rel sockaddr_un_buf]
    xor eax, eax
    mov ecx, 110
.clear_un:
    mov byte [rdi], 0
    inc rdi
    loop .clear_un

    lea rdi, [rel sockaddr_un_buf]
    mov word [rdi], AF_UNIX
    mov rsi, [rel socket_path_ptr]
    mov rcx, [rel socket_path_len]
    cmp rcx, 107
    jbe .path_len_ok
    mov ecx, 107
.path_len_ok:
    mov [rel socket_path_len], rcx
    lea rdi, [rel sockaddr_un_buf + 2]
.copy_path:
    test rcx, rcx
    jz .path_copied
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .copy_path
.path_copied:

    mov eax, SYS_bind
    mov rdi, r12
    lea rsi, [rel sockaddr_un_buf]
    mov rdx, [rel socket_path_len]
    add rdx, 3                ; family(2) + path bytes + trailing NUL
    syscall
    test rax, rax
    js .die

    mov eax, SYS_chmod
    mov rdi, [rel socket_path_ptr]
    mov esi, 438              ; 0666 octal
    syscall

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
; load_socket_path_from_env — parse initial stack envp for SOCKET_PATH.
;   In : rdi = initial rsp from _start
; ============================================================
load_socket_path_from_env:
    push rbx
    push r12
    push r13

    mov rbx, rdi
    mov rax, [rbx]            ; argc
    lea rbx, [rbx + 8 + rax * 8 + 8] ; envp = &argv[argc + 1]

.env_loop:
    mov r12, [rbx]
    test r12, r12
    jz .done
    mov rdi, r12
    lea rsi, [rel socket_path_prefix]
    mov rcx, socket_path_prefix_len
    call mem_prefix_eq
    test rax, rax
    jz .next

    lea r13, [r12 + socket_path_prefix_len]
    cmp byte [r13], 0
    je .next
    mov [rel socket_path_ptr], r13
    mov rdi, r13
    call strlen_asm
    mov [rel socket_path_len], rax
    jmp .done

.next:
    add rbx, 8
    jmp .env_loop

.done:
    pop r13
    pop r12
    pop rbx
    ret

; In: rdi=string, rsi=prefix, rcx=len. Out: rax=1 if equal.
mem_prefix_eq:
    test rcx, rcx
    jz .yes
.loop:
    mov al, [rdi]
    cmp al, [rsi]
    jne .no
    inc rdi
    inc rsi
    dec rcx
    jnz .loop
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

strlen_asm:
    xor rax, rax
.loop:
    cmp byte [rdi + rax], 0
    je .ret
    inc rax
    jmp .loop
.ret:
    ret

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
; Wave 3 fills a partial quantized vector from real payload fields and returns
; a temporary score bucket from those lanes. KNN will consume query_i16 later.
; ============================================================
parse_score_count_from_json:
    push rbx
    push r12

    mov rbx, rdi              ; body base
    mov r12, rsi              ; body length

    call vectorize_json_partial
    cmp qword [rel index_loaded], 1
    jne .heuristic
    call knn_count_first_clusters
    jmp .done

.heuristic:
    call heuristic_count_from_vector
    jmp .done

.fallback_zero:
    xor eax, eax

.done:
    pop r12
    pop rbx
    ret

; ============================================================
; vectorize_json_partial — fill all 14 Rinha feature lanes in quantized i16.
;   In : rbx = body base, r12 = body length
;   Out: query_i16 lanes updated
;
; Decimal parsing returns value*100. That is enough for the official payloads
; (amount/km averages are cents-ish), and lets the hot path stay fully integer.
; ============================================================
vectorize_json_partial:
    push r13
    push r14
    push r15
    push rbp

    ; Clear all 16 lanes.
    lea rdi, [rel query_i16]
    xor eax, eax
    mov ecx, 8
.clear:
    mov [rdi], rax
    add rdi, 8
    loop .clear

    mov word [rel query_i16 + 5 * 2], -10000
    mov word [rel query_i16 + 6 * 2], -10000

    ; Locate top-level object ranges first so duplicate field names do not
    ; collide (customer.avg_amount vs merchant.avg_amount, merchant.id vs tx id).
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel transaction_key]
    mov rcx, transaction_key_len
    call find_object_range
    test rax, rax
    jz .fallback_partial
    mov [rel txn_ptr], rax
    mov [rel txn_len], rdx

    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel customer_key]
    mov rcx, customer_key_len
    call find_object_range
    test rax, rax
    jz .fallback_partial
    mov [rel customer_ptr], rax
    mov [rel customer_len], rdx

    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel merchant_key]
    mov rcx, merchant_key_len
    call find_object_range
    test rax, rax
    jz .fallback_partial
    mov [rel merchant_ptr], rax
    mov [rel merchant_len], rdx

    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel terminal_key]
    mov rcx, terminal_key_len
    call find_object_range
    test rax, rax
    jz .fallback_partial
    mov [rel terminal_ptr], rax
    mov [rel terminal_len], rdx

    ; amount -> lane 0. quant_i16(clamp(amount/10000)) == round(amount).
    mov rdi, [rel txn_ptr]
    mov rsi, [rel txn_len]
    lea rdx, [rel amount_key]
    mov rcx, amount_key_len
    call find_key_decimal_x100_in_range
    mov r13, rax              ; amount * 100
    add rax, 50
    xor edx, edx
    mov ecx, 100
    div rcx
    cmp rax, 10000
    jbe .amount_ok
    mov eax, 10000
.amount_ok:
    mov [rel query_i16 + 0 * 2], ax

    ; installments -> lane 1 = clamp(installments / 12) * 10000.
    mov rdi, [rel txn_ptr]
    mov rsi, [rel txn_len]
    lea rdx, [rel installments_key]
    mov rcx, installments_key_len
    call find_key_decimal_x100_in_range
    cmp rax, 1200
    jbe .installments_ok
    mov eax, 1200
.installments_ok:
    imul rax, rax, 10000
    add rax, 600
    xor edx, edx
    mov ecx, 1200
    div rcx
    mov [rel query_i16 + 1 * 2], ax

    ; customer avg amount for lane 2.
    mov rdi, [rel customer_ptr]
    mov rsi, [rel customer_len]
    lea rdx, [rel avg_amount_key]
    mov rcx, avg_amount_key_len
    call find_key_decimal_x100_in_range
    test rax, rax
    jnz .avg_nonzero
    mov eax, 1                ; Rust clamps avg_amount to at least 0.01
.avg_nonzero:
    mov r14, rax              ; customer avg * 100

    ; lane 2 = clamp((amount / customer_avg) / 10) * 10000
    ;        = round(amount100 * 1000 / avg100)
    mov rax, r13
    imul rax, rax, 1000
    mov rcx, r14
    mov rdx, rcx
    shr rdx, 1
    add rax, rdx
    xor edx, edx
    div rcx
    cmp rax, 10000
    jbe .ratio_ok
    mov eax, 10000
.ratio_ok:
    mov [rel query_i16 + 2 * 2], ax

    ; requested_at -> lanes 3 (hour) and 4 (weekday).
    mov rdi, [rel txn_ptr]
    mov rsi, [rel txn_len]
    lea rdx, [rel requested_at_key]
    mov rcx, requested_at_key_len
    call find_key_string_in_range
    test rax, rax
    jz .date_done
    mov [rel requested_at_ptr], rax

    mov rdi, rax
    call iso_hour
    imul rax, rax, 10000
    add rax, 11
    xor edx, edx
    mov ecx, 23
    div rcx
    mov [rel query_i16 + 3 * 2], ax

    mov rdi, [rel requested_at_ptr]
    call iso_weekday_monday0
    imul rax, rax, 10000
    add rax, 3
    xor edx, edx
    mov ecx, 6
    div rcx
    mov [rel query_i16 + 4 * 2], ax
.date_done:

    ; Optional last_transaction object -> lanes 5/6. Null keeps -10000 sentinels.
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel last_transaction_key]
    mov rcx, last_transaction_key_len
    call find_object_range
    test rax, rax
    jz .last_done
    mov [rel last_ptr], rax
    mov [rel last_len], rdx

    mov rdi, [rel last_ptr]
    mov rsi, [rel last_len]
    lea rdx, [rel timestamp_key]
    mov rcx, timestamp_key_len
    call find_key_string_in_range
    test rax, rax
    jz .last_done
    mov [rel last_ts_ptr], rax

    mov rdi, [rel requested_at_ptr]
    call iso_epoch_minutes
    mov r15, rax
    mov rdi, [rel last_ts_ptr]
    call iso_epoch_minutes
    cmp r15, rax
    jae .mins_sub_ok
    xchg r15, rax
.mins_sub_ok:
    sub r15, rax
    mov rax, r15
    imul rax, rax, 10000
    add rax, 720
    xor edx, edx
    mov ecx, 1440
    div rcx
    cmp rax, 10000
    jbe .mins_ok
    mov eax, 10000
.mins_ok:
    mov [rel query_i16 + 5 * 2], ax

    mov rdi, [rel last_ptr]
    mov rsi, [rel last_len]
    lea rdx, [rel km_from_current_key]
    mov rcx, km_from_current_key_len
    call find_key_decimal_x100_in_range
    call quant_km_x100_to_i16
    mov [rel query_i16 + 6 * 2], ax
.last_done:

    ; km_from_home -> lane 7.
    mov rdi, [rel terminal_ptr]
    mov rsi, [rel terminal_len]
    lea rdx, [rel km_from_home_key]
    mov rcx, km_from_home_key_len
    call find_key_decimal_x100_in_range
    call quant_km_x100_to_i16
    mov [rel query_i16 + 7 * 2], ax

    ; tx_count_24h -> lane 8.
    mov rdi, [rel customer_ptr]
    mov rsi, [rel customer_len]
    lea rdx, [rel tx_count_key]
    mov rcx, tx_count_key_len
    call find_key_decimal_x100_in_range
    cmp rax, 2000
    jbe .tx_ok
    mov eax, 2000
.tx_ok:
    imul rax, rax, 10000
    add rax, 1000
    xor edx, edx
    mov ecx, 2000
    div rcx
    mov [rel query_i16 + 8 * 2], ax

    mov rdi, [rel terminal_ptr]
    mov rsi, [rel terminal_len]
    lea rdx, [rel is_online_key]
    mov rcx, is_online_key_len
    call find_key_bool_in_range
    test rax, rax
    jz .online_done
    mov word [rel query_i16 + 9 * 2], 10000
.online_done:

    mov rdi, [rel terminal_ptr]
    mov rsi, [rel terminal_len]
    lea rdx, [rel card_present_key]
    mov rcx, card_present_key_len
    call find_key_bool_in_range
    test rax, rax
    jz .card_done
    mov word [rel query_i16 + 10 * 2], 10000
.card_done:

    ; merchant.id + known_merchants -> lane 11 unknown merchant.
    mov rdi, [rel merchant_ptr]
    mov rsi, [rel merchant_len]
    lea rdx, [rel id_key]
    mov rcx, id_key_len
    call find_key_string_in_range
    test rax, rax
    jz .unknown_yes
    mov [rel merchant_id_ptr], rax
    mov [rel merchant_id_len], rdx

    mov rdi, [rel customer_ptr]
    mov rsi, [rel customer_len]
    mov rdx, [rel merchant_id_ptr]
    mov rcx, [rel merchant_id_len]
    call known_merchants_contains
    test rax, rax
    jnz .unknown_done
.unknown_yes:
    mov word [rel query_i16 + 11 * 2], 10000
.unknown_done:

    ; MCC risk -> lane 12.
    mov rdi, [rel merchant_ptr]
    mov rsi, [rel merchant_len]
    lea rdx, [rel mcc_key]
    mov rcx, mcc_key_len
    call find_key_string_in_range
    test rax, rax
    jz .mcc_default
    mov rdi, rax
    call mcc_risk_i16
    jmp .mcc_store
.mcc_default:
    mov eax, 5000
.mcc_store:
    mov [rel query_i16 + 12 * 2], ax

    ; merchant.avg_amount -> lane 13.
    mov rdi, [rel merchant_ptr]
    mov rsi, [rel merchant_len]
    lea rdx, [rel avg_amount_key]
    mov rcx, avg_amount_key_len
    call find_key_decimal_x100_in_range
    add rax, 50
    xor edx, edx
    mov ecx, 100
    div rcx
    cmp rax, 10000
    jbe .merchant_avg_ok
    mov eax, 10000
.merchant_avg_ok:
    mov [rel query_i16 + 13 * 2], ax

.ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    ret

.fallback_partial:
    ; Keep the zero/sentinel vector. Bad payloads should approve-fallback rather
    ; than throwing an HTTP error, matching the Rust behavior.
    jmp .ret

; ============================================================
; heuristic_count_from_vector — temporary bucket until IVF KNN is wired.
;   Out: rax = 0..5
; ============================================================
heuristic_count_from_vector:
    xor eax, eax

    ; amount contribution: +0..3 by amount lane.
    movsx ecx, word [rel query_i16 + 0 * 2]
    cmp ecx, 2000
    jb .amount_done
    inc eax
    cmp ecx, 5000
    jb .amount_done
    inc eax
    cmp ecx, 8000
    jb .amount_done
    inc eax
.amount_done:

    ; high 24h activity.
    movsx ecx, word [rel query_i16 + 8 * 2]
    cmp ecx, 2500             ; tx_count_24h >= 5
    jb .tx_done
    inc eax
.tx_done:

    ; online and card-not-present are riskier for this temporary heuristic.
    cmp word [rel query_i16 + 9 * 2], 10000
    jne .online_done
    inc eax
.online_done:
    cmp word [rel query_i16 + 10 * 2], 10000
    je .clamp
    inc eax

.clamp:
    cmp eax, 5
    jbe .ret
    mov eax, 5
.ret:
    ret

; ============================================================
; knn_count_first_clusters — scan the 8 closest IVF clusters.
;   Out: rax = number of fraud labels among the 5 nearest records in cluster 0
;
; Wave 7 selects probes by scalar centroid distance. The name remains for now
; to avoid a large churny rename in the route path.
; ============================================================
knn_count_first_clusters:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    ; Initialize best distances to UINT64_MAX and labels to 0.
    lea rdi, [rel best_dist]
    mov rax, -1
    mov ecx, 5
.init_dist:
    mov [rdi], rax
    add rdi, 8
    loop .init_dist

    lea rdi, [rel best_label]
    xor eax, eax
    mov ecx, 5
.init_label:
    mov [rdi], al
    inc rdi
    loop .init_label

    lea rdi, [rel best_id]
    mov eax, -1
    mov ecx, 5
.init_id:
    mov [rdi], eax
    add rdi, 4
    loop .init_id

    lea rdi, [rel cluster_visited]
    xor eax, eax
    mov ecx, 512              ; 4096 bytes / 8
.init_visited:
    mov [rdi], rax
    add rdi, 8
    loop .init_visited

    mov rbx, [rel cluster_offsets_ptr]
    test rbx, rbx
    jz .fallback_zero

    call select_top8_clusters

    xor ebp, ebp              ; cluster_id
    mov r15, [rel index_clusters]
    cmp r15, 1
    jbe .probe_limit_ok
    mov r15d, 1
.probe_limit_ok:
    test r15, r15
    jz .fallback_zero

.cluster_loop:
    cmp rbp, r15
    jae .repair

    lea r11, [rel cluster_best_id]
    mov rax, [r11 + rbp * 8]      ; selected cluster id
    lea r11, [rel cluster_visited]
    mov byte [r11 + rax], 1
    cmp qword [rel index_format], 3
    jne .not_sivf_selected
    mov rdi, rax
    call scan_cluster_id
    jmp .next_cluster
.not_sivf_selected:
    cmp qword [rel index_format], 2
    je .load_ivf6_offsets
    mov r12, [rbx + rax * 8]      ; start offset (RINHA26 u64)
    mov r13, [rbx + rax * 8 + 8]  ; end offset
    jmp .offsets_loaded

.load_ivf6_offsets:
    mov r12d, [rbx + rax * 4]     ; start offset (IVF6 u32)
    mov r13d, [rbx + rax * 4 + 4] ; end offset

.offsets_loaded:
    cmp r13, r12
    jbe .next_cluster

    mov r14, [rel records_ptr]
    mov rax, r12
    imul rax, [rel record_stride]
    add r14, rax                  ; current record ptr

    mov r10, r13
    sub r10, r12                  ; records remaining
    mov r11, r12                  ; current absolute record index

.record_loop:
    test r10, r10
    jz .next_cluster

    cmp qword [rel index_format], 2
    je .ivf6_label
    movzx esi, byte [r14 + 28]
    mov edx, r11d
    jmp .label_loaded

.ivf6_label:
    mov rax, [rel labels_ptr]
    movzx esi, byte [rax + r11]
    mov rax, [rel ids_ptr]
    mov edx, [rax + r11 * 4]

.label_loaded:
    mov rdi, r14
    push r10
    push r11
    push rsi
    push rdx
    call squared_distance_record_avx2
    pop rdx
    pop rsi
    pop r11
    pop r10
    mov rdi, rax
    push r10
    push r11
    call insert_best_u64_asm
    pop r11
    pop r10

    add r14, [rel record_stride]
    inc r11
    dec r10
    jmp .record_loop

.next_cluster:
    inc rbp
    jmp .cluster_loop

.repair:
    ; The scalar repair is exact but currently too slow under the official
    ; 900 rps k6 ramp, causing HTTP timeouts. Keep the implementation below for
    ; the optimized path, but default to the fast probe-only scan until repair
    ; gets an AVX2/queue-aware version.
    ; call bbox_repair_clusters

.score:
    xor eax, eax
    lea rdi, [rel best_label]
    mov ecx, 5
.count:
    cmp byte [rdi], 1
    jne .next_label
    inc eax
.next_label:
    inc rdi
    loop .count
    jmp .done

.fallback_zero:
    xor eax, eax

.done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; squared_distance_record_scalar — L2 over 14 i16 lanes.
;   In : rdi = IVF record ptr (14*i16 + label)
;   Out: rax = u64 squared distance
; ============================================================
squared_distance_record_scalar:
    push rbx
    xor rax, rax
    xor ecx, ecx
    lea rbx, [rel query_i16]

.loop:
    cmp ecx, DIMS
    jae .done
    movsx edx, word [rbx + rcx * 2]
    movsx esi, word [rdi + rcx * 2]
    sub edx, esi
    imul edx, edx
    movsxd rdx, edx
    add rax, rdx
    inc ecx
    jmp .loop

.done:
    pop rbx
    ret

; ============================================================
; squared_distance_record_avx2 — L2 over 14 i16 lanes via vpmaddwd.
;   In : rdi = IVF record ptr (14*i16 + label)
;   Out: rax = u64 squared distance
;
; Stores the eight i32 partial sums into dist_lanes, then zero-extends and
; sums in GPRs. That is intentionally straightforward; a pure register
; horizontal reduction can replace it once behavior is fully locked down.
; ============================================================
squared_distance_record_avx2:
    vmovdqu ymm0, [rel query_i16]
    vmovdqu ymm1, [rdi]
    vpand ymm1, ymm1, [rel distance_mask_i16]
    vpsubw ymm0, ymm0, ymm1
    vpmaddwd ymm0, ymm0, ymm0
    vmovdqu [rel dist_lanes], ymm0
    vzeroupper

    xor rax, rax
    xor ecx, ecx
    lea r8, [rel dist_lanes]
.sum:
    cmp ecx, 8
    jae .done
    mov edx, [r8 + rcx * 4]
    add rax, rdx
    inc ecx
    jmp .sum
.done:
    ret

; ============================================================
; insert_best_u64_asm — insert (dist,label,orig_id) into sorted top-5 arrays.
;   In : rdi = dist, sil = label, edx = orig_id
; ============================================================
insert_best_u64_asm:
    mov r10d, edx
    mov rax, [rel best_dist + 4 * 8]
    cmp rdi, rax
    ja .ret
    jb .candidate_better
    cmp r10d, [rel best_id + 4 * 4]
    jae .ret
.candidate_better:

    lea r8, [rel best_dist]
    lea r9, [rel best_label]
    lea r11, [rel best_id]
    mov ecx, 4
.shift_loop:
    test ecx, ecx
    jz .place
    mov rax, [r8 + rcx * 8 - 8]
    cmp rdi, rax
    ja .place
    jb .shift
    cmp r10d, [r11 + rcx * 4 - 4]
    jae .place
.shift:
    mov [r8 + rcx * 8], rax
    mov al, [r9 + rcx - 1]
    mov [r9 + rcx], al
    mov eax, [r11 + rcx * 4 - 4]
    mov [r11 + rcx * 4], eax
    dec ecx
    jmp .shift_loop

.place:
    mov [r8 + rcx * 8], rdi
    mov [r9 + rcx], sil
    mov [r11 + rcx * 4], r10d
.ret:
    ret

; ============================================================
; bbox_repair_clusters — scan unvisited clusters whose bbox can still beat
; the current worst top-5 distance.
; ============================================================
bbox_repair_clusters:
    push rbx
    push r14
    push r15

    mov r15, [rel index_clusters]
    xor r14, r14

.loop:
    cmp r14, r15
    jae .done
    lea rbx, [rel cluster_visited]
    cmp byte [rbx + r14], 0
    jne .next

    mov rdi, r14
    call bbox_lower_bound_asm
    cmp rax, [rel best_dist + 4 * 8]
    ja .next

    lea rbx, [rel cluster_visited]
    mov byte [rbx + r14], 1
    mov rdi, r14
    call scan_cluster_id

.next:
    inc r14
    jmp .loop

.done:
    pop r15
    pop r14
    pop rbx
    ret

; ============================================================
; bbox_lower_bound_asm — lower bound from query to cluster bbox.
;   In : rdi = cluster id
;   Out: rax = u64 lower bound
; ============================================================
bbox_lower_bound_asm:
    push rbx
    push r12
    push r13

    mov rbx, rdi
    imul rbx, DIMS * 2
    mov r12, [rel bbox_min_ptr]
    add r12, rbx
    mov r13, [rel bbox_max_ptr]
    add r13, rbx
    lea rbx, [rel query_i16]
    xor rax, rax
    xor ecx, ecx

.dim_loop:
    cmp ecx, DIMS
    jae .done
    movsx edx, word [rbx + rcx * 2]
    movsx esi, word [r12 + rcx * 2]
    cmp edx, esi
    jl .below
    movsx esi, word [r13 + rcx * 2]
    cmp edx, esi
    jg .above
    xor esi, esi
    jmp .accum
.below:
    sub esi, edx
    jmp .accum
.above:
    sub edx, esi
    mov esi, edx
.accum:
    imul esi, esi
    movsxd rsi, esi
    add rax, rsi
    inc ecx
    jmp .dim_loop

.done:
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; scan_cluster_id — scan one cluster into global best_dist/best_label.
;   In : rdi = cluster id
; ============================================================
scan_cluster_id:
    push rbx
    push r12
    push r13
    push r14
    push rbp

    mov rbp, rdi
    cmp qword [rel index_format], 3
    je .sivf
    mov rbx, [rel cluster_offsets_ptr]
    cmp qword [rel index_format], 2
    je .load_ivf6_offsets
    mov r12, [rbx + rbp * 8]
    mov r13, [rbx + rbp * 8 + 8]
    jmp .offsets_loaded

.load_ivf6_offsets:
    mov r12d, [rbx + rbp * 4]
    mov r13d, [rbx + rbp * 4 + 4]

.offsets_loaded:
    cmp r13, r12
    jbe .done
    mov r14, [rel records_ptr]
    mov rax, r12
    imul rax, [rel record_stride]
    add r14, rax
    mov r10, r13
    sub r10, r12
    mov r11, r12

.record_loop:
    test r10, r10
    jz .done
    cmp qword [rel index_format], 2
    je .ivf6_label
    movzx esi, byte [r14 + 28]
    mov edx, r11d
    jmp .label_loaded
.ivf6_label:
    mov rax, [rel labels_ptr]
    movzx esi, byte [rax + r11]
    mov rax, [rel ids_ptr]
    mov edx, [rax + r11 * 4]
.label_loaded:
    mov rdi, r14
    push r10
    push r11
    push rsi
    push rdx
    call squared_distance_record_avx2
    pop rdx
    pop rsi
    pop r11
    pop r10
    mov rdi, rax
    push r10
    push r11
    call insert_best_u64_asm
    pop r11
    pop r10
    add r14, [rel record_stride]
    inc r11
    dec r10
    jmp .record_loop

.done:
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.sivf:
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    jmp scan_cluster_soa_scalar

%macro ACC_SOA_DIM 1
    mov rax, [rel dim_ptrs + %1 * 8]
    movsx ecx, word [rax + r11 * 2]
    movsx eax, word [rel query_i16 + %1 * 2]
    sub eax, ecx
    imul eax, eax
    cdqe
    add r8, rax
    cmp r8, [rel best_dist + 4 * 8]
    ja .skip_record
%endmacro

%macro ACC_SOA_DIM8 1
    movsx eax, word [rel query_i16 + %1 * 2]
    vmovd xmm2, eax
    vpbroadcastd ymm2, xmm2
    mov rax, [rel dim_ptrs + %1 * 8]
    vmovdqu xmm0, [rax + r11 * 2]
    vpmovsxwd ymm1, xmm0
    vpsubd ymm1, ymm1, ymm2
    vpmulld ymm1, ymm1, ymm1
    vpmovsxdq ymm3, xmm1
    vextracti128 xmm4, ymm1, 1
    vpmovsxdq ymm4, xmm4
    vpaddq ymm5, ymm5, ymm3
    vpaddq ymm6, ymm6, ymm4
%endmacro

; ============================================================
; scan_cluster_soa_avx2 — SIVF scan, eight records per vector chunk.
;   In : rdi = cluster id
; ============================================================
scan_cluster_soa_avx2:
    push rbx
    push r12
    push r13
    push r14
    push rbp

    mov rbp, rdi
    mov rbx, [rel cluster_offsets_ptr]
    mov r12d, [rbx + rbp * 4]      ; start
    mov r13d, [rbx + rbp * 4 + 4]  ; end
    cmp r13, r12
    jbe .done

    mov r14, r13
    sub r14, r12
    and r14, -8
    add r14, r12                   ; vector loop limit
    mov r11, r12

.vec_loop:
    cmp r11, r14
    jae .tail
    vpxor ymm5, ymm5, ymm5
    vpxor ymm6, ymm6, ymm6

    ACC_SOA_DIM8 5
    ACC_SOA_DIM8 6
    ACC_SOA_DIM8 2
    ACC_SOA_DIM8 0
    ACC_SOA_DIM8 7
    ACC_SOA_DIM8 8
    ACC_SOA_DIM8 11
    ACC_SOA_DIM8 12
    ACC_SOA_DIM8 9
    ACC_SOA_DIM8 10
    ACC_SOA_DIM8 1
    ACC_SOA_DIM8 13
    ACC_SOA_DIM8 3
    ACC_SOA_DIM8 4

    vmovdqu [rel soa_tmp_lo], ymm5
    vmovdqu [rel soa_tmp_hi], ymm6
    vzeroupper

    xor ecx, ecx
.lo_lanes:
    cmp ecx, 4
    jae .hi_start
    lea r9, [rel soa_tmp_lo]
    mov rdi, [r9 + rcx * 8]
    mov rax, [rel ids_ptr]
    lea r8, [r11 + rcx]
    mov edx, [rax + r8 * 4]
    mov rax, [rel labels_ptr]
    movzx esi, byte [rax + r8]
    push rcx
    push r11
    call insert_best_u64_asm
    pop r11
    pop rcx
    inc ecx
    jmp .lo_lanes

.hi_start:
    xor ecx, ecx
.hi_lanes:
    cmp ecx, 4
    jae .next_vec
    lea r9, [rel soa_tmp_hi]
    mov rdi, [r9 + rcx * 8]
    mov rax, [rel ids_ptr]
    lea r8, [r11 + 4 + rcx]
    mov edx, [rax + r8 * 4]
    mov rax, [rel labels_ptr]
    movzx esi, byte [rax + r8]
    push rcx
    push r11
    call insert_best_u64_asm
    pop r11
    pop rcx
    inc ecx
    jmp .hi_lanes

.next_vec:
    add r11, 8
    jmp .vec_loop

.tail:
    cmp r11, r13
    jae .done
    ; Tail uses the same early-exit scalar logic for the final 0..7 records.
.tail_loop:
    cmp r11, r13
    jae .done
    xor r8, r8
    ACC_SOA_DIM 5
    ACC_SOA_DIM 6
    ACC_SOA_DIM 2
    ACC_SOA_DIM 0
    ACC_SOA_DIM 7
    ACC_SOA_DIM 8
    ACC_SOA_DIM 11
    ACC_SOA_DIM 12
    ACC_SOA_DIM 9
    ACC_SOA_DIM 10
    ACC_SOA_DIM 1
    ACC_SOA_DIM 13
    ACC_SOA_DIM 3
    ACC_SOA_DIM 4

    mov rax, [rel labels_ptr]
    movzx esi, byte [rax + r11]
    mov rax, [rel ids_ptr]
    mov edx, [rax + r11 * 4]
    mov rdi, r8
    push r11
    push r13
    call insert_best_u64_asm
    pop r13
    pop r11

.skip_record:
    inc r11
    jmp .tail_loop

.done:
    vzeroupper
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; scan_cluster_soa_scalar — SIVF scan with early-exit dimension order.
;   In : rdi = cluster id
; ============================================================
scan_cluster_soa_scalar:
    push rbx
    push r12
    push r13
    push r14
    push rbp

    mov rbp, rdi
    mov rbx, [rel cluster_offsets_ptr]
    mov r12d, [rbx + rbp * 4]
    mov r13d, [rbx + rbp * 4 + 4]
    cmp r13, r12
    jbe .done

    mov r11, r12
.record_loop:
    cmp r11, r13
    jae .done
    xor r8, r8                ; distance accumulator

    ACC_SOA_DIM 5
    ACC_SOA_DIM 6
    ACC_SOA_DIM 2
    ACC_SOA_DIM 0
    ACC_SOA_DIM 7
    ACC_SOA_DIM 8
    ACC_SOA_DIM 11
    ACC_SOA_DIM 12
    ACC_SOA_DIM 9
    ACC_SOA_DIM 10
    ACC_SOA_DIM 1
    ACC_SOA_DIM 13
    ACC_SOA_DIM 3
    ACC_SOA_DIM 4

    mov rax, [rel labels_ptr]
    movzx esi, byte [rax + r11]
    mov rax, [rel ids_ptr]
    mov edx, [rax + r11 * 4]
    mov rdi, r8
    push r11
    push r13
    call insert_best_u64_asm
    pop r13
    pop r11

.skip_record:
    inc r11
    jmp .record_loop

.done:
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; select_top8_clusters — choose closest centroid ids into cluster_best_id.
;   Uses scalar SSE to convert centroid f32 lanes to i16 scale on the fly.
; ============================================================
select_top8_clusters:
    push rbx
    push r12
    push r13
    push r14
    push r15

    lea rdi, [rel cluster_best_dist]
    mov rax, -1
    mov ecx, 8
.init_dist:
    mov [rdi], rax
    add rdi, 8
    loop .init_dist

    lea rdi, [rel cluster_best_id]
    xor eax, eax
    mov ecx, 8
.init_id:
    mov [rdi], rax
    add rdi, 8
    loop .init_id

    mov r12, [rel index_clusters]
    xor r13, r13              ; cluster id

.loop:
    cmp r13, r12
    jae .done
    mov rdi, r13
    call centroid_distance_scalar
    mov rdi, rax              ; distance
    mov rsi, r13              ; cluster id
    call insert_best_cluster_asm
    inc r13
    jmp .loop

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; centroid_distance_scalar — integer distance to centroid[cluster_id].
;   In : rdi = cluster_id
;   Out: rax = u64 squared distance in i16 scale
; ============================================================
centroid_distance_scalar:
    push rbx
    push r12

    mov rbx, [rel centroids_ptr]
    mov rax, rdi
    imul rax, DIMS * 4
    add rbx, rax              ; centroid ptr

    lea r12, [rel query_i16]
    xor rax, rax
    xor ecx, ecx

.loop:
    cmp ecx, DIMS
    jae .done

    movss xmm0, dword [rbx + rcx * 4]
    mulss xmm0, dword [rel f32_10000]
    cvttss2si edx, xmm0       ; centroid lane scaled to i16-ish integer
    movsx esi, word [r12 + rcx * 2]
    sub esi, edx
    imul esi, esi
    movsxd rsi, esi
    add rax, rsi

    inc ecx
    jmp .loop

.done:
    pop r12
    pop rbx
    ret

; ============================================================
; insert_best_cluster_asm — sorted top-8 insert for (dist, cluster_id).
;   In : rdi = distance, rsi = cluster id
; ============================================================
insert_best_cluster_asm:
    cmp rdi, [rel cluster_best_dist + 7 * 8]
    jae .ret

    lea r8, [rel cluster_best_dist]
    lea r9, [rel cluster_best_id]
    mov ecx, 7
.shift_loop:
    test ecx, ecx
    jz .place
    mov rax, [r8 + rcx * 8 - 8]
    cmp rdi, rax
    jae .place
    mov [r8 + rcx * 8], rax
    mov rax, [r9 + rcx * 8 - 8]
    mov [r9 + rcx * 8], rax
    dec ecx
    jmp .shift_loop

.place:
    mov [r8 + rcx * 8], rdi
    mov [r9 + rcx * 8], rsi
.ret:
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
; find_object_range — find `"key": { ... }` inside a byte range.
;   In : rdi = range ptr, rsi = range len, rdx = key ptr, rcx = key len
;   Out: rax = object ptr or 0, rdx = object len including braces
; ============================================================
find_object_range:
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi
    mov r12, rsi
    mov r13, rcx
    call find_bytes
    test rax, rax
    js .zero

    add rax, r13
    cmp rax, r12
    jae .zero
    mov r8, rax

.find_colon:
    cmp r8, r12
    jae .zero
    cmp byte [rbx + r8], ':'
    je .after_colon
    inc r8
    jmp .find_colon

.after_colon:
    inc r8
.skip_ws:
    cmp r8, r12
    jae .zero
    mov al, [rbx + r8]
    cmp al, ' '
    je .ws
    cmp al, 9
    je .ws
    cmp al, 10
    je .ws
    cmp al, 13
    je .ws
    cmp al, '{'
    jne .zero
    lea r14, [rbx + r8]
    mov rdi, r14
    mov rsi, r12
    sub rsi, r8
    call matching_brace_len
    test rax, rax
    jz .zero
    mov rdx, rax
    mov rax, r14
    jmp .ret
.ws:
    inc r8
    jmp .skip_ws

.zero:
    xor eax, eax
    xor edx, edx
.ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; matching_brace_len — return byte length of a JSON object.
;   In : rdi = pointer at '{', rsi = max len
;   Out: rax = length through matching '}', or 0
; ============================================================
matching_brace_len:
    xor ecx, ecx              ; offset
    xor edx, edx              ; depth
    xor r8d, r8d              ; in_string
    xor r9d, r9d              ; escaped

.loop:
    cmp rcx, rsi
    jae .zero
    mov al, [rdi + rcx]
    test r8d, r8d
    jz .not_string
    test r9d, r9d
    jz .string_normal
    xor r9d, r9d
    jmp .next
.string_normal:
    cmp al, '\'
    jne .not_escape
    mov r9d, 1
    jmp .next
.not_escape:
    cmp al, '"'
    jne .next
    xor r8d, r8d
    jmp .next

.not_string:
    cmp al, '"'
    jne .not_quote
    mov r8d, 1
    jmp .next
.not_quote:
    cmp al, '{'
    jne .not_open
    inc edx
    jmp .next
.not_open:
    cmp al, '}'
    jne .next
    dec edx
    jnz .next
    lea rax, [rcx + 1]
    ret
.next:
    inc rcx
    jmp .loop
.zero:
    xor eax, eax
    ret

; ============================================================
; find_key_decimal_x100_in_range — find a key and parse number*100.
;   In : rdi = range ptr, rsi = range len, rdx = key ptr, rcx = key len
;   Out: rax = unsigned decimal scaled by 100, or 0
; ============================================================
find_key_decimal_x100_in_range:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rcx
    call find_bytes
    test rax, rax
    js .zero
    add rax, r13
    lea rdi, [rbx + rax]
    mov rsi, r12
    sub rsi, rax
    call parse_decimal_x100_after_colon
    jmp .ret
.zero:
    xor eax, eax
.ret:
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; parse_decimal_x100_after_colon — parse JSON number after ':' into value*100.
;   In : rdi = ptr after key, rsi = remaining len
;   Out: rax = value*100, rounded on the third decimal digit
; ============================================================
parse_decimal_x100_after_colon:
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
    je .ws
    cmp al, 9
    je .ws
    cmp al, 10
    je .ws
    cmp al, 13
    je .ws
    jmp .parse_int
.ws:
    inc r8
    jmp .skip_ws

.parse_int:
    xor rax, rax
.int_digit:
    cmp r8, rsi
    jae .scale_no_frac
    movzx ecx, byte [rdi + r8]
    sub ecx, '0'
    cmp ecx, 9
    ja .after_int
    imul rax, rax, 10
    add rax, rcx
    inc r8
    jmp .int_digit
.after_int:
    imul rax, rax, 100
    cmp byte [rdi + r8], '.'
    jne .done
    inc r8
    xor r9d, r9d              ; frac accumulator (two digits)
    xor r10d, r10d            ; digit count
.frac_loop:
    cmp r8, rsi
    jae .frac_finish
    movzx ecx, byte [rdi + r8]
    sub ecx, '0'
    cmp ecx, 9
    ja .frac_finish
    cmp r10d, 2
    jae .round_digit
    imul r9d, r9d, 10
    add r9d, ecx
    inc r10d
    inc r8
    jmp .frac_loop
.round_digit:
    cmp ecx, 5
    jb .frac_finish
    inc r9d
    jmp .frac_finish
.frac_finish:
    cmp r10d, 0
    je .done
    cmp r10d, 1
    jne .frac_add
    imul r9d, r9d, 10
.frac_add:
    add rax, r9
    ret
.scale_no_frac:
    imul rax, rax, 100
.done:
    ret
.zero:
    xor eax, eax
    ret

; ============================================================
; find_key_string_in_range — find string value after key.
;   In : rdi = range ptr, rsi = range len, rdx = key ptr, rcx = key len
;   Out: rax = string bytes ptr or 0, rdx = string len
; ============================================================
find_key_string_in_range:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rcx
    call find_bytes
    test rax, rax
    js .zero
    add rax, r13
    mov r8, rax
.find_colon:
    cmp r8, r12
    jae .zero
    cmp byte [rbx + r8], ':'
    je .after_colon
    inc r8
    jmp .find_colon
.after_colon:
    inc r8
.skip_ws:
    cmp r8, r12
    jae .zero
    mov al, [rbx + r8]
    cmp al, ' '
    je .ws
    cmp al, 9
    je .ws
    cmp al, 10
    je .ws
    cmp al, 13
    je .ws
    cmp al, '"'
    jne .zero
    inc r8
    lea rax, [rbx + r8]
    xor edx, edx
.str_loop:
    cmp r8, r12
    jae .zero
    cmp byte [rbx + r8], '"'
    je .ret
    inc edx
    inc r8
    jmp .str_loop
.ws:
    inc r8
    jmp .skip_ws
.zero:
    xor eax, eax
    xor edx, edx
.ret:
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; find_key_bool_in_range — find a key and parse true/false.
;   In : rdi = range ptr, rsi = range len, rdx = key ptr, rcx = key len
;   Out: rax = 1 for true, 0 otherwise
; ============================================================
find_key_bool_in_range:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rcx
    call find_bytes
    test rax, rax
    js .false
    add rax, r13
    lea rdi, [rbx + rax]
    mov rsi, r12
    sub rsi, rax
    call parse_bool_after_colon
    jmp .ret
.false:
    xor eax, eax
.ret:
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; known_merchants_contains — scan known_merchants array for merchant id.
;   In : rdi = customer ptr, rsi = customer len, rdx = needle ptr, rcx = len
;   Out: rax = 1 if found, 0 otherwise
; ============================================================
known_merchants_contains:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    lea rdx, [rel known_merchants_key]
    mov rcx, known_merchants_key_len
    call find_bytes
    test rax, rax
    js .false
    add rax, known_merchants_key_len
    mov r8, rax
.find_lbracket:
    cmp r8, r12
    jae .false
    cmp byte [rbx + r8], '['
    je .array
    inc r8
    jmp .find_lbracket
.array:
    inc r8
.next_item:
    cmp r8, r12
    jae .false
    mov al, [rbx + r8]
    cmp al, ']'
    je .false
    cmp al, '"'
    je .string
    inc r8
    jmp .next_item
.string:
    inc r8
    lea r15, [rbx + r8]
    xor r9d, r9d
.string_len:
    cmp r8, r12
    jae .false
    cmp byte [rbx + r8], '"'
    je .compare
    inc r9
    inc r8
    jmp .string_len
.compare:
    cmp r9, r14
    jne .skip_string
    xor r10, r10
.cmp_loop:
    cmp r10, r14
    jae .true
    mov al, [r15 + r10]
    cmp al, [r13 + r10]
    jne .skip_string
    inc r10
    jmp .cmp_loop
.skip_string:
    inc r8
    jmp .next_item
.true:
    mov eax, 1
    jmp .ret
.false:
    xor eax, eax
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; quant_km_x100_to_i16 — q = round((km/1000)*10000) = round(km*10).
;   In : rax = km * 100
;   Out: rax = 0..10000
; ============================================================
quant_km_x100_to_i16:
    add rax, 5
    xor edx, edx
    mov ecx, 10
    div rcx
    cmp rax, 10000
    jbe .ret
    mov eax, 10000
.ret:
    ret

; ============================================================
; ISO helpers for fixed UTC strings: YYYY-MM-DDTHH:MM:SSZ
; ============================================================
iso_year:
    movzx eax, byte [rdi]
    sub eax, '0'
    imul eax, eax, 1000
    movzx ecx, byte [rdi + 1]
    sub ecx, '0'
    imul ecx, ecx, 100
    add eax, ecx
    movzx ecx, byte [rdi + 2]
    sub ecx, '0'
    imul ecx, ecx, 10
    add eax, ecx
    movzx ecx, byte [rdi + 3]
    sub ecx, '0'
    add eax, ecx
    ret

iso_month:
    movzx eax, byte [rdi + 5]
    sub eax, '0'
    imul eax, eax, 10
    movzx ecx, byte [rdi + 6]
    sub ecx, '0'
    add eax, ecx
    ret

iso_day:
    movzx eax, byte [rdi + 8]
    sub eax, '0'
    imul eax, eax, 10
    movzx ecx, byte [rdi + 9]
    sub ecx, '0'
    add eax, ecx
    ret

iso_hour:
    movzx eax, byte [rdi + 11]
    sub eax, '0'
    imul eax, eax, 10
    movzx ecx, byte [rdi + 12]
    sub ecx, '0'
    add eax, ecx
    cmp eax, 23
    jbe .ret
    mov eax, 23
.ret:
    ret

iso_minute:
    movzx eax, byte [rdi + 14]
    sub eax, '0'
    imul eax, eax, 10
    movzx ecx, byte [rdi + 15]
    sub ecx, '0'
    add eax, ecx
    ret

is_leap_year:
    ; In eax = year, out eax = 1 if leap, 0 otherwise.
    push rbx
    mov ebx, eax
    xor edx, edx
    mov ecx, 4
    div ecx
    test edx, edx
    jnz .no
    mov eax, ebx
    xor edx, edx
    mov ecx, 100
    div ecx
    test edx, edx
    jnz .yes
    mov eax, ebx
    xor edx, edx
    mov ecx, 400
    div ecx
    test edx, edx
    jz .yes
.no:
    xor eax, eax
    pop rbx
    ret
.yes:
    mov eax, 1
    pop rbx
    ret

iso_day_number:
    ; Days since Gregorian year 1-01-01, enough for absolute differences.
    push rbx
    push r12
    push r13
    mov r13, rdi
    call iso_year
    mov r12d, eax             ; year
    mov ebx, eax
    dec ebx                   ; prior years

    mov eax, ebx
    imul rax, rax, 365
    mov r8, rax
    mov eax, ebx
    xor edx, edx
    mov ecx, 4
    div ecx
    add r8, rax
    mov eax, ebx
    xor edx, edx
    mov ecx, 100
    div ecx
    sub r8, rax
    mov eax, ebx
    xor edx, edx
    mov ecx, 400
    div ecx
    add r8, rax

    mov rdi, r13
    call iso_month
    mov r9d, eax              ; month
    lea r10, [rel month_days_before]
    movzx eax, word [r10 + r9 * 2 - 2]
    add r8, rax
    cmp r9d, 2
    jbe .no_leap_day
    mov eax, r12d
    call is_leap_year
    add r8, rax
.no_leap_day:
    mov rdi, r13
    call iso_day
    dec rax
    add r8, rax
    mov rax, r8
    pop r13
    pop r12
    pop rbx
    ret

iso_epoch_minutes:
    push rbx
    mov rbx, rdi
    call iso_day_number
    imul rax, rax, 1440
    mov r8, rax
    mov rdi, rbx
    call iso_hour
    imul rax, rax, 60
    add r8, rax
    mov rdi, rbx
    call iso_minute
    add r8, rax
    mov rax, r8
    pop rbx
    ret

iso_weekday_monday0:
    ; Sakamoto: Sunday=0, convert to Monday=0.
    push rbx
    push r12
    push r13
    mov r13, rdi
    call iso_year
    mov ebx, eax
    mov rdi, r13
    call iso_month
    mov r12d, eax
    mov rdi, r13
    call iso_day
    mov r13d, eax
    cmp r12d, 3
    jae .year_ok
    dec ebx
.year_ok:
    mov eax, ebx
    mov r8d, eax
    xor edx, edx
    mov ecx, 4
    div ecx
    add r8d, eax
    mov eax, ebx
    xor edx, edx
    mov ecx, 100
    div ecx
    sub r8d, eax
    mov eax, ebx
    xor edx, edx
    mov ecx, 400
    div ecx
    add r8d, eax
    lea r10, [rel weekday_month_offsets]
    movzx eax, byte [r10 + r12 - 1]
    add r8d, eax
    add r8d, r13d
    mov eax, r8d
    xor edx, edx
    mov ecx, 7
    div ecx
    ; edx = Sunday0. Monday0 = (edx + 6) % 7.
    lea eax, [rdx + 6]
    xor edx, edx
    mov ecx, 7
    div ecx
    mov eax, edx
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; mcc_risk_i16 — hard-coded official MCC table, default 5000.
;   In : rdi = ptr to first char of 4-digit MCC string
;   Out: rax = quantized risk in 0..10000
; ============================================================
mcc_risk_i16:
    movzx eax, byte [rdi]
    sub eax, '0'
    imul eax, eax, 1000
    movzx ecx, byte [rdi + 1]
    sub ecx, '0'
    imul ecx, ecx, 100
    add eax, ecx
    movzx ecx, byte [rdi + 2]
    sub ecx, '0'
    imul ecx, ecx, 10
    add eax, ecx
    movzx ecx, byte [rdi + 3]
    sub ecx, '0'
    add eax, ecx
    cmp eax, 5411
    je .r5411
    cmp eax, 5812
    je .r5812
    cmp eax, 5912
    je .r5912
    cmp eax, 5944
    je .r5944
    cmp eax, 7801
    je .r7801
    cmp eax, 7802
    je .r7802
    cmp eax, 7995
    je .r7995
    cmp eax, 4511
    je .r4511
    cmp eax, 5311
    je .r5311
    mov eax, 5000
    ret
.r5411:
    mov eax, 1500
    ret
.r5812:
    mov eax, 3000
    ret
.r5912:
    mov eax, 2000
    ret
.r5944:
    mov eax, 4500
    ret
.r7801:
    mov eax, 8000
    ret
.r7802:
    mov eax, 7500
    ret
.r7995:
    mov eax, 8500
    ret
.r4511:
    mov eax, 3500
    ret
.r5311:
    mov eax, 2500
    ret

; ============================================================
; find_key_number — find a JSON key and parse the unsigned number after ':'.
;   In : rbx = body ptr, r12 = body len, rdx = key ptr, rcx = key len
;   Out: rax = integer part of the number, or 0 if absent/malformed
; ============================================================
find_key_number:
    push rdx
    push rcx
    mov rdi, rbx
    mov rsi, r12
    call find_bytes
    pop rcx
    pop rdx
    test rax, rax
    js .zero

    add rax, rcx
    mov rdi, rbx
    add rdi, rax
    mov rsi, r12
    sub rsi, rax
    call parse_u64_after_colon
    ret
.zero:
    xor eax, eax
    ret

; ============================================================
; find_key_bool — find a JSON key and parse true/false after ':'.
;   In : rbx = body ptr, r12 = body len, rdx = key ptr, rcx = key len
;   Out: rax = 1 for true, 0 for false/absent/malformed
; ============================================================
find_key_bool:
    push rdx
    push rcx
    mov rdi, rbx
    mov rsi, r12
    call find_bytes
    pop rcx
    pop rdx
    test rax, rax
    js .false

    add rax, rcx
    mov rdi, rbx
    add rdi, rax
    mov rsi, r12
    sub rsi, rax
    call parse_bool_after_colon
    ret
.false:
    xor eax, eax
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

; ============================================================
; parse_bool_after_colon — scan a JSON suffix for ':' and parse true/false.
;   In : rdi = ptr after key, rsi = remaining length
;   Out: rax = 1 for true, 0 otherwise
; ============================================================
parse_bool_after_colon:
    xor r8, r8

.find_colon:
    cmp r8, rsi
    jae .false
    cmp byte [rdi + r8], ':'
    je .after_colon
    inc r8
    jmp .find_colon

.after_colon:
    inc r8

.skip_ws:
    cmp r8, rsi
    jae .false
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
    ; Need at least "true".
    mov rax, rsi
    sub rax, r8
    cmp rax, 4
    jb .false
    cmp byte [rdi + r8], 't'
    jne .false
    cmp byte [rdi + r8 + 1], 'r'
    jne .false
    cmp byte [rdi + r8 + 2], 'u'
    jne .false
    cmp byte [rdi + r8 + 3], 'e'
    jne .false
    mov eax, 1
    ret
.false:
    xor eax, eax
    ret

; ============================================================
; load_index_optional — mmap /index/data.bin if present.
; Supports:
;   - RINHA26 IVF v3: old experiment format, AoS32 records with label inline
;   - IVF6: competitive K=256 format used by the public C top implementation,
;           AoS28 vectors followed by labels and original ids
;   Startup intentionally keeps serving if the file is absent while the early
;   waves still use heuristic scoring. Once KNN is wired, absence becomes fatal.
; ============================================================
load_index_optional:
    push rbx
    push r12
    push r13
    push r14

    mov qword [rel index_loaded], 0

    mov eax, SYS_open
    lea rdi, [rel index_path]
    mov esi, O_RDONLY
    xor edx, edx
    syscall
    test rax, rax
    js .return
    mov rbx, rax              ; fd

    mov eax, SYS_lseek
    mov rdi, rbx
    xor esi, esi
    mov edx, SEEK_END
    syscall
    test rax, rax
    jle .close_return
    mov r12, rax              ; file length

    mov eax, SYS_lseek
    mov rdi, rbx
    xor esi, esi
    mov edx, SEEK_SET
    syscall

    mov eax, SYS_mmap
    xor edi, edi              ; addr = NULL
    mov rsi, r12              ; len
    mov edx, PROT_READ
    mov r10d, MAP_PRIVATE
    mov r8, rbx               ; fd
    xor r9d, r9d              ; offset
    syscall
    ; Linux returns -errno in [-4095,-1].
    cmp rax, -4095
    jae .close_return
    mov r13, rax              ; mmap base

    mov eax, SYS_close
    mov rdi, rbx
    syscall

    cmp r12, IVF_HEADER_LEN
    jb .return

    cmp dword [r13], 0x46564953    ; "SIVF" (SoA IVF6)
    je .parse_sivf
    cmp dword [r13], 0x36465649    ; "IVF6"
    je .parse_ivf6

.parse_rinha26:
    mov rax, [r13]
    cmp rax, [rel index_magic]
    jne .return
    cmp dword [r13 + 8], IVF_VERSION
    jne .return
    cmp dword [r13 + 12], DIMS
    jne .return

    mov rax, [r13 + 16]
    mov [rel index_count], rax
    mov eax, [r13 + 24]
    test eax, eax
    jz .return
    mov [rel index_clusters], rax

    ; centroids_ptr = base + 32
    lea r14, [r13 + IVF_HEADER_LEN]
    mov [rel centroids_ptr], r14

    ; cluster_offsets_ptr = centroids + clusters * DIMS * sizeof(f32)
    mov rax, [rel index_clusters]
    imul rax, DIMS * 4
    add r14, rax
    mov [rel cluster_offsets_ptr], r14

    ; bbox_min_ptr = offsets + (clusters + 1) * sizeof(u64)
    mov rax, [rel index_clusters]
    inc rax
    shl rax, 3
    add r14, rax
    mov [rel bbox_min_ptr], r14

    ; bbox_max_ptr = bbox_min + clusters * DIMS * sizeof(i16)
    mov rax, [rel index_clusters]
    imul rax, DIMS * 2
    add r14, rax
    mov [rel bbox_max_ptr], r14

    ; records_ptr = bbox_max + clusters * DIMS * sizeof(i16)
    mov rax, [rel index_clusters]
    imul rax, DIMS * 2
    add r14, rax
    mov [rel records_ptr], r14
    mov qword [rel labels_ptr], 0
    mov qword [rel ids_ptr], 0
    mov qword [rel record_stride], IVF_RECORD_LEN

    mov [rel index_base], r13
    mov [rel index_len], r12
    mov qword [rel index_format], 1
    mov qword [rel index_loaded], 1
    jmp .return

.parse_ivf6:
    cmp r12, IVF6_HEADER_LEN
    jb .return
    cmp dword [r13 + 12], DIMS     ; d
    jne .return
    cmp dword [r13 + 16], DIMS     ; stride
    jne .return

    mov eax, [r13 + 4]             ; n
    test eax, eax
    jz .return
    mov [rel index_count], rax
    mov eax, [r13 + 8]             ; k
    test eax, eax
    jz .return
    mov [rel index_clusters], rax

    lea r14, [r13 + IVF6_HEADER_LEN]
    mov [rel centroids_ptr], r14

    mov rax, [rel index_clusters]
    imul rax, DIMS * 4
    add r14, rax
    mov [rel bbox_min_ptr], r14

    mov rax, [rel index_clusters]
    imul rax, DIMS * 2
    add r14, rax
    mov [rel bbox_max_ptr], r14

    mov rax, [rel index_clusters]
    imul rax, DIMS * 2
    add r14, rax
    mov [rel cluster_offsets_ptr], r14

    mov rax, [rel index_clusters]
    inc rax
    shl rax, 2                    ; IVF6 offsets are u32
    add r14, rax
    mov [rel records_ptr], r14

    mov rax, [rel index_count]
    imul rax, DIMS * 2
    add r14, rax
    mov [rel labels_ptr], r14

    mov rax, [rel index_count]
    add r14, rax
    mov [rel ids_ptr], r14

    mov qword [rel record_stride], IVF6_RECORD_LEN
    mov [rel index_base], r13
    mov [rel index_len], r12
    mov qword [rel index_format], 2
    mov qword [rel index_loaded], 1
    jmp .return

.parse_sivf:
    cmp r12, IVF6_HEADER_LEN
    jb .return
    cmp dword [r13 + 12], DIMS
    jne .return
    cmp dword [r13 + 16], DIMS
    jne .return

    mov eax, [r13 + 4]
    test eax, eax
    jz .return
    mov [rel index_count], rax
    mov eax, [r13 + 8]
    test eax, eax
    jz .return
    mov [rel index_clusters], rax

    lea r14, [r13 + IVF6_HEADER_LEN]
    mov [rel centroids_ptr], r14

    mov rax, [rel index_clusters]
    imul rax, DIMS * 4
    add r14, rax
    mov [rel bbox_min_ptr], r14

    mov rax, [rel index_clusters]
    imul rax, DIMS * 2
    add r14, rax
    mov [rel bbox_max_ptr], r14

    mov rax, [rel index_clusters]
    imul rax, DIMS * 2
    add r14, rax
    mov [rel cluster_offsets_ptr], r14

    mov rax, [rel index_clusters]
    inc rax
    shl rax, 2
    add r14, rax

    ; r14 now points to dim0; store 14 dimension base pointers.
    lea rdi, [rel dim_ptrs]
    mov rax, [rel index_count]
    shl rax, 1                ; bytes per dimension array
    xor ecx, ecx
.sivf_dim_loop:
    cmp ecx, DIMS
    jae .sivf_dims_done
    mov [rdi + rcx * 8], r14
    add r14, rax
    inc ecx
    jmp .sivf_dim_loop
.sivf_dims_done:
    mov [rel labels_ptr], r14
    mov rax, [rel index_count]
    add r14, rax
    mov [rel ids_ptr], r14

    mov qword [rel records_ptr], 0
    mov qword [rel record_stride], 0
    mov [rel index_base], r13
    mov [rel index_len], r12
    mov qword [rel index_format], 3
    mov qword [rel index_loaded], 1
    jmp .return

.close_return:
    mov eax, SYS_close
    mov rdi, rbx
    syscall

.return:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
