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
index_loaded:      dq 0
index_base:        dq 0
index_len:         dq 0
index_count:       dq 0
index_clusters:    dq 0
centroids_ptr:     dq 0
cluster_offsets_ptr: dq 0
bbox_min_ptr:      dq 0
bbox_max_ptr:      dq 0
records_ptr:       dq 0

section .bss
; Per-connection scratch. 16 KiB covers the largest payload we'll see (the
; Rinha references include ~500-byte JSON blobs; headers add ~200 bytes).
recv_buf:  resb 16384
; Wave 3 quantized vector scratch: 16 i16 lanes so AVX2 can load one full ymm.
; Lanes 0..13 mirror the Rinha feature contract; lanes 14..15 stay zero.
query_i16: resw 16
best_dist: resq 5
best_label: resb 5
cluster_best_dist: resq 8
cluster_best_id: resq 8
dist_lanes: resd 8

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
amount_key:    db '"amount"'
amount_key_len equ $ - amount_key
installments_key: db '"installments"'
installments_key_len equ $ - installments_key
is_online_key: db '"is_online"'
is_online_key_len equ $ - is_online_key
card_present_key: db '"card_present"'
card_present_key_len equ $ - card_present_key
index_path: db '/index/data.bin', 0
index_magic: db 'RINHA26', 0
f32_10000: dd 10000.0
distance_mask_i16:
    times 14 dw -1
    times 2 dw 0

IVF_HEADER_LEN equ 32
IVF_VERSION equ 3
DIMS equ 14
IVF_RECORD_LEN equ 32

section .text

; ============================================================
; _start — setup listener, then accept-serve loop forever.
; ============================================================
_start:
    call load_index_optional

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
; vectorize_json_partial — fill cheap lanes of query_i16 from JSON.
;   In : rbx = body base, r12 = body length
;   Out: query_i16 lanes updated
;
; Implemented lanes:
;   0 amount:       round-ish amount clamped to 0..10000
;   1 installments: installments / 12 * 10000
;   8 tx_count_24h: tx_count / 20 * 10000
;   9 is_online:    0 or 10000
;  10 card_present: 0 or 10000
;
; Missing lanes stay conservative zero for now. last_transaction sentinel
; lanes 5/6 use -10000 to match the Rust negative quantization contract.
; ============================================================
vectorize_json_partial:
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

    ; amount -> lane 0. quant_i16(clamp(amount/10000)) == round(amount).
    lea rdx, [rel amount_key]
    mov rcx, amount_key_len
    call find_key_number
    cmp rax, 10000
    jbe .amount_ok
    mov eax, 10000
.amount_ok:
    mov [rel query_i16 + 0 * 2], ax

    ; installments -> lane 1 = clamp(installments / 12) * 10000.
    lea rdx, [rel installments_key]
    mov rcx, installments_key_len
    call find_key_number
    cmp rax, 12
    jbe .installments_ok
    mov eax, 12
.installments_ok:
    imul rax, rax, 10000
    xor edx, edx
    mov ecx, 12
    div rcx
    mov [rel query_i16 + 1 * 2], ax

    lea rdx, [rel tx_count_key]
    mov rcx, tx_count_key_len
    call find_key_number
    cmp rax, 20
    jbe .tx_ok
    mov eax, 20
.tx_ok:
    imul rax, rax, 10000
    xor edx, edx
    mov ecx, 20
    div rcx
    mov [rel query_i16 + 8 * 2], ax

    lea rdx, [rel is_online_key]
    mov rcx, is_online_key_len
    call find_key_bool
    test rax, rax
    jz .online_done
    mov word [rel query_i16 + 9 * 2], 10000
.online_done:

    lea rdx, [rel card_present_key]
    mov rcx, card_present_key_len
    call find_key_bool
    test rax, rax
    jz .card_done
    mov word [rel query_i16 + 10 * 2], 10000
.card_done:
    ret

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

    mov rbx, [rel cluster_offsets_ptr]
    test rbx, rbx
    jz .fallback_zero

    call select_top8_clusters

    xor ebp, ebp              ; cluster_id
    mov r15, [rel index_clusters]
    cmp r15, 8
    jbe .probe_limit_ok
    mov r15d, 8
.probe_limit_ok:
    test r15, r15
    jz .fallback_zero

.cluster_loop:
    cmp rbp, r15
    jae .score

    lea r11, [rel cluster_best_id]
    mov rax, [r11 + rbp * 8]      ; selected cluster id
    mov r12, [rbx + rax * 8]      ; start offset
    mov r13, [rbx + rax * 8 + 8]  ; end offset
    cmp r13, r12
    jbe .next_cluster

    mov r14, [rel records_ptr]
    mov rax, r12
    shl rax, 5                    ; * IVF_RECORD_LEN (32)
    add r14, rax                  ; current record ptr

    mov r10, r13
    sub r10, r12                  ; records remaining

.record_loop:
    test r10, r10
    jz .next_cluster

    mov rdi, r14
    push r10
    call squared_distance_record_avx2
    pop r10
    movzx esi, byte [r14 + 28]
    mov rdi, rax
    push r10
    call insert_best_u64_asm
    pop r10

    add r14, IVF_RECORD_LEN
    dec r10
    jmp .record_loop

.next_cluster:
    inc rbp
    jmp .cluster_loop

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
; insert_best_u64_asm — insert (dist,label) into sorted top-5 arrays.
;   In : rdi = dist, sil = label
; ============================================================
insert_best_u64_asm:
    cmp rdi, [rel best_dist + 4 * 8]
    jae .ret

    lea r8, [rel best_dist]
    lea r9, [rel best_label]
    mov ecx, 4
.shift_loop:
    test ecx, ecx
    jz .place
    mov rax, [r8 + rcx * 8 - 8]
    cmp rdi, rax
    jae .place
    mov [r8 + rcx * 8], rax
    mov al, [r9 + rcx - 1]
    mov [r9 + rcx], al
    dec ecx
    jmp .shift_loop

.place:
    mov [r8 + rcx * 8], rdi
    mov [r9 + rcx], sil
.ret:
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
; load_index_optional — mmap /index/data.bin if present and parse IVF v3.
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

    mov [rel index_base], r13
    mov [rel index_len], r12
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
