; Pre-built HTTP responses for /fraud-score, indexed by neighbor count (0..5).
;
; Body lengths differ between approved=true (35 bytes) and approved=false (36
; bytes) because "false" is one char longer than "true".
;
; Lookup table `resp_table` packs [pointer, length] pairs so the dispatch in
; api.asm can index it directly with `count * 16`.

section .rodata

resp0:
    db "HTTP/1.1 200 OK", 13, 10
    db "Content-Type: application/json", 13, 10
    db "Content-Length: 35", 13, 10
    db "Connection: keep-alive", 13, 10
    db 13, 10
    db '{"approved":true,"fraud_score":0.0}'
resp0_end:

resp1:
    db "HTTP/1.1 200 OK", 13, 10
    db "Content-Type: application/json", 13, 10
    db "Content-Length: 35", 13, 10
    db "Connection: keep-alive", 13, 10
    db 13, 10
    db '{"approved":true,"fraud_score":0.2}'
resp1_end:

resp2:
    db "HTTP/1.1 200 OK", 13, 10
    db "Content-Type: application/json", 13, 10
    db "Content-Length: 35", 13, 10
    db "Connection: keep-alive", 13, 10
    db 13, 10
    db '{"approved":true,"fraud_score":0.4}'
resp2_end:

resp3:
    db "HTTP/1.1 200 OK", 13, 10
    db "Content-Type: application/json", 13, 10
    db "Content-Length: 36", 13, 10
    db "Connection: keep-alive", 13, 10
    db 13, 10
    db '{"approved":false,"fraud_score":0.6}'
resp3_end:

resp4:
    db "HTTP/1.1 200 OK", 13, 10
    db "Content-Type: application/json", 13, 10
    db "Content-Length: 36", 13, 10
    db "Connection: keep-alive", 13, 10
    db 13, 10
    db '{"approved":false,"fraud_score":0.8}'
resp4_end:

resp5:
    db "HTTP/1.1 200 OK", 13, 10
    db "Content-Type: application/json", 13, 10
    db "Content-Length: 36", 13, 10
    db "Connection: keep-alive", 13, 10
    db 13, 10
    db '{"approved":false,"fraud_score":1.0}'
resp5_end:

; [pointer, length] pairs — index with (count << 4).
global resp_table
resp_table:
    dq resp0, resp0_end - resp0
    dq resp1, resp1_end - resp1
    dq resp2, resp2_end - resp2
    dq resp3, resp3_end - resp3
    dq resp4, resp4_end - resp4
    dq resp5, resp5_end - resp5

; 204 for /ready
ready_resp:
    db "HTTP/1.1 204 No Content", 13, 10
    db "Connection: keep-alive", 13, 10
    db "Content-Length: 0", 13, 10
    db 13, 10
ready_resp_end:
%define READY_RESP_LEN (ready_resp_end - ready_resp)

; 400 for malformed requests (the Rust API uses approve-fallback; we mirror that
; by returning resp0 instead, but keep this one around for future use).
bad_resp:
    db "HTTP/1.1 400 Bad Request", 13, 10
    db "Connection: close", 13, 10
    db "Content-Length: 0", 13, 10
    db 13, 10
bad_resp_end:
%define BAD_RESP_LEN (bad_resp_end - bad_resp)
