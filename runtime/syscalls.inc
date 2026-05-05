; Linux x86_64 syscall numbers and constants.
; Source of truth: /usr/include/asm/unistd_64.h on Debian bookworm.

%ifndef SYSCALLS_INC
%define SYSCALLS_INC

; ---- Syscall numbers ----
%define SYS_read           0
%define SYS_write          1
%define SYS_open           2
%define SYS_close          3
%define SYS_fstat          5
%define SYS_lseek          8
%define SYS_mmap           9
%define SYS_brk           12
%define SYS_socket        41
%define SYS_bind          49
%define SYS_listen        50
%define SYS_setsockopt    54
%define SYS_exit         60
%define SYS_exit_group   231
%define SYS_epoll_wait   232
%define SYS_epoll_ctl    233
%define SYS_accept4      288
%define SYS_epoll_create1 291

; ---- Socket constants ----
%define AF_INET            2
%define SOCK_STREAM        1
%define SOL_SOCKET         1
%define SO_REUSEADDR       2
%define SO_REUSEPORT      15

; ---- mmap ----
%define PROT_READ          1
%define PROT_WRITE         2
%define MAP_SHARED         1
%define MAP_PRIVATE        2
%define MAP_ANONYMOUS   0x20

; ---- lseek ----
%define SEEK_SET           0
%define SEEK_END           2

; ---- epoll ----
%define EPOLL_CTL_ADD      1
%define EPOLL_CTL_DEL      2
%define EPOLL_CTL_MOD      3
%define EPOLLIN        0x001
%define EPOLLOUT       0x004
%define EPOLLERR       0x008
%define EPOLLHUP       0x010
%define EPOLLET   0x80000000

; ---- fcntl / open ----
%define O_RDONLY           0

%endif
