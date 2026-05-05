# rinha-2026 — pure x86_64 assembly experiment

Experimento alternativo da [Rinha de Backend 2026](https://github.com/zanfranceschi/rinha-de-backend-2026) — detecção de fraude em transações via *k-Nearest Neighbors* (k=5) sobre 3 milhões de vetores de referência em 14 dimensões — escrito **inteiramente em assembly x86_64** (NASM), sem libc, sem stdlib, sem runtime.

A submissão "principal" em Rust vive na branch `refactor/secret-sauce` do mesmo repo (final 5135.33 oficial Mac Mini, 19º BR). Esta branch é um experimento paralelo pra ver até onde dá pra ir só com asm.

## Estado atual (Wave 18 — competitive IVF6/SIVF runtime)

- ✅ ELF estático freestanding (`build/api`), linkado direto pelo `ld`
- ✅ Servidor TCP ou Unix socket via syscalls Linux cruas
- ✅ HAProxy 3.3 + 2 réplicas asm sobre UDS
- ✅ Loop `accept` síncrono fechando cada resposta (`Connection: close`) para não prender o processo em um fd idle
- ✅ Parser HTTP básico (`Content-Length`, body offset, `/ready`, `/fraud-score`)
- ✅ Parser JSON por busca de chaves reais
- ✅ Vectorização i16 completa dos 14 campos reais do payload
- ✅ Loader opcional do índice IVF v3 (`open` + `lseek` + `mmap` + header/offset parse)
- ✅ Loader opcional do formato competitivo `IVF6` (`index.bin` K=256, vetores i16 + labels separados)
- ✅ Loader do layout `SIVF` transposto/SoA embutido na imagem (`resources/index.bin`)
- ✅ Seleção escalar dos 8 centróides mais próximos
- ✅ KNN sobre registros reais dos clusters selecionados
- ✅ Adaptive repair capado nos borderline (`IVF_NPROBE=5`, `IVF_REPAIR_LIMIT=1`)
- ✅ Score temporário por heurística só quando o índice ainda não existe
- ✅ Docker multi-stage com imagem final `FROM scratch`
- ✅ docker-compose dentro do budget oficial
- ⏳ epoll/io_uring para concorrência real sem fechar conexão
- ⏳ Kernel SoA AVX2 com pruning por máscara (a versão ingênua regrediu)
- ⏳ `build_index` em asm (k-means++ + Lloyd + write IVF)

## Melhor resultado local k6 oficial

Harness: `/tmp/rinha-2026-official/test/test.js`, 54.100 requests @ 900 rps.

| Configuração | p99 | FP | FN | Err | final |
|---|---:|---:|---:|---:|---:|
| `nprobe=3`, `repair=0`, keep-alive | 3.65ms | 7 | 10 | 32 | 4186.92 |
| `nprobe=3`, `repair=2`, keep-alive | 3.85ms | 1 | 3 | 14 | 4671.27 |
| `nprobe=3`, `repair=3`, close | 5.77ms | 1 | 2 | 0 | 4967.66 |
| `nprobe=4`, `repair=2`, close | 4.23ms | 1 | 0 | 0 | 5282.94 |
| **`nprobe=5`, `repair=1`, close** | **4.17ms** | **1** | **0** | **0** | **5289.28** |
| `nprobe=6`, `repair=0`, close | 4.17ms | 1 | 2 | 0 | 5108.76 |

## Build local

Pré-requisitos: `nasm` 2.16+, `binutils` (`ld`), `make`.

```bash
make api
./build/api &
curl -i -X POST -H 'content-type: application/json' \
     --data '{}' http://localhost:8080/fraud-score
```

## Build Docker

```bash
docker compose up --build
curl -i http://localhost:9999/fraud-score -X POST --data '{}'
```

## Estrutura

```
runtime/
├── api.asm          # entry point + accept/serve loop
├── syscalls.inc     # Linux x86_64 syscall numbers + socket/mmap/epoll consts
└── responses.inc    # 6 respostas JSON pré-construídas + table de lookup
Makefile             # nasm + ld
Dockerfile           # multi-stage: build em debian, runtime FROM scratch
docker-compose.yml   # nginx + 2× api, mesmas resource limits da Rinha
nginx.conf           # LB com keep-alive
```

## Notas

- Linkagem `nasm → ld -nostdlib -static`. Não passa pelo gcc, não puxa nada.
- `_start` é o entry; sem `main`, sem CRT.
- Single-threaded síncrono nessa wave; `epoll` chega quando começar a importar pra latência.
- O `data.bin` (índice IVF) ainda não é gerado nessa branch — vai vir junto com o port do `build_index` pra asm.
