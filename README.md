# rinha-2026 — pure x86_64 assembly experiment

Experimento alternativo da [Rinha de Backend 2026](https://github.com/zanfranceschi/rinha-de-backend-2026) — detecção de fraude em transações via *k-Nearest Neighbors* (k=5) sobre 3 milhões de vetores de referência em 14 dimensões — escrito **inteiramente em assembly x86_64** (NASM), sem libc, sem stdlib, sem runtime.

A submissão "principal" em Rust vive na branch `refactor/secret-sauce` do mesmo repo (final 5135.33 oficial Mac Mini, 19º BR). Esta branch é um experimento paralelo pra ver até onde dá pra ir só com asm.

## Estado atual (Wave 3 — partial vectorization)

- ✅ ELF estático freestanding (`build/api`), linkado direto pelo `ld`
- ✅ Servidor TCP em `0.0.0.0:8080` via syscalls Linux cruas
- ✅ Loop `accept` síncrono com HTTP/1.1 keep-alive
- ✅ Parser HTTP básico (`Content-Length`, body offset, `/ready`, `/fraud-score`)
- ✅ Parser JSON parcial por busca de chaves reais
- ✅ Vectorização i16 parcial em `query_i16` (amount, installments, tx_count_24h, is_online, card_present)
- ✅ Loader opcional do índice IVF v3 (`open` + `lseek` + `mmap` + header/offset parse)
- ✅ KNN escalar inicial sobre registros reais dos primeiros até 8 clusters IVF quando `/index/data.bin` existe
- ✅ Score temporário por heurística só quando o índice ainda não existe
- ✅ Docker multi-stage com imagem final `FROM scratch`
- ✅ docker-compose com nginx + 2 réplicas, mesma topologia da versão Rust
- ⏳ Vectorize completo + datas ISO-8601 + `known_merchants`/MCC/last_transaction
- ⏳ Centroid scan para escolher probes + AVX2 `vpmaddwd`
- ⏳ Adaptive nprobe (8 → 24 borderline) + early-exit
- ⏳ `build_index` em asm (k-means++ + Lloyd + write IVF)
- ⏳ epoll loop pra concorrência

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
