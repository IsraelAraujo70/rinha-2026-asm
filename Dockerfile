FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git nasm binutils make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch main https://github.com/IsraelAraujo70/rinha-2026-asm.git .
RUN make api

FROM scratch
COPY --from=builder /src/build/api /api
COPY --from=builder /src/resources/index.bin /index/data.bin
EXPOSE 8080
ENTRYPOINT ["/api"]

