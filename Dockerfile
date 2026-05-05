FROM debian:bookworm-slim AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends nasm binutils make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Makefile .
COPY runtime/ ./runtime/
RUN make api

# Runtime image: scratch + the static ELF. Nothing else.
FROM scratch
COPY --from=builder /build/build/api /api
EXPOSE 8080
ENTRYPOINT ["/api"]
