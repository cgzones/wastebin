# --- build image

FROM docker.io/rust:alpine AS builder

RUN apk add musl-dev

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "10001" \
    "app"

WORKDIR /app
COPY . .

# Build both binaries together so their shared dependencies are compiled once.
RUN cargo build --locked --release --no-default-features -p wastebin -p wastebin-ctl

# --- final image

FROM scratch

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /app
COPY --from=builder /app/target/release/wastebin /app/wastebin
COPY --from=builder /app/target/release/wastebin-ctl /app/wastebin-ctl
USER app:app
CMD ["/app/wastebin"]
