# --- build image

FROM docker.io/rust:alpine AS builder

RUN apk add musl-dev

ENV USER=app
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

WORKDIR /app
COPY . .
RUN cargo install --path .


# --- final image

FROM scratch

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /app
COPY --from=builder /usr/local/cargo/bin/wastebin /app/wastebin
USER app:app
CMD ["/app/wastebin"]
