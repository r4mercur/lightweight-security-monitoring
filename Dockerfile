# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Must match the go directive in go.mod (official images set GOTOOLCHAIN=local).
FROM golang:1.27-alpine AS builder

WORKDIR /app

# Cache dependency downloads separately from source code
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build a statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/main.go

# Directory for the SQLite database (DB_PATH=/data/monitoring.db). scratch has
# no mkdir; a volume mounted here takes over the owner, so UID 65534 can write.
RUN mkdir /data

# ── Stage 2: Run ──────────────────────────────────────────────────────────────
FROM scratch

# Import CA certificates for HTTPS (required for OpenAI API calls)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /server /server
COPY --from=builder --chown=65534:65534 /data /data

# Run as an unprivileged user. Mounted log files must be readable by UID 65534.
USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/server"]
