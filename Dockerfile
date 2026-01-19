
# Build stage
FROM golang:1.25-alpine AS builder
ARG TARGETARCH
WORKDIR /app

# Copy only necessary files for dependency download
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build with optimizations for minimal size and deterministic output
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build \
    -trimpath \
    -ldflags="-s -w -extldflags '-static'" \
    -tags netgo \
    -o certstream-monitor \
    ./cmd/cli

# Intermediate stage to get CA certificates
FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

# Final minimal image
FROM scratch

# Copy binary
COPY --from=builder /app/certstream-monitor /certstream-monitor

# Copy CA certificates for HTTPS
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Environment variables
ENV TARGET_DOMAINS="" \
    CERTSTREAM_URL="" \
    WEBHOOK_URL="" \
    API_TOKEN="" \
    NO_BACKOFF="" \
    BUFFER_SIZE="" \
    WORKERS=""

ENTRYPOINT ["/certstream-monitor"]