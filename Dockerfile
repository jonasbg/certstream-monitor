
# Build stage
FROM golang:1.25 AS builder
ARG TARGETARCH
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o certstream-monitor ./cmd/cli

# Intermediate stage to get CA certificates
FROM alpine:3.18 AS certs
RUN apk add --no-cache ca-certificates

# Final minimal image
FROM scratch
COPY --from=builder /app/certstream-monitor /certstream-monitor
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/certstream-monitor"]