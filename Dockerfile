FROM golang:1.23 AS builder

# Install buildx prerequisites
ARG TARGETARCH
ARG BUILDPLATFORM

# Build our processor
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o certstream-monitor

FROM alpine:3.18

# Install CA certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

COPY --from=builder /app/certstream-monitor /usr/local/bin/certstream-monitor

ENTRYPOINT ["/usr/local/bin/certstream-monitor"]
