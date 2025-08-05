# Build stage
FROM golang:1.23-alpine AS builder

# Install git and ca-certificates for go mod download
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the gateway binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o gateway ./gateway

# Production stage
FROM alpine:latest

# Install ca-certificates, iptables, and curl for testing
RUN apk --no-cache add ca-certificates iptables curl

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/gateway .

# Create a startup script that runs iptables, then starts the gateway
RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'iptables -A INPUT -s proxy -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /app/start.sh && \
    echo 'iptables -A INPUT -s proxy -j DROP' >> /app/start.sh && \
    echo 'iptables -A OUTPUT -d proxy -j ACCEPT' >> /app/start.sh && \
    echo 'exec /app/gateway' >> /app/start.sh && \
    chmod +x /app/start.sh

# Expose the local HTTP server port
EXPOSE 8000

# Run the startup script
CMD ["/app/start.sh"] 