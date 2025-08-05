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

# Build the proxy binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o proxy ./proxy

# Production stage
FROM alpine:latest

# Install ca-certificates and curl for testing
RUN apk --no-cache add ca-certificates curl

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/proxy .

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose SSH and HTTP ports
EXPOSE 2222 8081

# Run the proxy
CMD ["./proxy"] 