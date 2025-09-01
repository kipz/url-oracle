# Build stage
FROM golang:1.23.7-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files from parent directory
COPY go.* ./

# Download dependencies
RUN go mod download

# Copy source code from parent directories
COPY . ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o generate-attestation ./cmd/generate_attestation
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o verify-attestation ./cmd/verify_attestation

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates git

# Create app user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binaries from builder stage
COPY --from=builder /app/generate-attestation /app/verify-attestation ./

# Copy entrypoint script
COPY ./entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Debug: List files to verify entrypoint exists
RUN ls -la /app/
RUN cat /app/entrypoint.sh | head -5

# Change ownership to app user
RUN chown -R appuser:appgroup /app

# Debug: Verify entrypoint still exists after ownership change
RUN ls -la /app/entrypoint.sh

# Switch to app user
USER appuser

# Debug: Verify entrypoint is accessible to app user
RUN ls -la /app/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
