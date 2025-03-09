# Use official Golang 1.24 image as a build stage
FROM golang:1.24 AS builder

WORKDIR /app

# Copy go.mod and go.sum first for dependency caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod tidy

# Now copy the rest of the project files
COPY . .

# Build the Go binary from the correct entry point
RUN go build -o authentication ./cmd

# Use a minimal image for production
FROM alpine:latest
WORKDIR /root/

# Install necessary certificates for HTTPS (if needed)
RUN apk --no-cache add ca-certificates

# Copy the compiled Go binary from the builder stage
COPY --from=builder /app/authentication .

# Expose the authentication service port
EXPOSE 8080

# Run the authentication service
CMD ["./authentication"]

