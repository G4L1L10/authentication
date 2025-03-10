# Use official Golang 1.24 image as a build stage
FROM golang:1.24 AS builder

WORKDIR /app

# Copy go.mod and go.sum first for dependency caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod tidy

# Now copy the rest of the project files
COPY . .

# ✅ Fix: Ensure fully static binary (no missing libraries)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o authentication ./cmd

# ✅ Switch to 'scratch' (completely minimal) for production
FROM scratch
COPY --from=builder /app/authentication .

# Ensure binary has execution permissions
CMD ["/authentication"]

