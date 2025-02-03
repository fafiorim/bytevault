FROM golang:1.21-alpine AS scanner-builder

WORKDIR /build

# Copy Go files
COPY scanner.go .
COPY go.mod go.sum ./

# Build the scanner
RUN go mod download
RUN go build -o scanner

# Final image
FROM alpine:latest

# Set environment variables with defaults
ENV ADMIN_USERNAME=admin \
    ADMIN_PASSWORD=admin123 \
    USER_USERNAME=user \
    USER_PASSWORD=user123 \
    FSS_API_ENDPOINT=antimalware.us-1.cloudone.trendmicro.com:443 \
    FSS_API_KEY="" \
    FSS_CUSTOM_TAGS=""

WORKDIR /app

# Install Node.js and npm
RUN apk add --update nodejs npm

# Create necessary directories
RUN mkdir -p /app/public /app/uploads && \
    chmod 777 /app/uploads

# Copy scanner from builder
COPY --from=scanner-builder /build/scanner /app/scanner

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy application files
COPY server.js .
COPY public/ public/

# Copy startup script
COPY start.sh .
RUN chmod +x start.sh

EXPOSE 3000

# Use the startup script to run both services
CMD ["./start.sh"]
