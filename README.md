# ByteVault - Secure File Storage with Malware Scanning

[![Docker Hub](https://img.shields.io/badge/docker-fafiorim%2Fbytevault-blue)](https://hub.docker.com/r/fafiorim/bytevault)
[![Version](https://img.shields.io/badge/version-1.5.0-green)](https://github.com/fafiorim/bytevault/releases/tag/v1.5.0)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Disclaimer: This application is designed for demo purposes only. It is not intended for production deployment under any circumstances. Use at your own risk.

Bytevault is a containerized file storage application with malware scanning capabilities, web interface, and REST API. It provides secure file upload, scanning, and management with enhanced health monitoring and real-time service validation.

## Features
- Web interface for file management
- Real-time malware scanning using File Security Services
- Configurable security modes (Prevent/Log Only/Disabled)
- File upload with automated scanning
- Scan history and status monitoring
- **Enhanced health monitoring dashboard with real-time service validation**
- **Scanner logs viewer accessible from health status page**
- **Degraded status reporting for better observability**
- RESTful API with Basic Authentication
- Session-based web authentication
- Docker containerization with multi-architecture support
- Kubernetes-ready deployment manifests
- Optional admin configuration
- Role-based access control
- HTTPS support with self-signed certificates

## Directory Structure
```
bytevault/
├── Dockerfile              # Container configuration
├── scanner.go             # Go-based scanner service
├── server.js              # Express server implementation
├── package.json           # Node.js dependencies
├── middleware/            # Application middleware
│   └── auth.js           # Authentication middleware
└── public/                # Static files directory
    ├── components/       # UI components
    ├── index.html        # Welcome page
    ├── login.html        # Login interface
    ├── dashboard.html    # File management interface
    ├── scan-results.html # Scan history interface
    ├── health-status.html # System health monitoring
    ├── configuration.html # System configuration page
    ├── styles.css        # Application styling
    └── script.js         # Client-side functionality
```

## Quick Start

### Using Docker Hub (Recommended)

```bash
# Set your FSS API key
export FSS_API_KEY=your_api_key

# Run with Docker Hub image
docker run -d \
  -p 3000:3000 \
  -p 3443:3443 \
  -e FSS_API_KEY=$FSS_API_KEY \
  -e SECURITY_MODE="logOnly" \
  --name bytevault \
  fafiorim/bytevault:v1.5.0
```

### Building from Source

```bash
# Clone and build
git clone https://github.com/fafiorim/bytevault.git
cd bytevault
docker build -t bytevault:latest .

# Run locally built image
docker run -d \
  -p 3000:3000 \
  -p 3443:3443 \
  -e FSS_API_KEY=$FSS_API_KEY \
  -e SECURITY_MODE="prevent" \
  --name bytevault \
  bytevault:latest
```

### Access the Application

- **HTTP**: http://localhost:3000
- **HTTPS**: https://localhost:3443
- **Health Status**: http://localhost:3000/health-status
- **API Endpoints**: http://localhost:3000/api/* (with Basic Auth)

### Default Credentials
- Username: `admin`
- Password: `changeMe123`

## Kubernetes Deployment

Bytevault includes production-ready Kubernetes manifests in the `k8s/` directory.

### Quick Deploy

```bash
# Create secret with your FSS API key
kubectl create secret generic bytevault-secrets \
  --from-literal=admin-password=your_admin_pass \
  --from-literal=user-password=your_user_pass \
  --from-literal=fss-api-key=your_fss_api_key

# Deploy ConfigMap
kubectl apply -f k8s/configmap.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml

# Create LoadBalancer service
kubectl apply -f k8s/service.yaml

# Get external IP
kubectl get svc bytevault-service
```

### Kubernetes Resources

- **Deployment**: `k8s/deployment.yaml` - Application deployment with health checks
- **Service**: `k8s/service.yaml` - LoadBalancer service exposing port 3000
- **ConfigMap**: `k8s/configmap.yaml` - Application configuration
- **Secret**: `k8s/secret.yaml` - Template for sensitive data

### Kubernetes Features

- Multi-architecture support (AMD64/ARM64)
- Liveness and readiness probes
- ConfigMap-based configuration
- Secret management for credentials
- LoadBalancer service for external access

## Security Modes

ByteVault supports three security modes:

### Disabled Mode (Default)
- Bypasses malware scanning
- Files are uploaded directly without scanning
- Maintains logging of uploads with clear "Not Scanned" status
- Suitable for trusted environments or testing
- Can be enabled/disabled by administrators only (when admin account is configured)

### Prevent Mode
- Blocks and deletes malicious files immediately
- Notifies users when malware is detected
- Provides highest security level
- Files marked as malicious are not stored

### Log Only Mode
- Allows all file uploads
- Logs and marks malicious files
- Warns users about detected threats
- Useful for testing and monitoring

## Authentication

ByteVault supports two authentication methods:

### Web Interface Authentication
- Session-based authentication
- Login through web interface at `/login`
- Configurable user credentials via environment variables
- Optional admin account for configuration management

### API Authentication
- Basic Authentication for all API endpoints
- Supports both user and admin credentials
- Works with standard API tools and curl commands
- Same credentials as web interface

### Default Credentials
- User Account (Required):
  - Configured via USER_USERNAME and USER_PASSWORD
  - Can upload and manage files
  - Cannot modify system configuration
- Admin Account (Optional):
  - Configured via ADMIN_USERNAME and ADMIN_PASSWORD
  - Full access to all features
  - Can modify system configuration
  - If not configured, configuration changes are disabled

## API Reference

### Endpoints

#### Upload File
```bash
# Upload with user account
curl -X POST http://localhost:3000/api/upload \
  -u "user:your_password" \
  -F "file=@/path/to/your/file.txt"

# Upload with admin account (if configured)
curl -X POST http://localhost:3000/api/upload \
  -u "admin:admin_password" \
  -F "file=@/path/to/your/file.txt"

# Example Response (Safe File)
{
    "message": "File uploaded and scanned successfully",
    "results": [{
        "file": "example.txt",
        "status": "success",
        "message": "File uploaded and scanned successfully",
        "scanResult": {
            "isSafe": true
        }
    }]
}

# Example Response (Disabled Mode)
{
    "message": "File upload processing complete",
    "results": [{
        "file": "example.txt",
        "status": "success",
        "message": "File uploaded successfully (scanning disabled)",
        "scanResult": {
            "isSafe": null,
            "message": "Scanning disabled"
        }
    }]
}
```

#### Get Configuration
```bash
# Access with user account (view only)
curl http://localhost:3000/api/config -u "user:your_password"

# Access with admin account (if configured)
curl http://localhost:3000/api/config -u "admin:admin_password"
```

#### Update Configuration (Admin Only)
```bash
# Only works if admin account is configured
curl -X POST http://localhost:3000/api/config \
  -u "admin:admin_password" \
  -H "Content-Type: application/json" \
  -d '{"securityMode": "prevent"}'
```

#### List Files
```bash
curl http://localhost:3000/api/files -u "user:your_password"
```

#### Get Scan Results
```bash
curl http://localhost:3000/api/scan-results -u "user:your_password"
```

#### Get System Health
```bash
curl http://localhost:3000/api/health -u "user:your_password"
```

#### Get Scanner Logs
```bash
curl http://localhost:3000/api/scanner-logs -u "admin:admin_password"
```

#### Delete File
```bash
curl -X DELETE http://localhost:3000/api/files/filename.txt -u "user:your_password"
```

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| FSS_API_KEY | File Security Services API Key | Required | Yes |
| FSS_API_ENDPOINT | FSS API Endpoint | antimalware.us-1.cloudone.trendmicro.com:443 | No |
| FSS_CUSTOM_TAGS | Custom tags for scans | env:bytevault,team:security | No |
| USER_USERNAME | Regular user username | user | No |
| USER_PASSWORD | Regular user password | user123 | No |
| ADMIN_USERNAME | Admin username | admin | No |
| ADMIN_PASSWORD | Admin password | changeMe123 | No |
| SECURITY_MODE | Default security mode (prevent/logOnly/disabled) | disabled | No |

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 3000 | HTTP | Web interface and API |
| 3443 | HTTPS | Secure web interface (self-signed cert) |
| 3001 | HTTP | Internal scanner service (not exposed) |

## Web Interface

### Dashboard
- File upload with real-time scanning
- File listing and management
- Delete functionality
- Clear scan status indicators
- Supports drag-and-drop file upload

### Scan Results
- View scan history
- Filter by safe/unsafe/unscanned files
- Detailed scan information
- Clear status badges for each scan state
- Real-time updates

### Health Status
- **Enhanced health monitoring with real-time service validation**
- **Scanner service connectivity checks**
- **Three-state health reporting** (healthy, degraded, unhealthy)
- **Scanner logs viewer** - Click "Total Scans" to view detailed logs
- Scan statistics by category (safe, unsafe, not scanned)
- Security mode status
- System uptime tracking
- Error reporting with detailed messages

### Configuration
- Security mode management
- System settings
- Real-time updates
- Role-based access control
- Disabled when admin account is not configured

## Volumes and Persistence

Mount volumes for persistent storage:
```bash
docker run -d \
  -p 3000:3000 -p 3001:3001 \
  -v /path/on/host:/app/uploads \
  -e FSS_API_KEY=$FSS_API_KEY \
  -e USER_USERNAME="user" \
  -e USER_PASSWORD="your_password" \
  -e SECURITY_MODE="prevent" \
  --name bytevault \
  bytevault:latest
```

## Version Information

### Latest Release: v1.5.0

**What's New:**
- Enhanced health checks with real-time service validation
- Scanner logs viewer (click "Total Scans" on health status page)
- Degraded status reporting for better observability
- Kubernetes deployment manifests
- Docker Hub multi-architecture images

**Security Updates:**
- Updated Go from 1.21 to 1.24.12 (fixes 16 stdlib vulnerabilities)
- Updated golang.org/x/net from v0.22.0 to v0.49.0
- Updated bcrypt from 5.1.1 to 6.0.0 (fixes 3 high severity vulnerabilities)
- Zero remaining vulnerabilities (verified with npm audit and govulncheck)

**Docker Images:**
- `fafiorim/bytevault:v1.5.0` - Stable release
- `fafiorim/bytevault:latest` - Latest build
- Multi-architecture: AMD64, ARM64
- Image size: 161MB

**Previous Versions:**
- v1.0.0 - Initial release

## Troubleshooting

### Common Issues

#### Authentication Issues
- Verify correct credentials are being used
- Check if credentials contain special characters
- Ensure proper Basic Auth encoding for API calls
- Verify admin account is configured if attempting admin operations

#### Scanner Issues
- Verify FSS_API_KEY is set correctly
- Check scanner logs: `docker logs bytevault | grep scanner`
- Verify both ports (3000 and 3001) are accessible
- Check if security mode is not disabled

#### Configuration Issues
- Verify admin account is configured if trying to change settings
- Check if user has appropriate permissions
- Verify security mode settings

#### Upload Issues
- Check file permissions
- Verify scanner status
- Check upload size limits
- Verify correct credentials for API uploads

View logs:
```bash
docker logs bytevault
docker logs -f bytevault
```
