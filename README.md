# FinGuard - Financial Services Malware Scanner

[![GitHub](https://img.shields.io/badge/github-fafiorim%2Ffinguard-blue)](https://github.com/fafiorim/finguard)
[![Version](https://img.shields.io/badge/version-1.6.0-green)](https://github.com/fafiorim/finguard)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Powered by](https://img.shields.io/badge/powered%20by-Trend%20Micro%20Cloud%20One-red)](https://www.trendmicro.com/cloudone)

**Disclaimer:** This application is designed for demo purposes only. It is not intended for production deployment under any circumstances. Use at your own risk.

FinGuard is a specialized malware scanner designed for financial institutions, leveraging Trend Micro Cloud One File Security. Built with a focus on compliance and security, it provides comprehensive file scanning capabilities with advanced detection features and detailed audit trails.

## Features

### Core Capabilities
- **Real-time malware scanning** using Trend Micro Cloud One File Security API
- **Web interface** for file management and monitoring
- **RESTful API** with Basic Authentication
- **Configurable security modes** (Prevent/Log Only/Disabled)
- **Enhanced health monitoring** with real-time service validation
- **Scanner logs viewer** accessible from health status page
- **Session-based authentication** with role-based access control
- **Docker containerization** with multi-architecture support
- **HTTPS support** with self-signed certificates

### Advanced Scanner Features (NEW)
- **PML Detection** - Predictive Machine Learning for zero-day threats
- **SPN Feedback** - Smart Protection Network threat intelligence sharing
- **Verbose Results** - Detailed scan metadata with engine versions and timing
- **Active Content Detection** - Identifies PDF scripts and Office macros
- **Scan Method Selection** - Buffer (in-memory) or File (disk-based) scanning
- **File Hash Calculation** - SHA1/SHA256 digests for audit trails
- **Configuration Tags** - Track scanner settings per scan (ml_enabled, spn_feedback, active_content)

### Security & Compliance
- **Dual scan methods** for flexibility and performance optimization
- **Detailed audit logging** with configurable tags
- **File hash tracking** for forensic analysis
- **Active content detection** for Office/PDF document security
- **Malware detection** with proper status reporting (fixed EICAR detection bug)

## Directory Structure
```
finguard/
├── Dockerfile              # Multi-stage container build
├── docker-compose.yml      # Optional Docker Compose setup
├── start.sh               # Container startup script
├── generate-cert.js       # SSL certificate generator
├── scanner.go             # Go-based scanner service with Trend Micro SDK
├── server.js              # Express API server
├── package.json           # Node.js dependencies
├── go.mod                 # Go module dependencies
├── go.sum                 # Go dependency checksums
├── k8s/                   # Kubernetes deployment manifests
│   ├── deployment.yaml   # K8s deployment configuration
│   ├── service.yaml      # LoadBalancer service
│   └── configmap.yaml    # Configuration management
├── middleware/            # Application middleware
│   └── auth.js           # Authentication & authorization
├── public/                # Web interface (static files)
│   ├── components/       # Reusable UI components
│   │   └── nav.html     # Navigation component
│   ├── index.html        # Welcome/landing page
│   ├── login.html        # Authentication page
│   Building from Source

```bash
# Clone the repository
git clone https://github.com/fafiorim/finguard.git
cd finguard

# Build the Docker image
docker build -t finguard:latest .

# Set your Trend Micro Cloud One API key
export FSS_API_KEY=your_api_key_here

# Run the container
docker run -d \
  -p 3000:3000 \
  -p 3443:3443 \
  -e FSS_API_KEY=$FSS_API_KEY \
  -e SECURITY_MODE="logOnly" \
  --name finguard \
  finguard
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
Configuration**: http://localhost:3000/configuration
- **API Endpoints**: http://localhost:3000/api/* (with Basic Auth)

### Default Credentials
- **Admin**: `admin` / `admin123`
- **User**: `user` / `usern-password=your_admin_pass \
  -Scanner Configuration

FinGuard provides granular control over scanner behavior through the configuration page (admin access required).

### Scan Methods

**Buffer Scan (Default)**
- Loads file into memory
- Sends data to scanner via network
- Faster for small files
- Higher memory usage

**File Scan**
- Scanner reads directly from disk
- Lower network overhead
- Better for large files
- Requires shared file system access

### Advanced Detection Features

**PML (Predictive Machine Learning)**
- AI-powered detection for unknown threats
- Zero-day malware detection
- Enhanced by Smart Protection Network data
- Configurable per-scan via `ml_enabled` tag

**SPN Feedback (Smart Protection Network)**
- Shares threat intelligence with Trend Micro
- Improves global threat detection
- Real-time correlation analysis
- Tracked via `spn_feedback` tag

FinGuard Results**
- Detailed scan metadata
- Engine versions and pattern updates
- Scan timing and performance metrics
- File type detection details

**Active Content Detection**
- Identifies PDF JavaScript
- Detects Office macros
- Reports potentially risky embedded code
- Returns `activeContentCount` in results
- Tracked via `active_content` tag

**File Hash Calculation**
- SHA1 and SHA256 digest generation
- Essential for audit trails and forensics
- Toggleable to reduce overhead
- Included in scan results when enabled

### Configuration Tags

Each scan includes tags for audit and compliance:
```
FinGuardard                    # Application identifier
file_type=.pdf                  # File extension
scan_method=buffer              # Scan method used
ml_enabled=true                 # PML detection status
spn_feedback=true               # SPN sharing status
active_content=true             # Active content detection
malware_name=Eicar_test_file   # Detected threat (if any)
```

## Sample Files

FinGuard includes sample files in the `samples/` directory for testing scanner features:

- **safe-file.pdf** - Clean PDF file with no threats
- **file_active_content.pdf** - PDF with embedded JavaScript for active content detection testing
- **README.md** - Detailed testing instructions

Upload these samples with different configurations to see how various detection features work.

## Kubernetes Deployment

FinGuard
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
    "results": [{(empty) | No |
| FSS_REGION | Trend Micro Cloud One region | us-1
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
```bash6.0 (FinGuard)

**What's New:**
- 🐛 **Fixed EICAR malware detection bug** - Files now correctly identified as unsafe
- 🤖 **PML Detection** - AI-powered zero-day malware detection
- 🌐 **SPN Feedback** - Smart Protection Network integration
- 📊 **Verbose Results** - Detailed scan metadata and diagnostics
- 🔍 **Active Content Detection** - PDF scripts and Office macros detection
- 🔄 **Scan Method Selection** - Buffer vs File scanning options
- 🔐 **File Hash Calculation** - SHA1/SHA256 digests with toggle
- 🏷️ **Configuration Tags** - Audit trail with ml_enabled, spn_feedback, active_content
- 📄 **Sample Files** - Test files included for feature validation
- 🎨 **FinGuard Branding** - Specialized for financial services

**Bug Fixes:**
- Fixed malware detection logic to properly parse both verbose and non-verbose scan results
- Scanner now correctly uses `isSafe` field from scanner response
- EICAR test files properly marked as unsafe in all scan modes

**Security Updates:**
- Updated Go from 1.21 to 1.24.12 (fixes 16 stdlib vulnerabilities)
- Updated golang.org/x/net from v0.22.0 to v0.49.0
- Updated bcrypt from 5.1.1 to 6.0.0 (fixes 3 high severity vulnerabilities)
- Zero remaining vulnerabilities (verified with npm audit and govulncheck)

**Technical Details:**
- Trend Micro SDK: tm-v1-fs-golang-sdk v1.7.0
- Go: 1.24.12
- Node.js: Compatible with latest LTS
- Multi-architecture: AMD64, ARM64

**Previous Versions:**
- v1.5.0 - ByteVault with enhanced health monitoring
- v1.0.0 - Initial ByteVaultecure web interface (self-signed cert) |
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
