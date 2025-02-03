# ByteVault - Secure File Storage with Malware Scanning

ByteVault is a containerized file storage application with malware scanning capabilities, web interface, and REST API. It provides secure file upload, scanning, and management.

## Features
- Web interface for file management
- Real-time malware scanning using File Security Services
- Configurable security modes (Prevent/Log Only)
- File upload with automated scanning
- Scan history and status monitoring
- Health monitoring dashboard
- RESTful API with Basic Authentication
- Session-based web authentication
- Docker containerization

## Directory Structure
```
bytevault/
├── Dockerfile              # Container configuration
├── scanner.go             # Go-based scanner service
├── server.js              # Express server implementation
├── package.json           # Node.js dependencies
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

1. Set up File Security Services:
```bash
export FSS_API_KEY=your_api_key
```

2. Build and run:
```bash
docker build -t bytevault:latest .
docker run -d \
  -p 3000:3000 -p 3001:3001 \
  -e FSS_API_ENDPOINT="antimalware.us-1.cloudone.trendmicro.com:443" \
  -e FSS_API_KEY=$FSS_API_KEY \
  -e ADMIN_USERNAME="admin" \
  -e ADMIN_PASSWORD="admin123" \
  -e USER_USERNAME="user" \
  -e USER_PASSWORD="user123" \
  -e FSS_CUSTOM_TAGS="env:bytevault,team:security" \
  --name bytevault \
  bytevault:latest
```

3. Access the application:
- Web Interface: http://localhost:3000
- API Endpoints: http://localhost:3000/api/* (with Basic Auth)

## Security Modes

ByteVault supports two security modes:

### Prevent Mode (Default)
- Blocks and deletes malicious files immediately
- Notifies users when malware is detected
- Provides highest security level
- Files marked as malicious are not stored

### Log Only Mode
- Allows all file uploads
- Logs and marks malicious files
- Warns users about detected threats
- Useful for testing and monitoring

## API Reference

### Authentication
All API endpoints use Basic Authentication. Default credentials:
- Admin: username: `admin`, password: `admin123`
- User: username: `user`, password: `user123`

### Endpoints

#### Upload File
```bash
curl -X POST http://localhost:3000/upload \
  -u "admin:admin123" \
  -F "file=@/path/to/your/file.txt"

# Example Response (Safe File)
{
    "message": "File uploaded and scanned successfully",
    "filename": "1738463939938-example.txt",
    "size": 1234,
    "mimetype": "text/plain",
    "scanResult": {
        "isSafe": true
    }
}

# Example Response (Malware Detected - Prevent Mode)
{
    "error": "Malware detected - Upload prevented",
    "details": "Malware detection details",
    "scanId": "20250203162048-file.txt"
}

# Example Response (Malware Detected - Log Only Mode)
{
    "message": "File uploaded but marked as unsafe",
    "filename": "1738463939938-malware.txt",
    "warning": "Malware detected",
    "scanResult": {
        "isSafe": false
    }
}
```

#### Get Configuration
```bash
curl http://localhost:3000/api/config -u "admin:admin123"
```

#### Update Configuration
```bash
curl -X POST http://localhost:3000/api/config \
  -u "admin:admin123" \
  -H "Content-Type: application/json" \
  -d '{"securityMode": "logOnly"}'
```

#### List Files
```bash
curl http://localhost:3000/files -u "admin:admin123"
```

#### Get Scan Results
```bash
curl http://localhost:3000/api/scan-results -u "admin:admin123"
```

#### Get System Health
```bash
curl http://localhost:3000/health -u "admin:admin123"
```

#### Delete File
```bash
curl -X DELETE http://localhost:3000/files/filename.txt -u "admin:admin123"
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| FSS_API_KEY | File Security Services API Key | Required |
| FSS_API_ENDPOINT | FSS API Endpoint | antimalware.us-1.cloudone.trendmicro.com:443 |
| FSS_CUSTOM_TAGS | Custom tags for scans | env:bytevault,team:security |
| ADMIN_USERNAME | Admin username | admin |
| ADMIN_PASSWORD | Admin password | admin123 |
| USER_USERNAME | Regular user username | user |
| USER_PASSWORD | Regular user password | user123 |

## Web Interface

### Dashboard
- File upload with real-time scanning
- File listing and management
- Delete functionality

### Scan Results
- View scan history
- Filter by safe/unsafe files
- Detailed scan information

### Health Status
- System health monitoring
- Scanner status
- Scan statistics

### Configuration
- Security mode management
- System settings
- Real-time updates

## Volumes and Persistence

Mount volumes for persistent storage:
```bash
docker run -d \
  -p 3000:3000 -p 3001:3001 \
  -v /path/on/host:/app/uploads \
  -e FSS_API_KEY=$FSS_API_KEY \
  -e FSS_API_ENDPOINT="antimalware.us-1.cloudone.trendmicro.com:443" \
  --name bytevault \
  bytevault:latest
```

## Troubleshooting

### Scanner Issues
- Verify FSS_API_KEY is set correctly
- Check scanner logs: `docker logs bytevault | grep scanner`
- Verify both ports (3000 and 3001) are accessible

### Common Issues
- Port conflicts: Check ports 3000 and 3001
- Authentication errors: Verify credentials
- Upload fails: Check file permissions and scanner status
- Configuration not saving: Check user permissions

View logs:
```bash
docker logs bytevault
docker logs -f bytevault
```
