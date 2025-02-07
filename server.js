const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const port = 3000;

// System Configuration
let systemConfig = {
    securityMode: process.env.SECURITY_MODE || 'disabled', // 'prevent', 'logOnly', or 'disabled'
};

// Environment variables
const adminUsername = process.env.ADMIN_USERNAME || 'admin';
const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
const userUsername = process.env.USER_USERNAME || 'user';
const userPassword = process.env.USER_PASSWORD || 'user123';

// Store scan results in memory
let scanResults = [];

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: './uploads',
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ storage: storage });

// Basic Auth middleware
const basicAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [username, password] = credentials.split(':');

        if ((username === adminUsername && password === adminPassword) ||
            (username === userUsername && password === userPassword)) {
            req.user = {
                username,
                role: username === adminUsername ? 'admin' : 'user'
            };
            return next();
        }
    }

    res.setHeader('WWW-Authenticate', 'Basic realm="ByteVault API"');
    res.status(401).json({ error: 'Authentication required' });
};

// Session middleware
app.use(session({
    secret: 'bytevault-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Store scan result
const storeScanResult = (result) => {
    scanResults.unshift(result);
    if (scanResults.length > 100) {
        scanResults = scanResults.slice(0, 100);
    }
};

// API Endpoints
app.post('/upload', basicAuth, upload.array('file'), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: 'No files uploaded' });
        }

        const responses = [];
        
        // Process each file
        for (const file of req.files) {
            const filePath = path.join('./uploads', file.filename);

            try {
                // Skip scanning if security mode is disabled
                if (systemConfig.securityMode === 'disabled') {
                    const scanRecord = {
                        filename: file.originalname,
                        size: file.size,
                        mimetype: file.mimetype,
                        isSafe: true,
                        scanId: `SCAN_DISABLED_${Date.now()}`,
                        tags: ['scan_disabled'],
                        timestamp: new Date(),
                        securityMode: systemConfig.securityMode,
                        action: 'Uploaded without scanning',
                        fileStatus: 'Saved',
                        uploadedBy: req.user.username
                    };
                    
                    storeScanResult(scanRecord);
                    responses.push({ 
                        file: file.originalname,
                        status: 'success',
                        message: 'File uploaded successfully (scanning disabled)',
                        scanResult: {
                            isSafe: true,
                            message: 'Scanning disabled'
                        }
                    });
                    continue; // Move to next file
                }
                
                // Normal scanning process
                const fileData = fs.readFileSync(filePath);
                
                try {
                    const scanResponse = await axios.post('http://localhost:3001/scan', fileData, {
                        headers: {
                            'Content-Type': 'application/octet-stream',
                            'X-Filename': file.originalname
                        }
                    });

                    const scanResult = JSON.parse(scanResponse.data.message);
                    const isMalwareFound = scanResult.scanResult === 1 || (scanResult.foundMalwares && scanResult.foundMalwares.length > 0);
                    
                    // Store scan result
                    const scanRecord = {
                        filename: file.originalname,
                        size: file.size,
                        mimetype: file.mimetype,
                        isSafe: !isMalwareFound,
                        scanId: scanResponse.data.scanId,
                        tags: scanResponse.data.tags || [],
                        timestamp: new Date(),
                        securityMode: systemConfig.securityMode,
                        action: isMalwareFound ? 
                            (systemConfig.securityMode === 'prevent' ? 'Malware detected and blocked' : 'Malware detected and logged') :
                            'Scanned and verified safe',
                        fileStatus: isMalwareFound && systemConfig.securityMode === 'prevent' ? 'Deleted' : 'Saved',
                        uploadedBy: req.user.username,
                        scanDetails: scanResult
                    };
                    
                    if (isMalwareFound) {
                        // Handle malware based on security mode
                        if (systemConfig.securityMode === 'prevent') {
                            fs.unlinkSync(filePath);
                            storeScanResult(scanRecord);
                            responses.push({
                                file: file.originalname,
                                status: 'error',
                                error: 'Malware detected - Upload prevented',
                                details: scanResponse.data.message,
                                scanId: scanResponse.data.scanId
                            });
                        } else {
                            // Log Only mode - keep file but mark as unsafe
                            storeScanResult(scanRecord);
                            responses.push({
                                file: file.originalname,
                                status: 'warning',
                                message: 'File uploaded but marked as unsafe',
                                warning: 'Malware detected',
                                scanResult: scanResponse.data
                            });
                        }
                    } else {
                        // Safe file handling
                        storeScanResult(scanRecord);
                        responses.push({
                            file: file.originalname,
                            status: 'success',
                            message: 'File uploaded and scanned successfully',
                            scanResult: scanResponse.data
                        });
                    }

                } catch (scanError) {
                    // Delete file on scan error
                    fs.unlinkSync(filePath);
                    console.error('Scan error:', scanError);
                    responses.push({
                        file: file.originalname,
                        status: 'error',
                        error: 'File scan failed',
                        details: scanError.message
                    });
                }
            } catch (fileError) {
                console.error('File processing error:', fileError);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
                responses.push({
                    file: file.originalname,
                    status: 'error',
                    error: 'File processing failed'
                });
            }
        }

        // Send combined response
        res.json({
            message: 'File upload processing complete',
            results: responses
        });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'File upload failed' });
    }
});

app.get('/files', basicAuth, (req, res) => {
    try {
        fs.readdir('./uploads', (err, files) => {
            if (err) {
                return res.status(500).json({ error: 'Error reading files' });
            }
            const fileList = files.map(filename => {
                const stats = fs.statSync(path.join('./uploads', filename));
                return {
                    name: filename,
                    size: stats.size,
                    created: stats.birthtime,
                    modified: stats.mtime
                };
            });
            res.json(fileList);
        });
    } catch (error) {
        console.error('File listing error:', error);
        res.status(500).json({ error: 'Error listing files' });
    }
});

app.delete('/files/:filename', basicAuth, (req, res) => {
    try {
        const filepath = path.join('./uploads', req.params.filename);
        if (!fs.existsSync(filepath)) {
            return res.status(404).json({ error: 'File not found' });
        }
        fs.unlink(filepath, (err) => {
            if (err) {
                return res.status(500).json({ error: 'Error deleting file' });
            }
            scanResults = scanResults.filter(result => result.filename !== req.params.filename);
            res.json({ message: 'File deleted successfully' });
        });
    } catch (error) {
        console.error('File deletion error:', error);
        res.status(500).json({ error: 'Error deleting file' });
    }
});

// Configuration endpoints
app.get('/api/config', basicAuth, (req, res) => {
    res.json({
        ...systemConfig,
        isAdmin: req.user.role === 'admin'
    });
});

app.post('/api/config', basicAuth, (req, res) => {
    // Check if user is admin
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only administrators can modify system configuration' });
    }

    const { securityMode } = req.body;
    
    if (securityMode && ['prevent', 'logOnly', 'disabled'].includes(securityMode)) {
        systemConfig.securityMode = securityMode;
        res.json({ message: 'Configuration updated', config: systemConfig });
    } else {
        res.status(400).json({ error: 'Invalid configuration' });
    }
});

app.get('/health', basicAuth, (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        securityMode: systemConfig.securityMode,
        scanResults: {
            total: scanResults.length,
            safe: scanResults.filter(r => r.isSafe && !r.tags.includes('scan_disabled')).length,
            unsafe: scanResults.filter(r => !r.isSafe).length,
            notScanned: scanResults.filter(r => r.tags.includes('scan_disabled')).length
        }
    });
});

app.get('/api/scan-results', basicAuth, (req, res) => {
    res.json(scanResults);
});

// Static files and web routes
app.use(express.static('public'));
app.use('/uploads', basicAuth, express.static('uploads'));

app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if ((username === adminUsername && password === adminPassword) ||
        (username === userUsername && password === userPassword)) {
        req.session.user = { 
            username,
            role: username === adminUsername ? 'admin' : 'user'
        };
        res.json({ success: true, redirect: '/dashboard' });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Web interface routes
app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/health-status', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'health-status.html'));
});

app.get('/scan-results', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'scan-results.html'));
});

app.get('/config', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'configuration.html'));
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Start server
app.listen(port, '0.0.0.0', () => {
    console.log(`ByteVault running on port ${port}`);
    console.log('Security Mode:', systemConfig.securityMode, process.env.SECURITY_MODE ? '(from environment)' : '(default)');
});
