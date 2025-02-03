const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const port = 3000;

// Get environment variables
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

// Basic Auth middleware for API endpoints
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
app.post('/upload', basicAuth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const filePath = path.join('./uploads', req.file.filename);
        const fileData = fs.readFileSync(filePath);
        
        try {
            // Scan the file
            const scanResponse = await axios.post('http://localhost:3001/scan', fileData, {
                headers: {
                    'Content-Type': 'application/octet-stream',
                    'X-Filename': req.file.originalname
                }
            });

            const scanResult = JSON.parse(scanResponse.data.message);

            // Check if malware was found
            const isMalwareFound = scanResult.scanResult === 1 || (scanResult.foundMalwares && scanResult.foundMalwares.length > 0);
            
            if (isMalwareFound) {
                // Delete the file if malware is found
                fs.unlinkSync(filePath);

                // Store scan result for reporting
                storeScanResult({
                    filename: req.file.originalname,
                    size: req.file.size,
                    mimetype: req.file.mimetype,
                    isSafe: false,
                    scanId: scanResponse.data.scanId,
                    tags: scanResponse.data.tags,
                    timestamp: new Date()
                });

                return res.status(400).json({
                    error: 'Malware detected',
                    details: scanResponse.data.message,
                    scanId: scanResponse.data.scanId
                });
            }

            // If file is safe, store the scan result
            storeScanResult({
                filename: req.file.originalname,
                size: req.file.size,
                mimetype: req.file.mimetype,
                isSafe: true,
                scanId: scanResponse.data.scanId,
                tags: scanResponse.data.tags,
                timestamp: new Date()
            });

            // Return success response
            res.json({ 
                message: 'File uploaded and scanned successfully',
                filename: req.file.filename,
                size: req.file.size,
                mimetype: req.file.mimetype,
                scanResult: scanResponse.data
            });

        } catch (scanError) {
            // On scan error, delete file and return error
            fs.unlinkSync(filePath);
            console.error('Scan error:', scanError);
            return res.status(500).json({ 
                error: 'File scan failed',
                details: scanError.message
            });
        }
    } catch (error) {
        console.error('Upload error:', error);
        // Cleanup file if it exists
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
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
            // Remove the file's scan results
            scanResults = scanResults.filter(result => result.filename !== req.params.filename);
            res.json({ message: 'File deleted successfully' });
        });
    } catch (error) {
        console.error('File deletion error:', error);
        res.status(500).json({ error: 'Error deleting file' });
    }
});

app.get('/health', basicAuth, (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        scanResults: {
            total: scanResults.length,
            safe: scanResults.filter(r => r.isSafe).length,
            unsafe: scanResults.filter(r => !r.isSafe).length
        }
    });
});

// API endpoint for scan results
app.get('/api/scan-results', basicAuth, (req, res) => {
    res.json(scanResults);
});

// Serve static files
app.use(express.static('public'));
app.use('/uploads', basicAuth, express.static('uploads'));

// Web interface routes
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

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Start server
app.listen(port, '0.0.0.0', () => {
    console.log(`ByteVault running on port ${port}`);
});
