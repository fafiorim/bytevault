# Sample Files for Testing

This directory contains sample files for testing the FinGuard malware scanner.

## Files

### safe-file.pdf
A clean, safe PDF file with simple text content. This file should pass all security scans without any detections.

**Expected Scan Result:**
- Status: Safe
- No malware detected
- No active content detected

**Use Case:** Testing normal file uploads and verifying the scanner correctly identifies clean files.

### file_active_content.pdf
A PDF file containing embedded JavaScript code. This file demonstrates active content detection capabilities.

**Embedded JavaScript Code:**
This PDF contains two JavaScript actions:

1. **Document Open Action** - Executes when PDF is opened:
   ```javascript
   app.alert('Document opened with active content');
   ```

2. **Named JavaScript Action** - Embedded script:
   ```javascript
   app.alert('This PDF contains active JavaScript content for testing active content detection');
   ```

**Expected Scan Result:**
- Status: Safe (no malware)
- Active Content Count: 1 (when active content detection is enabled)
- Active Content Count: N/A (when active content detection is disabled)
- Scanner detects embedded JavaScript as potentially risky content

**Security Implications:**
- JavaScript in PDFs can execute arbitrary code
- Can be used for phishing attacks or data exfiltration
- May trigger unwanted actions without user consent
- Common in malicious documents targeting enterprises

**Use Case:** Testing active content detection feature. When "Enable Active Content Detection" is enabled in settings, this file should be flagged for containing potentially risky JavaScript code. This simulates real-world scenarios where attackers embed malicious scripts in documents.

## Testing Instructions

### Upload via Web Interface
1. Navigate to http://localhost:3000
2. Login with credentials
3. Go to the upload page
4. Select a sample file
5. View the scan results

### Upload via API
```bash
# Test safe file
curl -X POST http://localhost:3000/api/upload \
  -u 'admin:admin123' \
  -F 'file=@samples/safe-file.pdf'

# Test active content file (with active content detection enabled)
curl -X POST http://localhost:3000/api/config \
  -u 'admin:admin123' \
  -H 'Content-Type: application/json' \
  -d '{"securityMode":"logOnly","activeContentEnabled":true}'

curl -X POST http://localhost:3000/api/upload \
  -u 'admin:admin123' \
  -F 'file=@samples/file_active_content.pdf'
```

### Expected Tags
Tags will vary based on configuration settings:

**safe-file.pdf:**
```
app=finguard
file_type=.pdf
scan_method=buffer (or file)
ml_enabled=true/false
spn_feedback=true/false
active_content=true/false
```

**file_active_content.pdf (with active content enabled):**
```
app=finguard
file_type=.pdf
scan_method=buffer (or file)
ml_enabled=true/false
spn_feedback=true/false
active_content=true
```

## Configuration Settings

These samples can be tested with various scanner configurations:

- **Security Mode:** disabled, logOnly, prevent
- **Scan Method:** buffer, file
- **Digest Calculation:** enabled/disabled
- **PML (ML) Detection:** enabled/disabled
- **SPN Feedback:** enabled/disabled
- **Verbose Results:** enabled/disabled
- **Active Content Detection:** enabled/disabled

## EICAR Test File

For malware detection testing, you can download the EICAR test file:
```bash
curl -o eicar.com https://secure.eicar.org/eicar.com
```

This is a safe test file recognized by all antivirus software as a test malware signature.
