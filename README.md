# GST Reconciliation Engine - Backend Documentation

## Overview

This is a complete FastAPI backend for the GST Reconciliation system with:
- **SQLite database** for persistent storage
- **JWT-based authentication** with secure token validation
- **User management** with role-based support (Taxpayer, CA, Government Officer)
- **Settings persistence** per user
- **File upload & processing** for GST documents (GSTR-1, GSTR-3B, Invoices)
- **Reconciliation logic** to compare GST filings
- **Dashboard analytics** with upload and reconciliation history

## Project Structure

```
C:\Hackathon/
├── main.py                      # FastAPI application (main backend)
├── requirements.txt             # Python dependencies
├── gst_reconciliation.db        # SQLite database (created automatically)
├── uploads/                     # Uploaded files directory (created automatically)
│   └── {user_id}/              # Organized by user
├── login.html / login.js        # Login page with JWT token flow
├── register.html                # Registration with backend API
├── Dashboard.html               # Dashboard with real data loading
├── upload.html                  # File upload with JWT auth
├── settings.html                # Settings page with API persistence
└── [other pages]                # Reports, Risk, Reconciliation, etc.
```

## Setup & Installation

### 1. Install Python Dependencies

```powershell
# Using pip
pip install -r requirements.txt

# Or manually
pip install fastapi uvicorn sqlalchemy python-jose passlib python-dotenv python-multipart pandas openpyxl
```

### 2. Start the Server

```powershell

python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The `--reload` flag auto-restarts on code changes (development mode).

### 3. Access the Application

- **Main App**: http://localhost:8000/ → redirects to Main.html
- **Login**: http://localhost:8000/login.html
- **Register**: http://localhost:8000/register.html
- **API Docs**: http://localhost:8000/docs (interactive Swagger UI)
- **Dashboard**: http://localhost:8000/Dashboard.html (requires login)

## Database Schema

### Users Table
- `id` (PK)
- `login` (unique)
- `password_hash` (SHA-256)
- `role` (taxpayer, ca, officer)
- `gstin`, `pan`, `legal_name` (optional)
- `created_at`

### User Settings Table
- `id` (PK)
- `user_id` (FK)
- `tolerance`, `match_mode`, `date_window`, `dup_rule`
- `high_threshold`, `med_threshold`, `model`, `risk_boost`
- `email_alerts`, `auto_reports`, `audit_trail`
- `updated_at`

### Uploaded Files Table
- `id` (PK)
- `user_id` (FK)
- `filename`, `file_type` (gstr1, gstr3b, invoice)
- `file_path`, `parsed_data` (JSON)
- `validation_status`, `validation_errors`
- `uploaded_at`

### Reconciliation Results Table
- `id` (PK)
- `user_id` (FK)
- `gstr1_id`, `gstr3b_id` (FK to UploadedFiles)
- `mismatches`, `risk_items` (JSON)
- `overall_status` (green/yellow/red)
- `created_at`

## API Endpoints

### Authentication

**POST /api/register**
```json
{
  "role": "taxpayer",
  "login": "user@example.com",
  "password": "secure_password",
  "gstin": "36ABCDE1234F1Z5",
  "pan": "ABCDE1234F",
  "legalBusinessName": "My Business Inc"
}
```
Response: `{ "status": "success", "user": "user@example.com", "user_id": 1 }`

**POST /api/login**
```json
{
  "userid": "user@example.com",
  "password": "secure_password",
  "role": "taxpayer"
}
```
Response: 
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "user_id": 1,
  "role": "taxpayer"
}
```

### Settings

**GET /api/settings** (requires JWT)
Returns current user's settings.

**POST /api/settings** (requires JWT)
```json
{
  "tolerance": 10.5,
  "match_mode": "standard",
  "email_alerts": true
}
```

### File Upload

**POST /api/upload** (requires JWT, multipart/form-data)
- Form fields: `gstr1`, `gstr3b`, `invoice` (file uploads)
- Parses CSV/Excel/JSON automatically
- Validates schema and stores metadata

**GET /api/uploads** (requires JWT)
Lists all uploaded files for the current user.

### Reconciliation

**POST /api/reconcile** (requires JWT)
```json
{
  "gstr1_id": 1,
  "gstr3b_id": 2
}
```
Response: Reconciliation results with match status and differences.

### Dashboard

**GET /api/dashboard** (requires JWT)
Returns summary: total uploads, recent files, reconciliation count, etc.

## Frontend Integration

### Login Flow

1. User submits login form on `login.html`
2. Frontend calls `POST /api/login` with credentials
3. Backend returns JWT token
4. Frontend stores token in `localStorage`
5. Frontend redirects to `/Dashboard.html`

### Protected Requests

All authenticated endpoints require the JWT token in the Authorization header:

```javascript
fetch('/api/settings', {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('token')
  }
})
```

### File Upload with Authentication

```javascript
const formData = new FormData();
formData.append('gstr1', file1);
formData.append('gstr3b', file2);

fetch('/api/upload', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('token')
  },
  body: formData
})
```

## File Processing

The backend automatically:
1. **Validates file format** (CSV, Excel, JSON)
2. **Checks schema** for required columns (gstin, invoice_no, invoice_date, taxable_value)
3. **Stores files** in `uploads/{user_id}/` directory
4. **Parses data** and extracts metadata
5. **Saves to database** for later retrieval and reconciliation

## Reconciliation Logic

Currently implemented:
- Compares total GST between GSTR-1 and GSTR-3B
- Calculates percentage difference
- Applies user's tolerance threshold
- Returns status: **green** (within tolerance), **yellow** (2x tolerance), **red** (exceeds 2x tolerance)

Future enhancements:
- Line-item matching between documents
- ITC claim validation
- Risk scoring based on mismatch patterns
- Vendor-level reconciliation

## Security Notes

⚠️ **For Production:**
1. Change `SECRET_KEY` in main.py to a strong random value
2. Use `.env` file for sensitive config (via `python-dotenv`)
3. Enable HTTPS/TLS
4. Add rate limiting
5. Implement CORS restrictions
6. Use bcrypt for passwords instead of SHA-256
7. Add database encryption at rest
8. Implement audit logging

Current implementation is for **demo/hackathon purposes** only.

## Troubleshooting

### "Module not found" errors
Ensure all packages from `requirements.txt` are installed:
```powershell
pip install -r requirements.txt
```

### Database locked
Close any other connections to the SQLite database file or restart the server.

### Token expired
Users need to re-login. Token expiry is set to 8 hours (480 minutes).

### File upload fails
Ensure the `uploads/` directory has write permissions and the file format is supported (CSV, Excel, JSON).

## Testing with curl

```bash
# Register
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"role":"taxpayer","login":"test@example.com","password":"pass123"}'

# Login
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"userid":"test@example.com","password":"pass123","role":"taxpayer"}'

# Get Settings
curl http://localhost:8000/api/settings \
  -H "Authorization: Bearer <YOUR_TOKEN>"
```

## Next Steps

- [ ] Add email notifications
- [ ] Implement advanced reconciliation matching
- [ ] Add data export (PDF/Excel reports)
- [ ] Create admin panel for officer role
- [ ] Add audit trail logging
- [ ] Implement caching for better performance
- [ ] Add webhook support for integrations
- [ ] Create mobile API version

