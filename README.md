# Safe File Sharing App

A Flask + SQLite secure file-sharing application.

## Features
- User registration and login
- Password hashing using Werkzeug
- AES-256-GCM encryption at rest
- Secure random storage filenames
- Authenticated file download
- File type and 25 MB size validation
- Password-protected sharing links
- Expiring sharing links (1–168 hours)
- Download limits (1–100)
- Share link revocation by deleting the file
- SQLite database

## Run on Windows

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

The application automatically creates `database.db` and `.encryption_key` on first run.

## Security notes
- Keep `.encryption_key` secret and backed up securely. If it is lost, encrypted files cannot be decrypted.
- For production, set `FLASK_SECRET_KEY` to a strong random value and use HTTPS.
- Do not expose the Flask development server directly to the Internet.
- Use a production WSGI server, reverse proxy, secure cookie settings, CSRF protection, malware scanning, rate limiting, and object storage for production deployments.
