# Disposable & Fake Email Detection API

A FastAPI-based API to detect disposable, fake, and risky email addresses.

## Features

- ✅ Validate email format
- ✅ Check for disposable email domains
- ✅ Verify MX records exist
- ✅ Detect catch-all domains
- ✅ Calculate risk score

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Start the server:

```bash
uvicorn app:app --reload
```

API will be available at `http://127.0.0.1:8000`

## API Endpoint

### POST /check-email

Request:
```json
{
  "email": "test@example.com"
}
```

Response:
```json
{
  "email": "test@example.com",
  "domain": "example.com",
  "valid_format": true,
  "disposable": false,
  "mx_exists": true,
  "catch_all": false,
  "risk": "LOW",
  "risk_score": 0,
  "reasons": []
}
```

## Documentation

Interactive API docs available at: `http://127.0.0.1:8000/docs`
