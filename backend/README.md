# AI-Eye Verification Backend

Python backend for verification pipeline, telemetry, and calibration.

## Installation

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
python app.py
```

Server runs on http://localhost:5001

## API Endpoints

- `POST /api/verify-pickle` - Deep pickle analysis
- `POST /api/triangulate` - Cross-validate with all tools
- `GET /api/dashboard` - Dashboard metrics
- `GET /api/review/<hash>` - Reviewer mode data
- `POST /api/run-corpus-check` - Trigger corpus re-scan
- `GET /api/telemetry/stats` - Statistical confidence metrics
- `GET /api/calibration` - Calibration curve data
