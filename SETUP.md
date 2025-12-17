# XQL Hub Setup Guide

This guide covers how to set up XQL Hub for local development or self-hosting.

## Prerequisites

- Python 3.11+
- pip
- Git

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/intrusus-dev/xql-hub.git
cd xql-hub
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Update MITRE ATT&CK data

```bash
python tools/update_mitre.py
```

This downloads the latest MITRE ATT&CK Enterprise data and generates `data/mitre_data.json`.

### 4. Run the application

```bash
python main.py
```

### 5. Access the application

Open your browser to `http://127.0.0.1:8000`

## Configuration

XQL Hub can be configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Server bind address | `127.0.0.1` |
| `PORT` | Server port | `8000` |
| `DEBUG` | Enable debug mode | `false` |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `LOG_FORMAT` | Log message format | Standard format |

### Webhook Configuration (Optional)

If you want to enable automatic content refresh via GitHub webhooks:

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_WEBHOOK_SECRET` | Secret for webhook signature verification | Yes (for webhooks) |
| `EXPECTED_REPO_URL` | Expected git remote URL for verification | Recommended |
| `STRICT_MODE` | Fail startup if webhook secret missing | `false` |

Example:
```bash
export GITHUB_WEBHOOK_SECRET="your-secure-secret-here"
export EXPECTED_REPO_URL="https://github.com/intrusus-dev/xql-hub.git"
export STRICT_MODE="true"
python main.py
```

## Docker Deployment (Coming Soon)

Docker support is planned for future releases.

## Updating MITRE Data

MITRE ATT&CK data is updated automatically via GitHub Actions every Monday. To update manually:

```bash
python tools/update_mitre.py
```

## Troubleshooting

### Application won't start

1. Check Python version: `python --version` (requires 3.11+)
2. Verify dependencies: `pip install -r requirements.txt`
3. Check for port conflicts on 8000

### MITRE data missing

Run `python tools/update_mitre.py` to generate the data file.

### Webhook not working

1. Verify `GITHUB_WEBHOOK_SECRET` is set
2. Check logs for signature verification failures
3. Ensure the webhook URL is accessible from GitHub

## Development

### Running in development mode

```bash
DEBUG=true python main.py
```

### Running tests

```bash
pip install pytest httpx
pytest tests/ -v
```

### Code formatting

```bash
pip install black isort
black .
isort .
```