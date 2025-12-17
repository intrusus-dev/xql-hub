# XQL Hub API Reference

XQL Hub provides a RESTful API for programmatic access to queries and filters.

## Base URL

```
https://xql-hub.com
```

For local development: `http://127.0.0.1:8000`

## Endpoints

### Get Filter Options

Returns all available filter options for queries.

```
GET /api/filters
```

**Response:**
```json
{
  "types": ["bioc", "correlation", "hunting", "hygiene", "widget"],
  "log_sources": ["Cortex XDR Agent", "Windows Event Logs", ...],
  "mitre_ids": ["T1003", "T1003.001", "T1021.001", ...],
  "tactics": [
    {"id": "TA0001", "name": "Initial Access", "shortname": "Initial Access", "order": 2},
    ...
  ],
  "mitre_data": {
    "T1003": {"name": "OS Credential Dumping", "tactic_ids": ["TA0006"]},
    ...
  }
}
```

### Get Content Type Labels

Returns human-readable labels for content types.

```
GET /api/content-types
```

**Response:**
```json
{
  "hunting": "Threat Hunting",
  "bioc": "BIOC",
  "correlation": "Correlation Rule",
  "hygiene": "IT Hygiene",
  "widget": "Dashboard Widget",
  "xql": "XQL Query"
}
```

### Get MITRE ATT&CK Data

Returns the full MITRE ATT&CK tactics and techniques data.

```
GET /api/mitre
```

**Response:**
```json
{
  "tactics": [
    {"id": "TA0043", "name": "Reconnaissance", "shortname": "Reconnaissance", "order": 0},
    {"id": "TA0042", "name": "Resource Development", "shortname": "Resource Dev", "order": 1},
    ...
  ],
  "techniques": {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic_ids": ["TA0002"]},
    "T1059.001": {"name": "PowerShell", "tactic_ids": ["TA0002"]},
    ...
  }
}
```

### Search Queries

Search and filter queries with various parameters.

```
GET /search
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `q` | string | Free-text search query |
| `content_type` | string | Filter by content type (hunting, bioc, correlation, hygiene, widget) |
| `mitre` | string[] | Filter by MITRE technique IDs (can specify multiple) |
| `log_source` | string | Filter by log source |
| `sort_by` | string | Sort order: `name`, `name-desc`, `severity`, `type` |

**Example:**
```
GET /search?content_type=bioc&mitre=T1003&mitre=T1059&sort_by=severity
```

**Response:** HTML partial (for HTMX integration)

### Health Check

Returns application health status.

```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "queries_loaded": 42,
  "tactics_loaded": 14,
  "techniques_loaded": 625
}
```

### Webhook Refresh (Internal)

Triggers a content refresh from the git repository. Used by GitHub webhooks.

```
POST /webhook/refresh
```

**Headers Required:**
- `X-Hub-Signature-256`: GitHub webhook signature
- `X-GitHub-Event`: Event type (push, workflow_run, ping)

**Response:**
```json
{
  "status": "success",
  "message": "Content updated"
}
```

**Note:** This endpoint requires proper webhook configuration. See [SETUP.md](SETUP.md) for details.

## Error Responses

All endpoints may return the following error responses:

| Status | Description |
|--------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid webhook signature |
| 403 | Forbidden - Repository/branch verification failed |
| 500 | Internal Server Error |
| 503 | Service Unavailable - Webhook disabled |

## Rate Limiting

Currently, there is no rate limiting on the API. Please be respectful with request frequency.

## CORS

CORS is not currently enabled. For cross-origin requests, consider proxying through your own backend.