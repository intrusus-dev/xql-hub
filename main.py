import os
import re
import yaml
import json
import hmac
import hashlib
import logging
import subprocess
from fastapi import FastAPI, Request, Query, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from typing import List, Optional

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv(
    "LOG_FORMAT",
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=LOG_FORMAT
)
logger = logging.getLogger("xql-hub")

# =============================================================================
# APPLICATION SETUP
# =============================================================================
app = FastAPI(title="XQL Hub", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# =============================================================================
# CONFIGURATION
# =============================================================================
# Webhook secret for GitHub signature verification
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")

# Expected repository for webhook validation (optional but recommended)
EXPECTED_REPO_URL = os.getenv("EXPECTED_REPO_URL", "")

# Input validation limits
MAX_SEARCH_QUERY_LENGTH = 500
MAX_CONTENT_TYPE_LENGTH = 50
MAX_MITRE_ID_LENGTH = 20
MAX_MITRE_IDS_COUNT = 50
MAX_LOG_SOURCE_LENGTH = 100
MAX_SORT_OPTION_LENGTH = 20

# Allowed values (Allowlist approach)
VALID_CONTENT_TYPES = frozenset(["bioc", "correlation", "hunting", "hygiene", "widget", "xql"])
VALID_SORT_OPTIONS = frozenset(["name", "name-desc", "severity", "type"])

# Webhook event types that trigger content refresh
ALLOWED_WEBHOOK_EVENTS = frozenset({"push", "workflow_run", "ping"})

# Regex patterns for validation
MITRE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# =============================================================================
# DATA STORES
# =============================================================================
QUERY_DB = []
FILTER_OPTIONS = {
    "mitre_ids": set(),
    "log_sources": set(),
    "types": set()
}
MITRE_DATA = {}
MITRE_TACTICS = []

# Content type display mappings
CONTENT_TYPE_LABELS = {
    "hunting": "Threat Hunting",
    "bioc": "BIOC",
    "correlation": "Correlation Rule",
    "hygiene": "IT Hygiene",
    "widget": "Dashboard Widget",
    "xql": "XQL Query"
}


# =============================================================================
# INPUT VALIDATION FUNCTIONS
# =============================================================================
def sanitize_string(value: str, max_length: int = 500, allow_empty: bool = True) -> Optional[str]:
    """
    Sanitize a string input by trimming and limiting length.

    Args:
        value: The string to sanitize
        max_length: Maximum allowed length (truncates if exceeded)
        allow_empty: If False, returns None for empty strings

    Returns:
        Sanitized string, or None if input is invalid/empty (when allow_empty=False)
    """
    if not isinstance(value, str):
        logger.debug(f"sanitize_string received non-string type: {type(value).__name__}")
        return None

    value = value.strip()

    if not allow_empty and not value:
        return None

    # Limit length
    if len(value) > max_length:
        value = value[:max_length]

    return value


def validate_content_type(content_type: str) -> str:
    # Validate content type against allowlist.
    sanitized = sanitize_string(content_type, MAX_CONTENT_TYPE_LENGTH)
    if sanitized is None:
        return "all"
    content_type = sanitized.lower()
    if content_type and content_type != "all" and content_type not in VALID_CONTENT_TYPES:
        logger.warning(f"Invalid content_type received: {content_type[:50]}")
        return "all"
    return content_type


def validate_sort_option(sort_by: str) -> str:
    # Validate sort option against allowlist.
    # Note: Membership check against VALID_SORT_OPTIONS is sufficient validation
    sanitized = sanitize_string(sort_by, MAX_SORT_OPTION_LENGTH)
    if sanitized is None:
        return "name"
    sort_by = sanitized.lower()
    if sort_by not in VALID_SORT_OPTIONS:
        logger.warning(f"Invalid sort_by received: {sort_by}")
        return "name"
    return sort_by


def validate_mitre_id(mitre_id: str) -> Optional[str]:
    """Validate a single MITRE ID format."""
    sanitized = sanitize_string(mitre_id, MAX_MITRE_ID_LENGTH)
    if sanitized is None:
        return None
    mitre_id = sanitized.upper()
    if mitre_id and MITRE_ID_PATTERN.match(mitre_id):
        return mitre_id
    return None


def validate_mitre_ids(mitre_ids: List[str]) -> List[str]:
    """Validate and filter a list of MITRE IDs."""
    if not isinstance(mitre_ids, list):
        return []

    # Limit count
    mitre_ids = mitre_ids[:MAX_MITRE_IDS_COUNT]

    validated = []
    for mid in mitre_ids:
        valid_mid = validate_mitre_id(mid)
        if valid_mid:
            validated.append(valid_mid)

    return validated


def validate_log_source(log_source: str) -> str:
    """Validate log source against known values."""
    sanitized = sanitize_string(log_source, MAX_LOG_SOURCE_LENGTH)
    if sanitized is None:
        return "all"
    log_source = sanitized

    if log_source and log_source != "all":
        # Check against known log sources
        if log_source not in FILTER_OPTIONS["log_sources"]:
            logger.warning(f"Unknown log_source received: {log_source[:50]}")
            return "all"

    return log_source


# =============================================================================
# SECURITY FUNCTIONS
# =============================================================================
def verify_github_signature(payload: bytes, signature: str) -> bool:
    """
    Verify that the webhook payload was sent by GitHub.
    Uses HMAC-SHA256 to compare the signature.
    """
    if not WEBHOOK_SECRET:
        logger.error("GITHUB_WEBHOOK_SECRET not configured - rejecting webhook")
        return False

    if not signature or not signature.startswith("sha256="):
        logger.warning("Invalid or missing webhook signature format")
        return False

    expected_signature = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected_signature, signature)


def verify_git_repository() -> bool:
    """
    Verify we're in the expected git repository.

    SECURITY: This check prevents Server-Side Request Forgery (SSRF) attacks where
    an attacker could potentially configure the webhook to pull from a malicious
    repository containing crafted YAML files or executable code. By verifying
    the git remote URL matches our expected repository, we ensure that even if
    the webhook endpoint is discovered or exposed, it can only pull from the
    legitimate source repository.

    Returns:
        True if verification passes or is not configured (EXPECTED_REPO_URL empty).
        False if the current git remote doesn't match the expected URL.
    """
    if not EXPECTED_REPO_URL:
        # No verification configured - allow (but log recommendation in strict mode)
        return True

    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            logger.error("Failed to get git remote URL")
            return False

        current_url = result.stdout.strip()

        # Normalize URLs for comparison (handle .git suffix, https vs. git protocols)
        def normalize_url(url):
            url = url.rstrip("/").rstrip(".git")
            url = url.replace("git@github.com:", "https://github.com/")
            return url.lower()

        if normalize_url(current_url) != normalize_url(EXPECTED_REPO_URL):
            logger.error(f"Repository URL mismatch. Expected: {EXPECTED_REPO_URL}, Got: {current_url}")
            return False

        return True

    except subprocess.TimeoutExpired:
        logger.error("Timeout while verifying git repository")
        return False
    except Exception as e:
        logger.error(f"Error verifying git repository: {e}")
        return False


def verify_git_branch() -> Optional[str]:
    """
    Get and verify the current git branch.
    Returns branch name if on main/master, None otherwise.
    """
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            logger.error("Failed to get current git branch")
            return None

        branch = result.stdout.strip()
        allowed_branches = {"main", "master"}

        if branch not in allowed_branches:
            logger.warning(f"Git pull attempted on non-main branch: {branch}")
            return None

        return branch

    except Exception as e:
        logger.error(f"Error checking git branch: {e}")
        return None


# =============================================================================
# DATA LOADING FUNCTIONS
# =============================================================================
def load_mitre_data():
    """Load MITRE ATT&CK data (tactics and techniques) from the JSON file."""
    global MITRE_DATA, MITRE_TACTICS

    data_file = "data/mitre_data.json"

    if os.path.exists(data_file):
        try:
            with open(data_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # New format: { "tactics": [...], "techniques": {...} }
            if "tactics" in data and "techniques" in data:
                MITRE_TACTICS = data["tactics"]
                MITRE_DATA = data["techniques"]
                logger.info(f"Loaded {len(MITRE_TACTICS)} tactics and {len(MITRE_DATA)} techniques")
            else:
                # Legacy format: just techniques
                MITRE_DATA = data
                MITRE_TACTICS = _get_fallback_tactics()
                logger.info(f"Loaded {len(MITRE_DATA)} techniques (legacy format, using fallback tactics)")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in MITRE data file: {e}")
            MITRE_DATA = {}
            MITRE_TACTICS = _get_fallback_tactics()
        except Exception as e:
            logger.error(f"Error loading MITRE data: {e}")
            MITRE_DATA = {}
            MITRE_TACTICS = _get_fallback_tactics()
    else:
        logger.warning(f"{data_file} not found. Run 'python tools/update_mitre.py' to generate it.")
        MITRE_DATA = {}
        MITRE_TACTICS = _get_fallback_tactics()


def _get_fallback_tactics():
    """Fallback tactics list if not available in the data file."""
    return [
        {"id": "TA0043", "name": "Reconnaissance", "shortname": "Reconnaissance", "order": 0},
        {"id": "TA0042", "name": "Resource Development", "shortname": "Resource Dev", "order": 1},
        {"id": "TA0001", "name": "Initial Access", "shortname": "Initial Access", "order": 2},
        {"id": "TA0002", "name": "Execution", "shortname": "Execution", "order": 3},
        {"id": "TA0003", "name": "Persistence", "shortname": "Persistence", "order": 4},
        {"id": "TA0004", "name": "Privilege Escalation", "shortname": "Priv Escalation", "order": 5},
        {"id": "TA0005", "name": "Defense Evasion", "shortname": "Defense Evasion", "order": 6},
        {"id": "TA0006", "name": "Credential Access", "shortname": "Cred Access", "order": 7},
        {"id": "TA0007", "name": "Discovery", "shortname": "Discovery", "order": 8},
        {"id": "TA0008", "name": "Lateral Movement", "shortname": "Lateral Move", "order": 9},
        {"id": "TA0009", "name": "Collection", "shortname": "Collection", "order": 10},
        {"id": "TA0011", "name": "Command and Control", "shortname": "C2", "order": 11},
        {"id": "TA0010", "name": "Exfiltration", "shortname": "Exfiltration", "order": 12},
        {"id": "TA0040", "name": "Impact", "shortname": "Impact", "order": 13},
    ]


def load_queries():
    """Load query definitions from YAML files."""
    global QUERY_DB, FILTER_OPTIONS
    QUERY_DB = []
    FILTER_OPTIONS = {k: set() for k in FILTER_OPTIONS}

    errors = []

    if not os.path.exists("queries"):
        logger.warning("queries directory not found")
        return

    for filename in os.listdir("queries"):
        if not filename.endswith((".yaml", ".yml")):
            continue

        filepath = os.path.join("queries", filename)

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict):
                errors.append(f"{filename}: YAML root must be a dictionary")
                continue

            data['id'] = filename

            # Data Normalization with validation
            if 'content_type' not in data or data['content_type'] not in VALID_CONTENT_TYPES:
                data['content_type'] = 'xql'

            if 'mitre_ids' not in data or not isinstance(data['mitre_ids'], list):
                data['mitre_ids'] = []
            else:
                # Validate MITRE IDs
                data['mitre_ids'] = [
                    mid for mid in data['mitre_ids']
                    if isinstance(mid, str) and MITRE_ID_PATTERN.match(mid.upper())
                ]

            if 'log_sources' not in data or not isinstance(data['log_sources'], list):
                data['log_sources'] = []

            if 'tags' not in data or not isinstance(data['tags'], list):
                data['tags'] = []

            # Populate Filter Lists
            FILTER_OPTIONS["types"].add(data['content_type'])

            for mid in data['mitre_ids']:
                FILTER_OPTIONS["mitre_ids"].add(mid)

            for src in data['log_sources']:
                if isinstance(src, str):
                    FILTER_OPTIONS["log_sources"].add(src)

            QUERY_DB.append(data)

        except yaml.YAMLError as e:
            errors.append(f"{filename}: Invalid YAML - {e}")
        except Exception as e:
            errors.append(f"{filename}: {e}")

    # Log summary
    logger.info(f"Loaded {len(QUERY_DB)} queries from {len(os.listdir('queries'))} files")

    if errors:
        for error in errors:
            logger.error(f"Query load error: {error}")


# Initialize data on startup
load_mitre_data()
load_queries()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def organize_mitre_by_tactic():
    """Organize available MITRE IDs by tactic for the matrix view."""
    techniques_in_use = {}
    for query in QUERY_DB:
        for mid in query.get('mitre_ids', []):
            if not isinstance(mid, str):
                continue
            base_id = mid.split('.')[0]
            if base_id not in techniques_in_use:
                techniques_in_use[base_id] = {
                    'id': base_id,
                    'subtechniques': set()
                }
            if '.' in mid:
                techniques_in_use[base_id]['subtechniques'].add(mid)

    return techniques_in_use


def safe_search_match(query_item: dict, search_term: str) -> bool:
    """
    Safely check if a search term matches a query item.
    Avoids potential issues with very large or malformed data.
    """
    try:
        # Only search specific fields, not the entire serialized object
        searchable_fields = ['name', 'description', 'author', 'query']
        searchable_tags = query_item.get('tags', [])

        for field in searchable_fields:
            value = query_item.get(field, '')
            if isinstance(value, str) and search_term in value.lower():
                return True

        # Search tags
        for tag in searchable_tags:
            if isinstance(tag, str) and search_term in tag.lower():
                return True

        return False
    except Exception:
        return False


# =============================================================================
# ROUTES
# =============================================================================
@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    """Render the landing page with all queries and filters available."""
    techniques_in_use = organize_mitre_by_tactic()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "queries": QUERY_DB,
        "filters": {k: sorted(list(v)) for k, v in FILTER_OPTIONS.items()},
        "tactics": MITRE_TACTICS,
        "techniques_in_use": techniques_in_use,
        "mitre_data": MITRE_DATA,
        "content_type_labels": CONTENT_TYPE_LABELS
    })


@app.get("/contribute", response_class=HTMLResponse)
async def contribute_wizard(request: Request):
    """Render the contribution wizard page."""
    return templates.TemplateResponse("wizard.html", {
        "request": request,
        "tactics": MITRE_TACTICS,
        "mitre_data": MITRE_DATA
    })


@app.get("/search", response_class=HTMLResponse)
async def search(
        request: Request,
        q: str = "",
        content_type: str = "",
        mitre: List[str] = Query(default=[]),
        log_source: str = "",
        sort_by: str = "name"
):
    """Search and filter queries with validated inputs."""

    # Validate and sanitize all inputs
    sanitized_q = sanitize_string(q, MAX_SEARCH_QUERY_LENGTH)
    search_query = sanitized_q.lower() if sanitized_q else ""
    content_type = validate_content_type(content_type)
    mitre_ids = validate_mitre_ids(mitre)
    log_source = validate_log_source(log_source)
    sort_by = validate_sort_option(sort_by)

    filtered = list(QUERY_DB)

    # 1. Text Search (using the safe search function)
    if search_query:
        filtered = [x for x in filtered if safe_search_match(x, search_query)]

    # 2. Filter by Content Type
    if content_type and content_type != "all":
        filtered = [x for x in filtered if x.get('content_type') == content_type]

    # 3. Filter by MITRE (multi-select - match ANY selected)
    if mitre_ids:
        def matches_mitre(query_item):
            query_mitre = query_item.get('mitre_ids', [])
            if not isinstance(query_mitre, list):
                return False
            for selected in mitre_ids:
                for qm in query_mitre:
                    if isinstance(qm, str) and (qm == selected or qm.startswith(selected + '.')):
                        return True
            return False

        filtered = [x for x in filtered if matches_mitre(x)]

    # 4. Filter by Log Source
    if log_source and log_source != "all":
        filtered = [
            x for x in filtered
            if log_source in x.get('log_sources', [])
        ]

    # 5. Sorting
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4, '': 5}

    try:
        if sort_by == "name":
            filtered = sorted(filtered, key=lambda x: str(x.get('name', '')).lower())
        elif sort_by == "name-desc":
            filtered = sorted(filtered, key=lambda x: str(x.get('name', '')).lower(), reverse=True)
        elif sort_by == "severity":
            filtered = sorted(
                filtered,
                key=lambda x: severity_order.get(str(x.get('severity', '')).lower(), 5)
            )
        elif sort_by == "type":
            filtered = sorted(filtered, key=lambda x: str(x.get('content_type', '')))
    except Exception as e:
        logger.error(f"Error sorting results: {e}")
        # Return unsorted on error

    return templates.TemplateResponse("partials/query_cards.html", {
        "request": request,
        "queries": filtered
    })


@app.get("/api/filters", response_class=JSONResponse)
async def get_filters():
    """API endpoint to get all available filter options."""
    return {
        "types": sorted(list(FILTER_OPTIONS["types"])),
        "log_sources": sorted(list(FILTER_OPTIONS["log_sources"])),
        "mitre_ids": sorted(list(FILTER_OPTIONS["mitre_ids"])),
        "tactics": MITRE_TACTICS,
        "mitre_data": MITRE_DATA
    }


@app.get("/api/content-types", response_class=JSONResponse)
async def get_content_types():
    """API endpoint to get content type labels."""
    return CONTENT_TYPE_LABELS


@app.get("/api/mitre", response_class=JSONResponse)
async def get_mitre_data():
    """API endpoint to get full MITRE ATT&CK data."""
    return {
        "tactics": MITRE_TACTICS,
        "techniques": MITRE_DATA
    }


@app.post("/webhook/refresh")
async def refresh_content(
        request: Request,
        x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
        x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event")
):
    """
    Called by GitHub Webhook. Pulls the latest changes and reloads memory.

    Security measures:
    - Validates GitHub webhook signature using HMAC-SHA256
    - Only processes 'push' and 'workflow_run' events
    - Verifies repository URL matches expected (if configured)
    - Verifies we're on main branch
    - Uses --ff-only to prevent unexpected merges
    - Requires GITHUB_WEBHOOK_SECRET environment variable
    """
    # Read the raw body for signature verification
    body = await request.body()

    # Verify the webhook signature
    if not verify_github_signature(body, x_hub_signature_256 or ""):
        logger.warning(
            f"Webhook signature verification failed from {request.client.host if request.client else 'unknown'}")
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing webhook signature. Ensure GITHUB_WEBHOOK_SECRET is configured."
        )

    # Only allow specific GitHub events (empty string won't match any allowed event)
    if x_github_event not in ALLOWED_WEBHOOK_EVENTS:
        logger.info(f"Ignoring webhook event: {x_github_event}")
        return {"status": "ignored", "message": f"Event '{x_github_event}' is not processed"}

    # Handle ping event (sent when the webhook is first configured)
    if x_github_event == "ping":
        logger.info("Webhook ping received - configuration successful")
        return {"status": "success", "message": "Webhook configured successfully"}

    # Verify the repository before pulling
    if not verify_git_repository():
        raise HTTPException(
            status_code=403,
            detail="Repository verification failed"
        )

    # Verify we're on an allowed branch
    branch = verify_git_branch()
    if not branch:
        raise HTTPException(
            status_code=403,
            detail="Git pull only allowed on main/master branch"
        )

    try:
        # Pull the latest code from git with strict options
        # --ff-only: Only fast-forward, fail if diverged
        # This prevents unexpected merges
        result = subprocess.run(
            ["git", "pull", "--ff-only", "origin", branch],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                # Disable git hooks that could execute arbitrary code
                "GIT_HOOKS_PATH": "/dev/null",
                # Disable credential helpers
                "GIT_ASKPASS": "/bin/true",
                "GIT_TERMINAL_PROMPT": "0"
            }
        )

        # Reload MITRE data and queries into memory
        load_mitre_data()
        load_queries()

        logger.info(f"Webhook refresh completed successfully on branch {branch}")

        return {
            "status": "success",
            "message": "Content updated",
            "branch": branch,
            "git_output": result.stdout.strip() if result.stdout else "Up to date"
        }

    except subprocess.TimeoutExpired:
        logger.error("Git pull timed out")
        raise HTTPException(status_code=504, detail="Git pull timed out")
    except subprocess.CalledProcessError as e:
        logger.error(f"Git pull failed: {e.stderr if e.stderr else str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Git pull failed: {e.stderr if e.stderr else str(e)}"
        )
    except Exception as e:
        logger.error(f"Refresh failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Refresh failed: {str(e)}")


# =============================================================================
# HEALTH CHECK
# =============================================================================
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "queries_loaded": len(QUERY_DB),
        "tactics_loaded": len(MITRE_TACTICS),
        "techniques_loaded": len(MITRE_DATA)
    }


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    import uvicorn

    # Use environment variables for configuration with sensible defaults
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("DEBUG", "false").lower() == "true"

    logger.info(f"Starting XQL Hub on {host}:{port} (debug={debug})")

    uvicorn.run(
        "main:app" if debug else app,
        host=host,
        port=port,
        reload=debug
    )