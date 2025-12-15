import os
import yaml
import json
import subprocess
from fastapi import FastAPI, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from typing import List, Optional

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

QUERY_DB = []
FILTER_OPTIONS = {
    "mitre_ids": set(),
    "log_sources": set(),
    "types": set()
}
MITRE_DATA = {}

# MITRE ATT&CK Enterprise Tactics (in kill chain order)
MITRE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "shortname": "recon"},
    {"id": "TA0042", "name": "Resource Development", "shortname": "resource-dev"},
    {"id": "TA0001", "name": "Initial Access", "shortname": "initial-access"},
    {"id": "TA0002", "name": "Execution", "shortname": "execution"},
    {"id": "TA0003", "name": "Persistence", "shortname": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "shortname": "priv-esc"},
    {"id": "TA0005", "name": "Defense Evasion", "shortname": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access", "shortname": "cred-access"},
    {"id": "TA0007", "name": "Discovery", "shortname": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "shortname": "lateral"},
    {"id": "TA0009", "name": "Collection", "shortname": "collection"},
    {"id": "TA0011", "name": "Command and Control", "shortname": "c2"},
    {"id": "TA0010", "name": "Exfiltration", "shortname": "exfil"},
    {"id": "TA0040", "name": "Impact", "shortname": "impact"},
]


def load_mitre_data():
    """Load MITRE ATT&CK data with proper many-to-many tactic mappings."""
    global MITRE_DATA
    if os.path.exists("static/mitre_data.json"):
        try:
            with open("static/mitre_data.json", "r") as f:
                MITRE_DATA = json.load(f)
            print(f"Loaded {len(MITRE_DATA)} MITRE techniques with tactic mappings")
        except Exception as e:
            print(f"Error loading MITRE data: {e}")
            MITRE_DATA = {}
    else:
        print("Warning: static/mitre_data.json not found. Run tools/update_mitre.py to generate it.")
        MITRE_DATA = {}


def load_queries():
    global QUERY_DB, FILTER_OPTIONS
    QUERY_DB = []
    FILTER_OPTIONS = {k: set() for k in FILTER_OPTIONS}

    if os.path.exists("queries"):
        for filename in os.listdir("queries"):
            if filename.endswith(".yaml"):
                with open(f"queries/{filename}", "r") as f:
                    try:
                        data = yaml.safe_load(f)
                        data['id'] = filename

                        # Data Normalization
                        if 'content_type' not in data:
                            data['content_type'] = 'xql'
                        if 'mitre_ids' not in data:
                            data['mitre_ids'] = []
                        if 'log_sources' not in data:
                            data['log_sources'] = []
                        if 'tags' not in data:
                            data['tags'] = []

                        # Populate Filter Lists
                        FILTER_OPTIONS["types"].add(data['content_type'])

                        for mid in data['mitre_ids']:
                            FILTER_OPTIONS["mitre_ids"].add(mid)

                        for src in data['log_sources']:
                            FILTER_OPTIONS["log_sources"].add(src)

                        QUERY_DB.append(data)
                    except Exception as e:
                        print(f"Error loading {filename}: {e}")


load_mitre_data()
load_queries()


def organize_mitre_by_tactic():
    """Organize available MITRE IDs by tactic for the matrix view."""
    # Group techniques by their base ID and collect all from queries
    techniques_in_use = {}
    for query in QUERY_DB:
        for mid in query.get('mitre_ids', []):
            base_id = mid.split('.')[0]  # T1098.007 -> T1098
            if base_id not in techniques_in_use:
                techniques_in_use[base_id] = {
                    'id': base_id,
                    'subtechniques': set()
                }
            if '.' in mid:
                techniques_in_use[base_id]['subtechniques'].add(mid)

    return techniques_in_use


@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    techniques_in_use = organize_mitre_by_tactic()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "queries": QUERY_DB,
        "filters": {k: sorted(list(v)) for k, v in FILTER_OPTIONS.items()},
        "tactics": MITRE_TACTICS,
        "techniques_in_use": techniques_in_use,
        "mitre_data": MITRE_DATA
    })


@app.get("/search", response_class=HTMLResponse)
async def search(
        request: Request,
        q: str = "",
        content_type: str = "",
        mitre: List[str] = Query(default=[]),
        log_source: str = "",
        sort: str = "created-desc"
):
    filtered = QUERY_DB.copy()
    q_lower = q.lower()

    # 1. Text Search
    if q_lower:
        filtered = [x for x in filtered if q_lower in str(x).lower()]

    # 2. Filter by Content Type
    if content_type and content_type != "all":
        filtered = [x for x in filtered if x['content_type'] == content_type]

    # 3. Filter by MITRE (multi-select - match ANY selected)
    if mitre and len(mitre) > 0:
        # Filter out empty strings
        mitre = [m for m in mitre if m and m != "all"]
        if mitre:
            def matches_mitre(query_item):
                query_mitre = query_item.get('mitre_ids', [])
                for selected in mitre:
                    # Check exact match or if it's a parent technique
                    for qm in query_mitre:
                        if qm == selected or qm.startswith(selected + '.'):
                            return True
                return False

            filtered = [x for x in filtered if matches_mitre(x)]

    # 4. Filter by Log Source
    if log_source and log_source != "all":
        filtered = [x for x in filtered if log_source in x.get('log_sources', [])]

    # 5. Sort results
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, '': 4}

    if sort == "name":
        filtered.sort(key=lambda x: x.get('name', '').lower())
    elif sort == "name-desc":
        filtered.sort(key=lambda x: x.get('name', '').lower(), reverse=True)
    elif sort == "severity":
        filtered.sort(key=lambda x: severity_order.get(x.get('severity', '').lower(), 4))
    elif sort == "type":
        filtered.sort(key=lambda x: x.get('content_type', ''))
    elif sort == "created-desc":
        filtered.sort(key=lambda x: x.get('created', ''), reverse=True)
    elif sort == "created-asc":
        filtered.sort(key=lambda x: x.get('created', ''))

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


@app.post("/webhook/refresh")
async def refresh_content(request: Request):
    """
    Called by GitHub Webhook. Pulls latest changes and reloads memory.
    """
    try:
        # 1. Pull latest code from git
        subprocess.run(["git", "pull"], check=True)

        # 2. Reload MITRE data and queries into memory
        load_mitre_data()
        load_queries()

        return {"status": "success", "message": "Content updated"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)