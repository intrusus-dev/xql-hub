import os
import yaml
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from typing import List, Optional

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

QUERY_DB = []
FILTER_OPTIONS = {
    "mitre_ids": set(),
    "datasets": set(),
    "types": set(),
    "categories": set()
}


def load_queries():
    global QUERY_DB, FILTER_OPTIONS
    QUERY_DB = []
    # Reset filters
    FILTER_OPTIONS = {k: set() for k in FILTER_OPTIONS}

    if os.path.exists("queries"):
        for filename in os.listdir("queries"):
            if filename.endswith(".yaml"):
                with open(f"queries/{filename}", "r") as f:
                    try:
                        data = yaml.safe_load(f)
                        data['id'] = filename  # track filename

                        # Data Normalization
                        if 'content_type' not in data: data['content_type'] = 'xql'
                        if 'mitre_ids' not in data: data['mitre_ids'] = []
                        if 'dataset' not in data: data['dataset'] = 'unknown'

                        # Populate Filter Lists
                        FILTER_OPTIONS["types"].add(data['content_type'])
                        FILTER_OPTIONS["datasets"].add(data['dataset'])
                        if 'category' in data: FILTER_OPTIONS["categories"].add(data['category'])
                        for mid in data['mitre_ids']: FILTER_OPTIONS["mitre_ids"].add(mid)

                        QUERY_DB.append(data)
                    except Exception as e:
                        print(f"Error loading {filename}: {e}")


load_queries()


@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    # Pass the available filter options to the frontend
    return templates.TemplateResponse("index.html", {
        "request": request,
        "queries": QUERY_DB,
        "filters": {k: sorted(list(v)) for k, v in FILTER_OPTIONS.items()}
    })


@app.get("/search", response_class=HTMLResponse)
async def search(
        request: Request,
        q: str = "",
        content_type: str = "",
        mitre: str = "",
        dataset: str = ""
):
    filtered = QUERY_DB
    q = q.lower()

    # 1. Text Search
    if q:
        filtered = [x for x in filtered if q in str(x).lower()]

    # 2. Filter by Content Type (XQL, Correlation, BIOC)
    if content_type and content_type != "all":
        filtered = [x for x in filtered if x['content_type'] == content_type]

    # 3. Filter by MITRE
    if mitre and mitre != "all":
        filtered = [x for x in filtered if mitre in x['mitre_ids']]

    # 4. Filter by Dataset
    if dataset and dataset != "all":
        filtered = [x for x in filtered if x['dataset'] == dataset]

    return templates.TemplateResponse("partials/query_cards.html", {
        "request": request,
        "queries": filtered
    })

# This allows you to run the app by pressing Play in PyCharm
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)