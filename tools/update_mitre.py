import requests
import json
import os

# Source: MITRE CTI GitHub (Enterprise ATT&CK)
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

print(f"Downloading MITRE ATT&CK data from {url}...")
data = requests.get(url).json()

mitre_map = {}

# Iterate through objects to build the map
# 1. Find all relationships (Technique -> Tactic)
# 2. Extract Technique Metadata

for obj in data['objects']:
    if obj['type'] == 'attack-pattern' and not obj.get('revoked', False):
        external_refs = obj.get('external_references', [])
        mitre_id = next((r['external_id'] for r in external_refs if r['source_name'] == 'mitre-attack'), None)

        if mitre_id:
            tactics = []
            if 'kill_chain_phases' in obj:
                for phase in obj['kill_chain_phases']:
                    if phase['kill_chain_name'] == 'mitre-attack':
                        # Convert phase-name (e.g., "privilege-escalation") to Tactic ID
                        # We need a standard map for this, or just store the slug
                        tactics.append(phase['phase_name'])

            mitre_map[mitre_id] = {
                "name": obj['name'],
                "tactics": tactics,  # Stores slugs like 'persistence', 'defense-evasion'
                "is_subtechnique": obj.get('x_mitre_is_subtechnique', False)
            }

# Mapping slugs back to Tactic IDs (TAxxxx)
tactic_slug_to_id = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040"
}

final_db = {}
for mid, data in mitre_map.items():
    tactic_ids = [tactic_slug_to_id.get(slug) for slug in data['tactics'] if slug in tactic_slug_to_id]
    final_db[mid] = {
        "name": data['name'],
        "tactic_ids": tactic_ids
    }

# Ensure directory exists
os.makedirs("static", exist_ok=True)

with open("static/mitre_data.json", "w") as f:
    json.dump(final_db, f, indent=2)

print("Success! Created static/mitre_data.json")