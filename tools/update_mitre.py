import requests
import json
import os

# Source: MITRE CTI GitHub (Enterprise ATT&CK)
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

print(f"Downloading MITRE ATT&CK data from {url}...")
data = requests.get(url).json()

# ============================================================================
# TACTICS EXTRACTION
# ============================================================================
# Extract tactics directly from the MITRE data source
tactics_map = {}

for obj in data['objects']:
    if obj['type'] == 'x-mitre-tactic' and not obj.get('revoked', False):
        external_refs = obj.get('external_references', [])
        tactic_id = next((r['external_id'] for r in external_refs if r['source_name'] == 'mitre-attack'), None)

        if tactic_id:
            # x_mitre_shortname is the kill chain phase name (e.g., "initial-access")
            shortname = obj.get('x_mitre_shortname', '')
            tactics_map[tactic_id] = {
                "name": obj['name'],
                "shortname": shortname,
                "description": obj.get('description', '')
            }

# Define kill chain order (this is stable and part of the framework definition)
KILL_CHAIN_ORDER = [
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
]

# Build ordered tactics list with display-friendly short names
tactics_list = []
for idx, tactic_id in enumerate(KILL_CHAIN_ORDER):
    if tactic_id in tactics_map:
        tactic = tactics_map[tactic_id]
        # Create display-friendly short names for the UI
        display_shortnames = {
            "TA0043": "Reconnaissance",
            "TA0042": "Resource Dev",
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Priv Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Cred Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Move",
            "TA0009": "Collection",
            "TA0011": "C2",
            "TA0010": "Exfiltration",
            "TA0040": "Impact",
        }
        tactics_list.append({
            "id": tactic_id,
            "name": tactic['name'],
            "shortname": display_shortnames.get(tactic_id, tactic['name']),
            "kill_chain_phase": tactic['shortname'],
            "order": idx
        })

# Build slug to ID mapping from extracted data
tactic_slug_to_id = {t['kill_chain_phase']: t['id'] for t in tactics_list}

print(f"Extracted {len(tactics_list)} tactics")

# ============================================================================
# TECHNIQUES EXTRACTION
# ============================================================================
techniques_map = {}

for obj in data['objects']:
    if obj['type'] == 'attack-pattern' and not obj.get('revoked', False):
        external_refs = obj.get('external_references', [])
        mitre_id = next((r['external_id'] for r in external_refs if r['source_name'] == 'mitre-attack'), None)

        if mitre_id:
            tactic_slugs = []
            if 'kill_chain_phases' in obj:
                for phase in obj['kill_chain_phases']:
                    if phase['kill_chain_name'] == 'mitre-attack':
                        tactic_slugs.append(phase['phase_name'])

            # Convert slugs to tactic IDs
            tactic_ids = [tactic_slug_to_id.get(slug) for slug in tactic_slugs if slug in tactic_slug_to_id]

            techniques_map[mitre_id] = {
                "name": obj['name'],
                "tactic_ids": tactic_ids
            }

print(f"Extracted {len(techniques_map)} techniques")

# ============================================================================
# BUILD FINAL OUTPUT
# ============================================================================
final_db = {
    "tactics": tactics_list,
    "techniques": techniques_map
}

# Ensure directory exists
os.makedirs("data", exist_ok=True)

with open("data/mitre_data.json", "w") as f:
    json.dump(final_db, f, indent=2)

print(f"Success! Created data/mitre_data.json")
print(f"  - {len(tactics_list)} tactics")
print(f"  - {len(techniques_map)} techniques")