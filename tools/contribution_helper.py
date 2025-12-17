#!/usr/bin/env python3
"""
Contribution Helper Module

Shared functions for GitHub Actions workflows to validate and process
contribution submissions. Used by validate-contribution.yml and merge-contribution.yml.

Usage:
    from contribution_helper import (
        load_issue_body,
        extract_yaml_content,
        validate_contribution,
        generate_filename,
        sanitize_output
    )
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import yaml

# =============================================================================
# CONSTANTS
# =============================================================================
MAX_BODY_SIZE = 100 * 1024  # 100KB max issue body size
MAX_YAML_SIZE = 50 * 1024  # 50KB max YAML content size
MAX_FILENAME_LENGTH = 100

REQUIRED_FIELDS = ['name', 'author', 'description', 'content_type', 'query']

VALID_CONTENT_TYPES = frozenset(['bioc', 'correlation', 'hunting', 'hygiene', 'widget'])

# Maps content_type to subdirectory name
CONTENT_TYPE_SUBDIRS = {
    'hunting': 'hunting',
    'bioc': 'bioc',
    'correlation': 'correlation',
    'hygiene': 'hygiene',
    'widget': 'widgets'
}

MITRE_ID_PATTERN = re.compile(r'^T\d{4}(\.\d{3})?$')


# =============================================================================
# DATA CLASSES
# =============================================================================
@dataclass
class ValidationResult:
    """Result of contribution validation."""
    success: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    data: Optional[Dict[str, Any]] = None
    filename: str = ""
    content_type: str = ""


# =============================================================================
# CORE FUNCTIONS
# =============================================================================
def load_issue_body(event_path: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Load issue body from GitHub event file.

    Args:
        event_path: Path to GitHub event JSON file. If None, reads from GITHUB_EVENT_PATH env var.

    Returns:
        Tuple of (issue_body, error_message). If successful, error_message is None.
    """
    if event_path is None:
        event_path = os.environ.get('GITHUB_EVENT_PATH', '')

    if not event_path:
        return None, "GITHUB_EVENT_PATH environment variable not set"

    if not os.path.exists(event_path):
        return None, f"Event file does not exist: {event_path}"

    try:
        with open(event_path, 'r', encoding='utf-8') as f:
            event_data = json.load(f)
    except json.JSONDecodeError as e:
        return None, f"Failed to parse event file as JSON: {e}"
    except IOError as e:
        return None, f"Failed to read event file: {e}"

    issue_body = event_data.get('issue', {}).get('body', '')

    if not issue_body:
        return None, "Issue body is empty"

    if len(issue_body) > MAX_BODY_SIZE:
        return None, f"Issue body exceeds maximum size of {MAX_BODY_SIZE} bytes"

    return issue_body, None


def extract_yaml_content(issue_body: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract YAML content from a code block in the issue body.

    Args:
        issue_body: The full issue body text.

    Returns:
        Tuple of (yaml_content, error_message). If successful, error_message is None.
    """
    yaml_match = re.search(r'```ya?ml\s*(.*?)\s*```', issue_body, re.DOTALL)

    if not yaml_match:
        return None, "No YAML code block found in issue body"

    yaml_content = yaml_match.group(1).strip()

    if not yaml_content:
        return None, "YAML code block is empty"

    if len(yaml_content) > MAX_YAML_SIZE:
        return None, f"YAML content exceeds maximum size of {MAX_YAML_SIZE} bytes"

    return yaml_content, None


def parse_yaml(yaml_content: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Parse YAML content safely.

    Args:
        yaml_content: Raw YAML string.

    Returns:
        Tuple of (parsed_data, error_message). If successful, error_message is None.
    """
    try:
        data = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return None, f"Invalid YAML syntax: {e}"

    # yaml.safe_load can return various types (dict, list, str, int, None)
    # We require a dictionary for contribution data
    if not isinstance(data, dict):
        type_name = type(data).__name__ if data is not None else "empty/null"
        return None, f"YAML must be a dictionary/mapping, got: {type_name}"

    return data, None


def validate_contribution(data: Dict[str, Any]) -> ValidationResult:
    """
    Validate contribution data against schema requirements.

    Args:
        data: Parsed YAML data dictionary.

    Returns:
        ValidationResult with success status, errors, warnings, and metadata.
    """
    errors = []
    warnings = []

    # Check required fields
    missing = [f for f in REQUIRED_FIELDS if f not in data or not data[f]]
    if missing:
        errors.append(f"Missing required fields: {', '.join(missing)}")

    # Validate content_type
    content_type = data.get('content_type', '')
    if not isinstance(content_type, str):
        errors.append(f"content_type must be a string, got: {type(content_type).__name__}")
        content_type = ''
    elif content_type not in VALID_CONTENT_TYPES:
        errors.append(f"Invalid content_type '{content_type}'. Must be one of: {sorted(VALID_CONTENT_TYPES)}")

    # BIOC-specific validation
    if content_type == 'bioc':
        query = str(data.get('query', '')).lower()
        if 'xdr_data' not in query and 'cloud_audit_log' not in query:
            errors.append("BIOC rules must use xdr_data or cloud_audit_log dataset")

        if 'event_type' not in query:
            warnings.append("BIOC rules should filter on event_type")

        mitre_ids = data.get('mitre_ids', [])
        if isinstance(mitre_ids, list) and len(mitre_ids) > 3:
            errors.append("BIOC rules support maximum 3 MITRE techniques")

    # Widget-specific validation
    if content_type == 'widget':
        query = str(data.get('query', '')).lower()
        if '| view' not in query:
            warnings.append("Widget queries should include a | view statement for visualization")

    # Validate MITRE IDs
    for mid in data.get('mitre_ids', []):
        if not isinstance(mid, str):
            errors.append(f"MITRE ID must be a string, got: {type(mid).__name__}")
        elif not MITRE_ID_PATTERN.match(mid):
            errors.append(f"Invalid MITRE technique ID format: {mid}")

    # Generate filename
    filename = generate_filename(data.get('name', ''))

    return ValidationResult(
        success=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        data=data,
        filename=filename,
        content_type=content_type
    )


def generate_filename(name: str) -> str:
    """
    Generate a safe filename from the query name.

    Args:
        name: The query name.

    Returns:
        Sanitized filename (without extension).
    """
    if not isinstance(name, str):
        return 'unnamed_query'

    # Convert to lowercase and replace non-alphanumeric with underscores
    filename = re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')

    # Limit length
    filename = filename[:MAX_FILENAME_LENGTH]

    # Ensure we have a valid filename
    if not filename:
        return 'unnamed_query'

    # Safety check for path traversal (should never happen after above sanitization)
    if '..' in filename or '/' in filename or '\\' in filename:
        return 'unnamed_query'

    return filename


def get_subdir_for_content_type(content_type: str) -> str:
    """
    Get the subdirectory name for a content type.

    Args:
        content_type: The content type string.

    Returns:
        Subdirectory name, or empty string if content type is unknown.
    """
    return CONTENT_TYPE_SUBDIRS.get(content_type, '')


def sanitize_output(value: Any) -> str:
    """
    Sanitize a value for safe use in GitHub Actions output.

    Escapes special characters that have meaning in GitHub Actions.

    Args:
        value: Any value to sanitize.

    Returns:
        Sanitized string safe for GitHub Actions output.
    """
    if not isinstance(value, str):
        value = str(value) if value is not None else ''

    # Escape characters with special meaning in GitHub Actions
    return value.replace('%', '%25').replace('\n', '%0A').replace('\r', '%0D')


def add_created_date(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add created date to data if not present.

    Args:
        data: The contribution data dictionary.

    Returns:
        Data dictionary with 'created' field set.
    """
    if 'created' not in data:
        data['created'] = date.today().isoformat()
    return data


def write_yaml_file(data: Dict[str, Any], filepath: str) -> Optional[str]:
    """
    Write contribution data to a YAML file.

    Args:
        data: The contribution data dictionary.
        filepath: Path where to write the file.

    Returns:
        Error message if failed, None if successful.
    """
    try:
        # Ensure directory exists
        dir_path = os.path.dirname(filepath)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

        return None
    except IOError as e:
        return f"Failed to write file: {e}"
    except yaml.YAMLError as e:
        return f"Failed to serialize YAML: {e}"


def write_github_output(outputs: Dict[str, str]) -> Optional[str]:
    """
    Write outputs to GitHub Actions output file.

    Args:
        outputs: Dictionary of output name -> value pairs.

    Returns:
        Error message if failed, None if successful.
    """
    output_file = os.environ.get('GITHUB_OUTPUT', '')

    if not output_file:
        return "GITHUB_OUTPUT environment variable not set"

    try:
        with open(output_file, 'a', encoding='utf-8') as f:
            for key, value in outputs.items():
                f.write(f"{key}={sanitize_output(value)}\n")
        return None
    except IOError as e:
        return f"Failed to write GitHub output: {e}"


def print_error(message: str) -> None:
    """Print an error message in GitHub Actions format."""
    print(f"::error::{message}")


def print_warning(message: str) -> None:
    """Print a warning message in GitHub Actions format."""
    print(f"::warning::{message}")


# =============================================================================
# MAIN ENTRY POINTS
# =============================================================================
def run_validation() -> int:
    """
    Main entry point for validation workflow.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    # Load issue body
    issue_body, error = load_issue_body()
    if error:
        print_error(error)
        return 1

    # Extract YAML
    yaml_content, error = extract_yaml_content(issue_body)
    if error:
        print_error(error)
        return 1

    # Parse YAML
    data, error = parse_yaml(yaml_content)
    if error:
        print_error(error)
        return 1

    # Validate
    result = validate_contribution(data)

    if not result.success:
        for err in result.errors:
            print_error(err)
        return 1

    # Write outputs
    error = write_github_output({
        'filename': result.filename,
        'content_type': result.content_type,
        'warnings': '; '.join(result.warnings)
    })

    if error:
        print_error(error)
        return 1

    print("✅ Validation passed!")
    for warning in result.warnings:
        print_warning(warning)

    return 0


def run_extraction() -> int:
    """
    Main entry point for merge/extraction workflow.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    # Load issue body
    issue_body, error = load_issue_body()
    if error:
        print_error(error)
        return 1

    # Extract YAML
    yaml_content, error = extract_yaml_content(issue_body)
    if error:
        print_error(error)
        return 1

    # Parse YAML
    data, error = parse_yaml(yaml_content)
    if error:
        print_error(error)
        return 1

    # Validate
    result = validate_contribution(data)

    if not result.success:
        for err in result.errors:
            print_error(err)
        return 1

    # Add created date
    data = add_created_date(result.data)

    # Determine file path
    subdir = get_subdir_for_content_type(result.content_type)
    if subdir:
        filepath = f"queries/{subdir}/{result.filename}.yaml"
    else:
        filepath = f"queries/{result.filename}.yaml"

    # Write file
    error = write_yaml_file(data, filepath)
    if error:
        print_error(error)
        return 1

    # Write outputs
    error = write_github_output({
        'filepath': filepath,
        'filename': result.filename,
        'query_name': sanitize_output(data.get('name', 'Unknown')),
        'author': sanitize_output(data.get('author', 'Unknown')),
        'content_type': result.content_type
    })

    if error:
        print_error(error)
        return 1

    print(f"Created: {filepath}")
    return 0


if __name__ == '__main__':
    # Allow running directly with a command argument
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == 'validate':
            sys.exit(run_validation())
        elif command == 'extract':
            sys.exit(run_extraction())
        else:
            print(f"Unknown command: {command}")
            print("Usage: python contribution_helper.py [validate|extract]")
            sys.exit(1)
    else:
        print("Usage: python contribution_helper.py [validate|extract]")
        sys.exit(1)