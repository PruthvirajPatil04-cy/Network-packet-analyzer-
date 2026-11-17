"""
CI Guard Test: Ensure Real-Request-Only Mode.
Fails if any static / synthetic / placeholder packet data or generators are introduced.
"""

import os
import re
import pytest

BANNED_TERMS = [
    "sample_packets",
    "mock_data",
    "EXAMPLE_STATS",
    "traffic_gen",
    "random_packet",
]

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
THIS_FILE = os.path.abspath(__file__)
IGNORE_DIRS = {".git", "node_modules", "dist", ".pytest_cache", "__pycache__"}


def test_traffic_gen_file_does_not_exist():
    """Ensure demo_server/traffic_gen.py is permanently removed."""
    gen_path = os.path.join(REPO_ROOT, "demo_server", "traffic_gen.py")
    assert not os.path.exists(gen_path), "demo_server/traffic_gen.py must not exist in real-request-only mode!"


def test_no_banned_static_data_terms():
    """
    Asserts zero occurrences of banned synthetic traffic symbols across the repository.
    """
    violations = []
    regex = re.compile(r"\b(" + "|".join(BANNED_TERMS) + r")\b")

    for root, dirs, files in os.walk(REPO_ROOT):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            if file.endswith((".pyc", ".png", ".jpg", ".ico", ".svg", ".lock", ".log")):
                continue

            file_path = os.path.abspath(os.path.join(root, file))
            if file_path == THIS_FILE:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        match = regex.search(line)
                        if match:
                            rel_path = os.path.relpath(file_path, REPO_ROOT)
                            violations.append(f"{rel_path}:{line_num} contains '{match.group(0)}'")
            except Exception:
                pass

    assert not violations, f"Found banned static traffic symbols:\n" + "\n".join(violations)
