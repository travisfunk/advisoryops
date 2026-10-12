"""Run browser change tracking behavior in Node without network access."""
from pathlib import Path
import re
import shutil
import subprocess

import pytest


def test_changes_since_review():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js required for dashboard behavior checks')
    root = Path(__file__).resolve().parents[1]
    html = (root / 'dashboard/index.html').read_text()
    assert html == (root / 'docs/index.html').read_text()
    code = re.search(r'  // BEGIN VISIT CHANGES(.*?)  // END VISIT CHANGES', html, re.S).group(1)
    cases = (root / 'tests/dashboard_changes_cases.js').read_text()
    subprocess.run([node, '-e', cases.replace('/* IMPLEMENTATION */', code)], check=True)
