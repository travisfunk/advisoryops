"""Execute the dashboard's metadata renderer to guard strict KEV scope."""
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest


@pytest.mark.parametrize('scope,key,cve,exact,partial', [
    ('full_cisa_kev_catalog', 'exact_cve_id', 0, 3, 7),
    ('full_cisa_kev_catalog', 'exact_cve_id', 2, 3, 7),
    ('enriched_subset', 'exact_cve_id', 0, 0, 0),
    ('full_cisa_kev_catalog', 'vendor', 0, 0, 0),
    (None, None, None, None, None),
])
def test_full_catalog_metadata_controls_strict_overlap(scope, key, cve, exact, partial):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js required for dashboard JavaScript behavior check')
    root = Path(__file__).resolve().parents[1]
    html = (root / 'dashboard/index.html').read_text(encoding='utf-8')
    assert html == (root / 'docs/index.html').read_text(encoding='utf-8')
    function = re.search(r'  function renderKevMethodology\(s, set\) \{.*?\n  \}', html, re.S).group()
    stats = dict(kev_comparison_scope=scope, kev_comparison_key=key,
                 kev_catalog_unique_cves=1721, medical_device_issues=463,
                 kev_md_cve_overlap=cve, kev_md_vendor_overlap=exact,
                 kev_md_vendor_partial_overlap=partial)
    script = function + '\nconst result = {}; renderKevMethodology(' + json.dumps(stats) + ", (id, value) => { if (value != null) result[id] = value; }); console.log(JSON.stringify(result));"
    result = json.loads(subprocess.check_output([node, '-e', script], text=True))
    if scope != 'full_cisa_kev_catalog' or key != 'exact_cve_id':
        assert result == {}
    else:
        assert result['kev-finding-overlap'] == result['meth-cve-overlap'] == cve
        assert result['meth-vendor-overlap'] == exact
        assert result['meth-vendor-partial-overlap'] == partial
        assert result['kev-finding-kev'] == 1721
        assert result['kev-finding-md'] == 463
