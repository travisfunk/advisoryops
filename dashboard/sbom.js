/* Private SBOM import. No inventory uploads, persistence, or external lookups. */
(function(root) {
  'use strict';
  const MAX_BYTES = 10 * 1024 * 1024, MAX_COMPONENTS = 10000;
  const text = value => typeof value === 'string' ? value.trim() : '';
  const norm = value => text(value).toLowerCase().replace(/[_\-./]+/g, ' ').replace(/\s+/g, ' ').trim();
  const list = value => Array.isArray(value) ? value : [];
  const generic = new Set(['server', 'client', 'core', 'library', 'software', 'system', 'application', 'runtime', 'unknown', 'noassertion']);
  function usable(value) { return !!value && !['NOASSERTION', 'NONE'].includes(value); }
  function purl(value) {
    const m = text(value).match(/^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)(?:\?[^#]*)?(?:#.*)?$/);
    if (!m) return null;
    try {
      const at = m[2].lastIndexOf('@');
      const path = at > 0 ? m[2].slice(0, at) : m[2];
      const parts = path.split('/').map(decodeURIComponent);
      if (parts.some(x => !x)) return null;
      return {name: parts.pop(), namespace: parts.join('/'), version: at > 0 ? decodeURIComponent(m[2].slice(at + 1)) : ''};
    } catch (_) { return null; }
  }
  function cpe(value) {
    const raw = text(value);
    const parts = raw.match(/(?:\\.|[^:])+/g);
    if (!parts || raw.includes('::')) return null;
    let part, vendor, name, version;
    if (raw.startsWith('cpe:2.3:') && parts.length === 13) {
      [part, vendor, name, version] = parts.slice(2, 6);
    } else if (raw.startsWith('cpe:/') && parts.length >= 4) {
      part = parts[1].slice(1); [vendor, name, version] = parts.slice(2, 5);
    } else return null;
    if (!['a', 'o', 'h'].includes(part)) return null;
    try {
      const decode = v => decodeURIComponent(v || '').replace(/\\(.)/g, '$1');
      return {vendor: decode(vendor), name: decode(name), version: decode(version)};
    } catch (_) { return null; }
  }
  function parseSBOM(input, device) {
    const doc = typeof input === 'string' ? JSON.parse(input.replace(/^\uFEFF/, '')) : input;
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw Error('Choose a CycloneDX or SPDX JSON document.');
    let format, entries, suggestedDevice;
    if (doc.bomFormat === 'CycloneDX' && /^1\.[2-7]$/.test(text(doc.specVersion))) {
      if (doc.components !== undefined && !Array.isArray(doc.components)) throw Error('CycloneDX components must be an array.');
      format = 'CycloneDX ' + doc.specVersion;
      suggestedDevice = text(doc.metadata?.component?.name);
      entries = list(doc.components).slice();
      if (doc.metadata?.component) entries.unshift(doc.metadata.component);
    } else if (/^SPDX-2\.[23]$/.test(text(doc.spdxVersion))) {
      if (!Array.isArray(doc.packages)) throw Error('SPDX packages must be an array.');
      format = doc.spdxVersion;
      suggestedDevice = text(doc.name);
      entries = doc.packages.slice();
    } else throw Error('Supported formats: CycloneDX 1.2–1.7 JSON and SPDX 2.2/2.3 JSON.');
    const components = [], warnings = [], seen = new Map();
    let visited = 0, skipped = 0;
    // Iteration avoids stack overflow on deeply nested, untrusted documents.
    for (let pos = 0; pos < entries.length; pos++) {
      const entry = entries[pos];
      if (++visited > MAX_COMPONENTS) throw Error('SBOM exceeds the 10,000 component limit. Split it by device.');
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) { skipped++; continue; }
      if (entry.components !== undefined && !Array.isArray(entry.components)) throw Error('Nested components must be an array.');
      entries.push(...list(entry.components));
      const name = text(entry.name);
      if (!usable(name)) { skipped++; continue; }
      const refs = list(entry.externalRefs);
      const packageUrl = text(entry.purl) || text(refs.find(r => r?.referenceType === 'purl')?.referenceLocator);
      const cpes = [text(entry.cpe), ...refs.filter(r => ['cpe22Type', 'cpe23Type'].includes(r?.referenceType)).map(r => text(r.referenceLocator))].filter(Boolean);
      const pv = purl(packageUrl);
      if (packageUrl && !pv) warnings.push(name + ': unrecognized PURL; using declared name.');
      if (cpes.some(v => !cpe(v))) warnings.push(name + ': unrecognized CPE; using declared name.');
      const declaredVersion = text(entry.version) || text(entry.versionInfo);
      const cpeVersions = [...new Set(cpes.map(cpe).filter(Boolean).map(c => c.version).filter(v => v && !/[?*]/.test(v) && v !== '-'))];
      const version = usable(declaredVersion) ? declaredVersion : (pv?.version || (cpeVersions.length === 1 ? cpeVersions[0] : ''));
      if (pv?.version && declaredVersion && pv.version !== declaredVersion) warnings.push(name + ': PURL and declared versions differ; verify the SBOM.');
      if (cpeVersions.some(v => v !== version)) warnings.push(name + ': CPE versions are ambiguous or conflict with the declared version.');
      const vendor = text(entry.manufacturer?.name) || text(entry.manufacturer);
      const supplier = text(entry.supplier?.name) || text(entry.supplier);
      const component = {name, version, vendor, supplier, purl: packageUrl, cpes, scope: text(entry.scope), refs: [text(entry['bom-ref']) || text(entry.SPDXID)].filter(Boolean)};
      const key = JSON.stringify([name, version, vendor, packageUrl, cpes, component.scope]);
      if (seen.has(key)) seen.get(key).refs.push(...component.refs);
      else { seen.set(key, component); components.push(component); }
    }
    if (!components.length) throw Error('No named components found in this SBOM.');
    if (skipped) warnings.push(skipped + ' entries without usable names were skipped.');
    const missing = components.filter(c => !c.version).length;
    if (missing) warnings.push(missing + ' components have no installed version.');
    if (components.some(c => c.scope === 'excluded')) warnings.push('Excluded/test components are included; confirm whether they ship on the device.');
    return {device: text(device) || suggestedDevice || 'Unnamed device', format, components, warnings, skipped_entries: skipped};
  }
  function buildIndex(catalog) {
    if (catalog?.version !== 1 || catalog.matching_policy !== 'product_identity_candidates_only' || !Array.isArray(catalog.issues) || catalog.total_records !== catalog.issues.length) throw Error('Advisory catalog is invalid or incomplete. Retry after the next feed publication.');
    const index = new Map(), ids = new Set();
    let withProducts = 0;
    for (const issue of catalog.issues) {
      if (!text(issue?.issue_id) || ids.has(issue.issue_id)) throw Error('Advisory catalog has missing or duplicate issue IDs.');
      ids.add(issue.issue_id);
      const products = list(issue.affected_products).map(text).filter(Boolean);
      if (text(issue.kev_product)) products.push(text(issue.kev_product));
      if (products.length) withProducts++;
      for (const label of new Set(products)) {
        const full = norm(label), words = full.split(' ');
        // Exact, complete trailing product names; never substring/fuzzy search.
        for (let start = 0; start < words.length; start++) {
          const key = words.slice(start).join(' ');
          if (!key || generic.has(key) || key.length < 4) continue;
          const prefix = words.slice(0, start).join(' ');
          if (!index.has(key)) index.set(key, []);
          index.get(key).push({issue, label, prefix});
        }
      }
    }
    if (catalog.records_with_products !== withProducts) throw Error('Advisory catalog product coverage is inconsistent.');
    return {catalog, index};
  }
  function matchSBOM(sbom, built) {
    const findings = [], unmatched = [];
    for (let componentIndex = 0; componentIndex < sbom.components.length; componentIndex++) {
      const component = sbom.components[componentIndex];
      const identities = [{name: component.name, vendor: component.vendor, via: 'declared component name'}];
      const pv = purl(component.purl);
      if (pv) identities.push({name: pv.name, vendor: component.vendor, via: 'PURL package name (ecosystem not verified)'});
      for (const value of component.cpes) {
        const cp = cpe(value);
        if (cp && !/[?*]/.test(cp.name) && cp.name !== '-') identities.push({name: cp.name, vendor: cp.vendor, via: 'CPE vendor/product name'});
      }
      const candidates = new Map();
      for (const identity of identities) {
        const name = norm(identity.name), vendor = norm(identity.vendor);
        const keys = new Set([name, vendor ? vendor + ' ' + name : name]);
        for (const key of keys) {
          for (const hit of built.index.get(key) || []) {
            // Require an exact vendor prefix when one is provided. Supplier and
            // PURL namespace are not assumed to be the software manufacturer.
            if (vendor && hit.prefix && hit.prefix !== vendor) continue;
            if (vendor && !hit.prefix && norm(hit.label) === name) {
              const advisoryVendors = [hit.issue.vendor, hit.issue.kev_vendor].map(norm).filter(Boolean);
              if (advisoryVendors.length && !advisoryVendors.includes(vendor)) continue;
            }
            if (!candidates.has(hit.issue.issue_id)) candidates.set(hit.issue.issue_id, {...hit, via: identity.via});
          }
        }
      }
      if (!candidates.size) unmatched.push(componentIndex);
      for (const hit of candidates.values()) {
        if (findings.length >= 100000) throw Error('More than 100,000 candidate matches. Split the SBOM by device.');
        findings.push({component_index: componentIndex, component: component.name, installed_version: component.version,
          issue_id: hit.issue.issue_id, title: hit.issue.title || hit.issue.issue_id, priority: hit.issue.priority || '',
          cves: list(hit.issue.cves), source_url: text(hit.issue.canonical_link), affected_product: hit.label,
          advisory_version_evidence: list(hit.issue.affected_versions), status: 'review_required',
          evidence: 'Exact normalized product-name match via ' + hit.via + ': ' + hit.label,
          limitation: 'Installed-version applicability, package ecosystem, deployment conditions, and exploitability are not verified.'});
      }
    }
    findings.sort((a, b) => a.priority.localeCompare(b.priority) || a.component.localeCompare(b.component) || a.issue_id.localeCompare(b.issue_id));
    return {version: 1, checked_at: new Date().toISOString(), device: sbom.device, sbom_format: sbom.format,
      catalog_generated_at: built.catalog.generated_at, advisories_checked: built.catalog.total_records,
      advisories_with_product_evidence: built.catalog.records_with_products,
      advisories_without_product_evidence: built.catalog.total_records - built.catalog.records_with_products,
      components: sbom.components, warnings: sbom.warnings, skipped_entries: sbom.skipped_entries,
      findings, unmatched_component_indexes: unmatched,
      interpretation: 'Candidates require review. No match does not mean safe; only tracked advisories with usable product names can match. No version ranges are evaluated.'};
  }
  const api = {parseSBOM, buildIndex, matchSBOM, MAX_BYTES, MAX_COMPONENTS};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.AdvisorySBOM = api;
  if (typeof document === 'undefined') return;

  const file = document.getElementById('sbom-file');
  if (!file) return;
  const device = document.getElementById('sbom-device'), run = document.getElementById('sbom-run');
  const status = document.getElementById('sbom-status'), results = document.getElementById('sbom-results');
  const download = document.getElementById('sbom-download'), clear = document.getElementById('sbom-clear');
  let report = null, generation = 0, pending = null;
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  function safeURL(value) {
    try { const u = new URL(value); return ['https:', 'http:'].includes(u.protocol) ? u.href : ''; } catch (_) { return ''; }
  }
  function reset() {
    generation++; pending?.abort(); pending = null; report = null;
    results.replaceChildren(); status.textContent = 'Choose a device SBOM to check.';
    download.disabled = true; run.disabled = false;
  }
  file.addEventListener('change', reset);
  device.addEventListener('input', reset);
  clear.addEventListener('click', () => { reset(); file.value = ''; device.value = ''; });
  run.addEventListener('click', async () => {
    reset();
    const selected = file.files[0], token = generation;
    if (!selected) { status.textContent = 'Choose a JSON SBOM first.'; return; }
    if (selected.size > MAX_BYTES) { status.textContent = 'SBOM exceeds the 10 MiB file limit.'; return; }
    run.disabled = true; status.textContent = 'Reading components and loading the full advisory catalog…';
    const controller = new AbortController(); pending = controller;
    const timeout = setTimeout(() => controller.abort(), 60000);
    try {
      const sbom = parseSBOM(await selected.text(), device.value);
      if (token !== generation) return;
      const response = await fetch('sbom_advisories.json', {signal: controller.signal});
      if (!response.ok) throw Error('Unable to load advisory catalog (HTTP ' + response.status + ').');
      const built = buildIndex(await response.json());
      const manifestResponse = await fetch('feed_archive/manifest.json', {signal: controller.signal});
      if (!manifestResponse.ok) throw Error('Unable to verify full-history coverage. Retry the check.');
      const manifest = await manifestResponse.json();
      if (manifest.total_records !== built.catalog.total_records || manifest.generated_at !== built.catalog.generated_at) throw Error('Catalog and full archive snapshots differ. Retry after publication completes.');
      if (token !== generation) return;
      report = matchSBOM(sbom, built);
      const matched = report.components.length - report.unmatched_component_indexes.length;
      status.textContent = sbom.device + ' · ' + sbom.components.length + ' components · ' + report.advisories_checked.toLocaleString() + ' tracked advisories checked · ' + matched + ' components with candidates · ' + report.findings.length + ' advisory matches requiring review.';
      const warnings = [...report.warnings, report.interpretation,
        report.advisories_without_product_evidence + ' advisories have no product names and cannot be matched.',
        'Catalog published ' + report.catalog_generated_at + '. Checks use this snapshot; import again to recheck after updates.'];
      let html = '<div class="prose-card"><h3>Coverage and limitations</h3><ul>' + warnings.map(w => '<li>' + escape(w) + '</li>').join('') + '</ul></div>';
      html += '<h3>Component matches — review required</h3>';
      if (!report.findings.length) html += '<p>No component candidates found in the tracked catalog. This does not establish that this device is safe.</p>';
      for (const finding of report.findings.slice(0, 200)) {
        const url = safeURL(finding.source_url);
        html += '<article class="prose-card"><h3>' + escape(finding.component) + ' <span class="badge">' + escape(finding.priority) + '</span></h3>' +
          '<p>Installed version: ' + escape(finding.installed_version || 'unknown') + '<br>' + escape(finding.title) + ' · ' + escape(finding.issue_id) + '<br>' + escape(finding.cves.join(', ')) + '</p>' +
          '<p>' + escape(finding.evidence) + '<br>Advisory version text: ' + escape(finding.advisory_version_evidence.map(v => typeof v === 'string' ? v : JSON.stringify(v)).join('; ') || 'not provided') + '<br>' + escape(finding.limitation) + '</p>' +
          (url ? '<a href="' + escape(url) + '" target="_blank" rel="noopener noreferrer">Review source advisory ↗</a>' : '<p>No source URL provided.</p>') + '</article>';
      }
      if (report.findings.length > 200) html += '<p>Showing the first 200 matches. Download JSON for all ' + report.findings.length + ' matches.</p>';
      html += '<details><summary>Imported components (' + report.components.length + ')</summary><ul>' + report.components.map((c, i) => '<li>' + escape(c.name) + ' ' + escape(c.version || '(version unknown)') + ' — ' + (report.unmatched_component_indexes.includes(i) ? 'no tracked candidate' : 'review required') + '</li>').join('') + '</ul></details>';
      results.innerHTML = html; download.disabled = false;
    } catch (error) {
      if (token === generation) { report = null; results.replaceChildren(); status.textContent = error.name === 'AbortError' ? 'Catalog request timed out. Retry the check.' : 'Check failed: ' + error.message; }
    } finally {
      clearTimeout(timeout);
      if (token === generation) { run.disabled = false; pending = null; }
    }
  });
  download.addEventListener('click', () => {
    if (!report) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2) + '\n'], {type:'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = 'advisoryops-sbom-report.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
