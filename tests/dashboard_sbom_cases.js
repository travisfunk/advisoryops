'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {parseSBOM, buildIndex, matchSBOM} = require('../dashboard/sbom.js');
const cdx = components => ({bomFormat:'CycloneDX',specVersion:'1.6',components});
const issue = (id, products, extra={}) => ({issue_id:id, title:id, priority:'P1', affected_products:products, ...extra});
const catalog = issues => ({version:1, matching_policy:'product_identity_candidates_only', generated_at:'2026-10-16T00:00:00Z',total_records:issues.length,records_with_products:issues.filter(r => r.affected_products?.length || r.kev_product).length,issues});
const check = (components, issues) => matchSBOM(parseSBOM(cdx(components),'device-1'), buildIndex(catalog(issues)));
let tests = 0;
function test(name, fn) { fn(); tests++; console.log('PASS ' + name); }

test('nested components, root, deduplication and device association', () => {
  const doc = cdx([{name:'openssl',version:'1.1.1',components:[{name:'zlib',version:'1.2.8'}]},{name:'openssl',version:'1.1.1'}]);
  doc.metadata = {component:{name:'Scanner 12',version:'3'}};
  const parsed = parseSBOM('\uFEFF' + JSON.stringify(doc));
  assert.equal(parsed.device, 'Scanner 12'); assert.equal(parsed.components.length,3);
  assert.equal(parsed.components.find(c=>c.name==='zlib').version, '1.2.8');
});
test('SPDX versions and external references', () => {
  const parsed = parseSBOM({spdxVersion:'SPDX-2.3',name:'CT',packages:[{SPDXID:'SPDXRef-ssl',name:'openssl',versionInfo:'NOASSERTION',supplier:'Organization: Distributor',externalRefs:[{referenceType:'purl',referenceLocator:'pkg:generic/openssl@1.1.1'},{referenceType:'cpe23Type',referenceLocator:'cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*'}]}]});
  assert.equal(parsed.components[0].version, '1.1.1'); assert.equal(parsed.components[0].vendor, '');
  assert.equal(parsed.components[0].cpes.length,1); assert.equal(parsed.components[0].refs[0],'SPDXRef-ssl');
});
test('unsupported, malformed and empty documents fail without partial inventory', () => {
  for (const doc of [null,[],{}, {spdxVersion:'SPDX-3.0'},cdx([]),{...cdx([]),components:{}},cdx([{name:'x',components:{}}])]) assert.throws(()=>parseSBOM(doc));
  assert.throws(()=>parseSBOM('{'));
});
test('missing versions, invalid identifiers, skipped entries and excluded scope remain visible', () => {
  const parsed = parseSBOM(cdx([null,{}, {name:'openssl',purl:'pkg:broken%',cpe:'bad',scope:'excluded'}]));
  assert.equal(parsed.skipped_entries,2); assert.equal(parsed.components[0].version,''); assert.equal(parsed.warnings.length,5);
});
test('component limit applies before deduplication', () => {
  assert.throws(()=>parseSBOM(cdx(Array.from({length:10001},()=>({name:'openssl'})))), /10,000/);
});
test('exact product identity matches with explanatory evidence, version remains unverified', () => {
  const r = check([{name:'openssl',version:'9.9.9'}],[issue('CVE-1',['OpenSSL OpenSSL'],{affected_versions:['before 1.1.1']})]);
  assert.equal(r.findings.length,1); assert.equal(r.findings[0].status,'review_required');
  assert.deepEqual(r.findings[0].advisory_version_evidence,['before 1.1.1']); assert.equal(r.findings[0].installed_version,'9.9.9');
  assert.equal(r.unmatched_component_indexes.length,0); assert.match(r.findings[0].evidence,/OpenSSL OpenSSL/);
});
test('no substring, fuzzy, title-only or summary-only matching', () => {
  const r = check([{name:'ssl'},{name:'curl'},{name:'server'},{name:'log4j'}],[issue('one',['curlish','Super Server'],{title:'log4j curl ssl',summary:'log4j curl ssl'})]);
  assert.equal(r.findings.length,0); assert.equal(r.unmatched_component_indexes.length,4);
});
test('explicit manufacturers and CPE vendors prevent cross-vendor suffix matches', () => {
  const r = check([{name:'log4j',manufacturer:{name:'Other'}},{name:'unhelpful label',cpe:'cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*'}],[issue('one',['Apache Log4j'])]);
  assert.equal(r.findings.length,1); assert.equal(r.findings[0].component_index,1); assert.match(r.findings[0].evidence,/CPE/);
});
test('PURL package identity preserves installed version and declares ecosystem uncertainty', () => {
  const r = check([{name:'opaque component',purl:'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'}],[issue('one',['Apache Log4j Core'])]);
  assert.equal(r.findings.length,1); assert.equal(r.findings[0].installed_version,'2.14.1'); assert.match(r.findings[0].evidence,/ecosystem not verified/);
});
test('versions and different package scopes are not collapsed', () => {
  const p = parseSBOM(cdx([{name:'a',purl:'pkg:npm/%40one/a@1'},{name:'a',purl:'pkg:npm/%40two/a@1'},{name:'a',version:'2'}]));
  assert.equal(p.components.length,3);
});
test('multi-product and KEV matches deduplicate per component/advisory', () => {
  const r = check([{name:'openssl'}],[issue('one',['OpenSSL OpenSSL','openssl'],{kev_product:'openssl'})]);
  assert.equal(r.findings.length,1);
});
test('coverage includes records without product metadata and all historical candidates', () => {
  const r = check([{name:'openssl'}],[issue('old',['OpenSSL OpenSSL']),issue('new',[]),issue('news',[],{vendor:'OpenSSL',title:'OpenSSL'})]);
  assert.equal(r.advisories_checked,3); assert.equal(r.advisories_without_product_evidence,2); assert.equal(r.findings[0].issue_id,'old');
});
test('catalog failure, duplicate IDs and coverage mismatch cannot produce a clean result', () => {
  assert.throws(()=>buildIndex({...catalog([]),total_records:1}));
  assert.throws(()=>buildIndex(catalog([issue('same',[]),issue('same',[])])));
  assert.throws(()=>buildIndex({...catalog([issue('one',['openssl'])]),records_with_products:0}));
});
test('actual published catalog matches expected products across the full corpus', () => {
  const data = JSON.parse(fs.readFileSync('docs/sbom_advisories.json','utf8'));
  const index = buildIndex(data);
  const report = matchSBOM(parseSBOM(cdx([{name:'openssl',version:'1.0.2'}]),'synthetic-test-device'),index);
  assert.equal(report.advisories_checked, data.total_records);
  assert.ok(data.total_records > 750); assert.ok(report.findings.length > 0);
  assert.ok(report.findings.every(f=>f.status==='review_required'));
});
console.log(tests + ' SBOM behavior checks passed.');
