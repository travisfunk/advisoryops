const assert = require('node:assert/strict');
let storage = {};
let blocked = false;
const localStorage = {
  getItem: key => { if (blocked) throw Error('blocked'); return storage[key] || null; },
  setItem: (key, value) => { if (blocked) throw Error('blocked'); storage[key] = value; }
};
let healthcareMode = true;
let meta = { generated_at: '2026-10-12T14:39:49Z' };
/* IMPLEMENTATION */
const issue = { issue_id: 'A', priority: 'P2', affected_versions: ['2', '1'], summary: 'No patch available', sources: ['cisa'], last_seen_at: 'yesterday' };
prepareVisitChanges([issue]);
assert.equal(visitChanges.message.includes('Baseline saved'), true);
assert.deepEqual(Object.keys(visitChanges.changes), []);
const baseline = storage[visitKey()];
const longText = 'unchanged prefix '.repeat(30) + 'DIFFERENT END';
assert.equal(visitDisplayValue(longText), longText);
assert.equal(visitDisplayValue([longText]).includes('DIFFERENT END'), true);
prepareVisitChanges([{ ...issue, affected_versions: ['1', '2', '1'], last_seen_at: 'today', score: 150, cves: [], tasks_by_role: {} }]);
assert.deepEqual(Object.keys(visitChanges.changes), []); // ordering, refresh and raw score noise
prepareVisitChanges([{ ...issue, priority: 'P1', affected_versions: ['3'], summary: 'Patch available' }, { issue_id: 'B' }]);
assert.equal(visitChanges.changes.A.type, 'updated');
assert.deepEqual(visitChanges.changes.A.fields.map(f => f.label), ['Priority', 'Affected versions', 'Advisory text']);
assert.equal(visitChanges.changes.A.fields[0].before, 'P2');
assert.equal(visitChanges.changes.A.fields[0].after, 'P1');
assert.equal(visitChanges.changes.B.type, 'new');
assert.equal(storage[visitKey()], baseline); // revisiting does not silently acknowledge changes
acknowledgeVisitChanges([{ ...issue, priority: 'P1' }, { issue_id: 'B' }]);
prepareVisitChanges([{ ...issue, priority: 'P1' }, { issue_id: 'B' }]);
assert.deepEqual(Object.keys(visitChanges.changes), []);
// A disappeared serving-window row is not resolved/deleted, and reappearance is not new.
acknowledgeVisitChanges([{ issue_id: 'B' }]);
prepareVisitChanges([{ ...issue, priority: 'P1' }]);
assert.deepEqual(Object.keys(visitChanges.changes), []);
// Separate baselines for complete medical-device subset and bounded general feed.
healthcareMode = false;
prepareVisitChanges([{ issue_id: 'C' }]);
assert.equal(visitChanges.message.includes('Baseline saved'), true);
assert.equal(visitChanges.changes.C, undefined);
healthcareMode = true;
storage[visitKey()] = '{malformed';
prepareVisitChanges([issue]);
assert.equal(visitChanges.message.includes('Baseline saved'), true);
storage[visitKey()] = JSON.stringify({ version: 1, records: { A: null } });
prepareVisitChanges([issue]);
assert.equal(visitChanges.message.includes('Baseline saved'), true);
blocked = true;
prepareVisitChanges([issue]);
assert.equal(visitChanges.available, false);
assert.equal(visitChanges.message.includes('unavailable'), true);
assert.equal(acknowledgeVisitChanges([issue]), false);
console.log('Browser baseline, meaningful changes, review, scope, corruption and storage checks passed');
