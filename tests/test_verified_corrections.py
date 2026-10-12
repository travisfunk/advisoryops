from copy import deepcopy
import json

from advisoryops.community_build import merge_baseline_feed
from advisoryops.verified_corrections import apply_verified_corrections
from advisoryops.summarize import _build_user_prompt
from advisoryops.source_mitigations import _build_user_prompt as mitigation_prompt
from advisoryops.sources.openfda_backfill import generate_signals_from_cache


def bad_record():
    return {
        'issue_id': 'UNK-42c8bda5d1c8ebae',
        'sources': ['openfda-recalls-historical'],
        'canonical_link': 'https://api.fda.gov/device/recall.json?search=res_event_number:"30666"',
        'summary': 'No patch is currently available. Update the software to the latest version. ' * 20,
        'title': 'Automated External Defibrillators (Non-Wearable) recall (Philips Medical Systems)',
        'remediation_steps': ['update the software to the latest version'],
        'published_dates': ['2016-02-02'], 'fda_risk_class': '3',
    }


def test_verified_correction_is_source_bound_and_idempotent():
    row = bad_record()
    assert apply_verified_corrections([row]) == 1
    assert row['published_dates'] == ['2004-12-15']
    assert 'No patch is currently available' not in row['summary']
    assert 'terminated on 2016-02-02' in row['summary']
    assert 'current patch availability' in row['summary']
    assert 'update the software to the latest version' not in row['remediation_steps']
    assert not any('patch: no patch' in reason for reason in row['why'])
    assert row['priority'] == 'P0'  # existing FDA Class III clinical floor
    corrected = deepcopy(row)
    assert apply_verified_corrections([row]) == 0
    assert row == corrected


def test_longer_stale_baseline_cannot_revive_bad_guidance():
    old = bad_record()
    new = bad_record()
    apply_verified_corrections([new])
    merged = merge_baseline_feed([new], [old])
    apply_verified_corrections(merged)
    assert merged[0]['summary'] == new['summary']
    assert merged[0]['published_dates'] == ['2004-12-15']
    assert merged[0]['source_mitigations'] == new['source_mitigations']


def test_wrong_event_source_or_issue_is_untouched():
    for field, value in [('issue_id', 'another-issue'), ('sources', ['another-source']),
                         ('canonical_link', 'https://api.fda.gov/device/recall.json?search=res_event_number:"999"')]:
        row = bad_record()
        row[field] = value
        original = deepcopy(row)
        assert apply_verified_corrections([row]) == 0
        assert row == original


def test_summarization_and_mitigations_use_preserved_source_text():
    row = bad_record()
    row['source_summary'] = 'Original recall reason; no operational instructions supplied.'
    assert 'Original recall reason' in _build_user_prompt(row)
    assert 'Update the software' not in _build_user_prompt(row)
    assert 'Original recall reason' in mitigation_prompt(row, 'openfda-recalls-historical')
    assert 'Update the software' not in mitigation_prompt(row, 'openfda-recalls-historical')


def test_fda_initiation_date_wins_and_termination_is_not_publication(tmp_path):
    path = tmp_path / 'recall_30666.json'
    record = {'res_event_number': '30666', '_cyber_relevant': True,
              'product_description': 'Philips monitor', 'reason_for_recall': 'Software defect',
              'event_date_initiated': '2004-12-15', 'event_date_terminated': '2016-02-02'}
    path.write_text(json.dumps(record))
    assert generate_signals_from_cache(cache_dir=tmp_path)[0]['published_date'] == '2004-12-15'
    del record['event_date_initiated']
    path.write_text(json.dumps(record))
    assert generate_signals_from_cache(cache_dir=tmp_path)[0]['published_date'] == ''
