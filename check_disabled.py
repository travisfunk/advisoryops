import json
d = json.load(open('configs/sources.json'))
for s in d['sources']:
    if not s.get('enabled'):
        print(s['source_id'] + '   ' + s['page_type'])
