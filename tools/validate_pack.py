#!/usr/bin/env python3
from pathlib import Path
import yaml
from xml.etree import ElementTree as ET
r=Path(__file__).resolve().parents[1];ids=set();rids=set()
for p in (r/'policies').glob('*.yml'):
 d=yaml.safe_load(p.read_text())
 for c in d['checks']:
  assert c['id'] not in ids;ids.add(c['id']);assert c['condition'] in ('all','any','none');assert c['rules']
for p in (r/'manager-rules').glob('*.xml'):
 t=ET.parse(p)
 for x in t.findall('.//rule'):
  assert x.attrib['id'] not in rids;rids.add(x.attrib['id'])
print(f'OK: {len(ids)} SCA checks; {len(rids)} XML rules')
