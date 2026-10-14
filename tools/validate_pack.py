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
# Every scored metric must be produced by the collector for that OS.
import re
cfg=yaml.safe_load((r/'evidence/controls.yml').read_text())
lin=(r/'evidence/linux/iso27001_collect.py').read_text();win=(r/'evidence/windows/iso27001_collect.ps1').read_text()
mets={'linux':set(re.findall(r'm\["(\w+)"\]',lin))|set(re.findall(r'"(backup_\w+)"',lin)),'windows':set(re.findall(r"M '(\w+)'",win))}
has={'linux':set(re.findall(r'@control\("([\w.]+)"\)',lin)),'windows':set(re.findall(r"\$Controls\['([\w.]+)'\]",win))}
n=0
for cid,spec in cfg['controls'].items():
 for c in spec['criteria']:
  for o in ([c['os']] if 'os' in c else ['linux','windows']):
   if cid in has[o]:assert c['metric'] in mets[o],f'{o} collector does not report {c["metric"]} for {cid}';n+=1
assert has['linux']|has['windows']<=set(cfg['controls']),'collector control missing from controls.yml'
print(f'OK: {n} scored criteria match collector metrics ({len(has["linux"])} Linux, {len(has["windows"])} Windows controls)')
