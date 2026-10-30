#!/usr/bin/env python3
"""Phase 3 design-artifact integrity check. No vulnerability scans are performed."""
import csv, json, pathlib, math, sys
root=pathlib.Path(__file__).resolve().parents[1]
def rows(file):
 with (root/file).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
th=rows('STRIDE_Threat_Catalog.csv'); risk=rows('Risk_Register_CVSS_v3_1.csv'); matrix=rows('STRIDE_By_DFD_Element.csv'); pne=rows('PNE_Traceability_Updated.csv'); jira=rows('Jira_Threat_Tasks_Planned.csv')
fail=[]
def check(ok,msg):
 print(('PASS' if ok else 'FAIL')+' | '+msg)
 if not ok: fail.append(msg)
check(len(th)>=20, f'{len(th)} threat scenarios')
check(len(matrix)>=30, f'{len(matrix)} DFD element coverage rows')
check(len(risk)>=10, f'{len(risk)} scored risk scenarios')
check(len(pne)==30, '30 original protection needs carried through')
check(len(jira)==len(th), 'Every modeled threat has planned Jira task')
ids={t['Threat_ID'] for t in th}; check(len(ids)==len(th),'Unique TH IDs')
pid={x['PNE_ID'] for x in pne}; check(len(pid)==30,'Unique PNE IDs')
check(set('STRIDE')=={t['STRIDE_Category'] for t in th},'All six STRIDE categories represented')
for x in matrix:
 for a in x['Threat_IDs'].split(';'):
  if a and a not in ids: fail.append('unknown threat in element matrix '+a)
for x in th:
 for a in x['PNE_IDs'].split(';'):
  if a not in pid: fail.append('unknown PNE in threat '+a)
for p in pne:
 for tid in p['STRIDE_Threat_ID_Actual'].split(';'):
  if tid not in ids: fail.append('unknown threat on PNE '+tid)
for r in risk:
 if not r['CVSS_v3_1_Vector'].startswith('CVSS:3.1/') or not 0<=float(r['Base_Score'])<=10:fail.append('invalid CVSS row '+r['Risk_ID'])
 for tid in r['Primary_TH'].split(';'):
  if tid not in ids: fail.append('risk references unknown threat '+tid)
check(not fail, 'All cross-references validate')
print('RESULT:', 'PASS' if not fail else 'FAIL')
sys.exit(0 if not fail else 1)
