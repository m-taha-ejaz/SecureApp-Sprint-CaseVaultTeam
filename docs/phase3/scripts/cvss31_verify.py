#!/usr/bin/env python3
"""Recompute FIRST CVSS v3.1 Base scores in Risk_Register_CVSS_v3_1.csv.
This is a deterministic DESIGN arithmetic check, not a live vulnerability scan.
"""
import csv, pathlib, math, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
W={
 'AV': {'N':.85,'A':.62,'L':.55,'P':.2},
 'AC': {'L':.77,'H':.44},
 'UI': {'N':.85,'R':.62},
 'C': {'N':0,'L':.22,'H':.56},
 'I': {'N':0,'L':.22,'H':.56},
 'A': {'N':0,'L':.22,'H':.56},
}
PR={'U':{'N':.85,'L':.62,'H':.27},'C':{'N':.85,'L':.68,'H':.5}}

def score(vector):
    parts=vector.split('/')
    if parts[0]!='CVSS:3.1': raise ValueError('CVSS v3.1 required')
    d=dict(e.split(':',1) for e in parts[1:])
    if set(d)!={'AV','AC','PR','UI','S','C','I','A'}:raise ValueError('Incomplete/unknown vector')
    iss=1-(1-W['C'][d['C']])*(1-W['I'][d['I']])*(1-W['A'][d['A']])
    impact=6.42*iss if d['S']=='U' else 7.52*(iss-.029)-3.25*(iss-.02)**15
    exploit=8.22*W['AV'][d['AV']]*W['AC'][d['AC']]*PR[d['S']][d['PR']]*W['UI'][d['UI']]
    if impact <= 0: return 0.0
    raw=min((impact+exploit)*(1.08 if d['S']=='C' else 1),10)
    return math.ceil(raw*10-1e-10)/10

def level(score):
    return 'Critical' if score>=9 else 'High' if score>=7 else 'Medium' if score>=4 else 'Low' if score>0 else 'None'

assert score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')==9.8
assert score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H')==8.8
with (ROOT/'Risk_Register_CVSS_v3_1.csv').open(encoding='utf-8-sig',newline='') as f:
    rows=list(csv.DictReader(f))
errors=[]
for row in rows:
    actual=score(row['CVSS_v3_1_Vector'])
    stored=float(row['Base_Score'])
    good=actual==stored and level(actual)==row['Base_Severity']
    print(f"{'PASS' if good else 'FAIL'} {row['Risk_ID']} | {actual:.1f} {level(actual)} | {row['CVSS_v3_1_Vector']}")
    if not good:errors.append(row['Risk_ID'])
print('SUMMARY:',len(rows),'vectors checked;',len(errors),'mismatches')
print('RESULT:', 'PASS' if not errors else 'FAIL')
sys.exit(1 if errors else 0)
