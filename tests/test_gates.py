import json
from pathlib import Path
from scripts.critical_gate import check
from scripts.zap_gate import count_high

ROOT=Path(__file__).resolve().parent.parent

def test_severity_gate_clean_and_high():
    assert check(ROOT/'security/gate-fixture-clean.json') == 0
    assert check(ROOT/'security/gate-fixture-high.json') == 1

def test_zap_gate_counts_high(tmp_path):
    clean=tmp_path/'clean.json'
    clean.write_text(json.dumps({'site':[{'alerts':[{'riskcode':'2','name':'medium'}]}]}))
    assert count_high(str(clean)) == 0
    bad=tmp_path/'bad.json'
    bad.write_text(json.dumps({'site':[{'alerts':[{'riskcode':'3','name':'critical issue'}]}]}))
    assert count_high(str(bad)) == 1
