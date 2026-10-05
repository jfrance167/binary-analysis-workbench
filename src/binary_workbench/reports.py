"""Versioned JSON and self-contained, inert, searchable HTML presentation."""
import base64
import hashlib
import html
import json
import re
from .safeio import write_new

SCHEMA_VERSION='1.0.0'
JSON_CAP=16*1024**2
HTML_CAP=24*1024**2
STATUSES={'complete','partial','unsupported','failed','unavailable','timeout','output_limit','skipped'}


def validate_report(report):
    """Minimal runtime contract; complete schema validation is exercised by tests."""
    if not isinstance(report,dict) or report.get('schema_version')!=SCHEMA_VERSION:
        raise ValueError('Unsupported report schema; expected 1.0.0')
    for key in ('metadata','sample','static','reverse_engineering','signatures','limits'):
        if not isinstance(report.get(key),dict):
            raise ValueError('Invalid report object')
    if report.get('status') not in STATUSES or not re.fullmatch(r'[0-9a-f]{64}',report['sample'].get('sha256','')):
        raise ValueError('Invalid report identity/status')
    if not isinstance(report.get('findings'),list) or not isinstance(report.get('warnings'),list):
        raise ValueError('Invalid report findings/warnings')
    return report


def json_text(report):
    validate_report(report)
    result=json.dumps(report,ensure_ascii=True,allow_nan=False,indent=2)
    if len(result.encode())>JSON_CAP:
        raise ValueError('JSON report output limit exceeded')
    return result


STYLE='''body{font:16px system-ui;margin:2rem auto;max-width:100rem;padding:0 1rem;background:#101725;color:#edf3ff}a{color:#9cc9ff}input{width:85%;padding:.7rem}article,section{border:1px solid #41516c;padding:1rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px ui-monospace,monospace}h2{color:#adcaff}.note{color:#d6b98c}[hidden]{display:none}label{display:block;margin:1rem 0}nav a{margin-right:1rem}'''
SCRIPT='''const box=document.getElementById('search');const rows=Array.from(document.querySelectorAll('.searchable'));box.addEventListener('input',()=>{const term=box.value.toLowerCase();for(const row of rows)row.hidden=!row.textContent.toLowerCase().includes(term);document.getElementById('count').textContent=rows.filter(x=>!x.hidden).length+' visible items';});'''


def html_text(report):
    validate_report(report)
    def escape(value):
        return html.escape(str(value),quote=True)
    def pretty(value):
        return escape(json.dumps(value,ensure_ascii=True,allow_nan=False,indent=2))
    def csp_hash(value):
        return "'sha256-"+base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()+"'"
    policy="default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'; style-src "+csp_hash(STYLE)+"; script-src "+csp_hash(SCRIPT)
    sections=[]
    for key in ('sample','metadata','limits','warnings'):
        sections.append(f'<section id="{key}" class="searchable"><h2>{key}</h2><pre>{pretty(report[key])}</pre></section>')
    static=report['static']
    for key,value in static.items():
        rows=value if isinstance(value,list) else [value]
        articles=[]
        for row in rows:
            identity=row.get('id','') if isinstance(row,dict) else ''
            articles.append(f'<article class="searchable" id="e-{escape(identity)}"><pre>{pretty(row)}</pre></article>')
        sections.append(f'<section id="static-{escape(key)}"><h2>Static: {escape(key)}</h2>'+''.join(articles)+'</section>')
    re_data=report['reverse_engineering']
    detail_index={(d['address']['space'],d['address']['value']):n for n,d in enumerate(re_data.get('details',[]))}
    sections.append('<section id="functions"><h2>Function index</h2>')
    for index,function in enumerate(re_data.get('functions',[])):
        available=detail_index.get((function['address']['space'],function['address']['value']))
        target=f'#function-{available}' if available is not None else '#re-state'
        sections.append(f'<article class="searchable"><a href="{target}">{escape(function["name"])}</a><pre>{pretty(function)}</pre></article>')
    sections.append('</section>')
    sections.append('<section id="re-state" class="searchable"><h2>Reverse engineering state</h2><pre>'+pretty({k:v for k,v in re_data.items() if k not in ('functions','details')})+'</pre></section>')
    for index,detail in enumerate(re_data.get('details',[])):
        sections.append(f'<section id="function-{index}"><h2>{escape(detail["name"])}</h2><p class="note">Pseudocode approximates machine code. Check instructions and references.</p>')
        sections.append('<article class="searchable"><pre>'+escape(detail['pseudocode'])+'</pre></article>')
        for key in ('instructions','references','callers','blocks'):
            sections.append('<h3>'+key+'</h3>')
            for row in detail[key]:
                links=''
                if key=='references':
                    links=' '.join(f'<a href="#e-{escape(identifier)}">{escape(identifier)}</a>' for identifier in row.get('evidence_ids',[]))
                sections.append('<article class="searchable"><pre>'+pretty(row)+'</pre>'+links+'</article>')
        sections.append('</section>')
    for key in ('signatures','findings'):
        value=report[key]
        rows=value if isinstance(value,list) else [value]
        sections.append(f'<section id="{key}"><h2>{key}</h2>')
        sections.extend('<article class="searchable"><pre>'+pretty(row)+'</pre></article>' for row in rows)
        sections.append('</section>')
    result='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'+f'<meta http-equiv="Content-Security-Policy" content="{escape(policy)}"><title>Binary Workbench report</title><style>'+STYLE+'</style></head><body><h1>Binary Workbench</h1><p>Status: '+escape(report['status'])+'</p><p class="note">Observed facts and heuristic interpretations are distinct. No findings is inconclusive. No extracted indicator is contacted. Strings are printable byte runs, not validated runtime values.</p><nav><a href="#static-sections">Sections</a><a href="#static-strings">Strings</a><a href="#functions">Functions</a><a href="#findings">Triage</a></nav><label>Search evidence <input id="search" type="search" autocomplete="off" placeholder="Search names, addresses, strings or rule evidence"></label><p id="count" aria-live="polite"></p>'+''.join(sections)+'<script>'+SCRIPT+'</script></body></html>'
    if len(result.encode())>HTML_CAP:
        raise ValueError('HTML report output limit exceeded')
    return result


def export(report,directory):
    # Build both before writing so invalid/oversized data creates no valid-looking report.
    json_content, html_content=json_text(report),html_text(report)
    write_new(directory/'report.json',json_content,JSON_CAP)
    write_new(directory/'report.html',html_content,HTML_CAP)
