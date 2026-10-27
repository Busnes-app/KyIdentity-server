"""Validate Council originals and exact cohort scores, then export CSV/XLSX."""
from pathlib import Path
from decimal import Decimal, ROUND_HALF_UP
from fractions import Fraction
from xml.sax.saxutils import escape
import csv, hashlib, json, re, struct, zipfile
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parent
WEIGHTS=dict(hierarchy='.20',typography='.15',density_layout='.20',color='.15',visible_affordances='.15',coherence='.15')
BRAND=['palette_tokens','type_geometry','shell','accent_discipline','suite_cohesion']
NS='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
def rounded(value): return value.quantize(Decimal('.1'),rounding=ROUND_HALF_UP)
def normalized(file): return file.removeprefix('docs/ui-identity-eight/')
inventories={}
evidence=[['Inventory','File','SHA256','Bytes','Width','Height','Cohort','Duplicate of']]
for path in sorted(ROOT.glob('inventory-v*.json')):
 rows=json.loads(path.read_text());inventories[path.name]={normalized(r['file']):r for r in rows}
 for r in rows:
  data=(ROOT/normalized(r['file'])).read_bytes()
  assert hashlib.sha256(data).hexdigest()==r['sha256'] and len(data)==r['bytes']
  assert struct.unpack('>II',data[16:24])==(r['width'],r['height'])
  evidence.append([path.name,r['file'],r['sha256'],r['bytes'],r['width'],r['height'],r['cohort'],r.get('duplicate_of')])
round_rows=[['Round','Reviewer','Cohort','n','Sum','Exact mean','Display mean','At least 8','Satisfied','Report SHA256']]
score_rows=[['Round','Reviewer','File','Cohort',*WEIGHTS,'Quality','Confidence','Caveat']]
brand_rows=[['Round','Reviewer','File',*BRAND,'Separate brand mean']]
spread_rows=[['Round','File','Dimension','Opus','Sol','Spread']]
reports={}
for path in sorted(ROOT.glob('*-round*.json')):
 m=re.fullmatch(r'(opus|sol|gemini)-round(\d+)\.json',path.name)
 if not m: continue
 who,number=m[1],int(m[2]);r=json.loads(path.read_text())
 satisfied=r.get('verdict',{}).get('satisfied',r.get('verdict',{}).get('genuinely_satisfied'))
 assert r['schema']=='ky-ui-council-scores/2' and r['rubric']['version']=='ky-suite-v2'
 assert {k:Decimal(str(v)) for k,v in r['rubric']['weights'].items()}=={k:Decimal(v) for k,v in WEIGHTS.items()}
 files={normalized(f['file']):f for f in r['files']};assert len(files)==len(r['files'])
 pins=next(v for v in inventories.values() if v.keys()==files.keys());groups={}
 no_score=r.get('verdict',{}).get('status')=='no_visual_score_tool_limitation'
 if no_score: assert r['verdict']['satisfied'] is None
 for file,f in files.items():
  assert all(f[k]==pins[file][k] for k in ['sha256','width','height','cohort'])
  assert f.get('duplicate_of')==pins[file].get('duplicate_of')
  if no_score:
   assert all(f['scores'][k] is None for k in WEIGHTS) and f['total'] is None
   assert all(f['ky_fit']['scores'][k] is None for k in BRAND)
   total=fit=None
  else:
   assert all(type(f['scores'][k]) is int and 0<=f['scores'][k]<=10 for k in WEIGHTS)
   total=rounded(sum(Decimal(w)*f['scores'][k] for k,w in WEIGHTS.items()));assert total==Decimal(str(f['total']))
   fit=rounded(sum(Decimal(str(f['ky_fit']['scores'][k])) for k in BRAND)/5)
  if not f.get('duplicate_of'): groups.setdefault(f['cohort'],[]).append(total)
  score_rows.append([number,who,file,f['cohort'],*[f['scores'][k] for k in WEIGHTS],str(total) if total is not None else None,f.get('confidence'),f.get('caveat')])
  brand_rows.append([number,who,file,*[f['ky_fit']['scores'][k] for k in BRAND],str(fit) if fit is not None else None])
 means={} if no_score else {c:sum(v)/len(v) for c,v in groups.items()}
 reports[who,number]={'report':r,'files':files,'means':means,'satisfied':satisfied}
 for c,values in groups.items():
  mean=means.get(c);summed=None if no_score else sum(values)
  round_rows.append([number,who,c,len(values),str(summed) if summed is not None else None,str(Fraction(summed)/len(values)) if summed is not None else None,str(rounded(mean)) if mean is not None else None,mean>=8 if mean is not None else None,satisfied,hashlib.sha256(path.read_bytes()).hexdigest()])
progression_rows=[['Round','Claude exact input','Sol exact input','Combined exact','Rounded progression','Accepted','Scope']]
for number in sorted({n for _,n in reports}):
 pair=[reports.get((who,number)) for who in ['opus','sol']]
 if all(pair):
  a,b=pair
  assert a['files'].keys()==b['files'].keys()
  values=[sum(Fraction(str(f['total'])) for f in r['files'].values() if not f.get('duplicate_of'))/sum(not f.get('duplicate_of') for f in r['files'].values()) for r in pair]
  combined=sum(values)/2
  progression_rows.append([number,*[str(Fraction(v)) for v in values],str((sum(Fraction(str(f['total'])) for f in a['files'].values())+sum(Fraction(str(f['total'])) for f in b['files'].values()))/(2*len(a['files']))),str(rounded(Decimal(combined.numerator)/Decimal(combined.denominator))),rounded(Decimal(combined.numerator)/Decimal(combined.denominator))>=8,'Covered visual progression only; not a ranking'])
for number in sorted({n for _,n in reports}):
 a,b=reports.get(('opus',number)),reports.get(('sol',number))
 if a and b:
  assert a['files'].keys()==b['files'].keys()
  for file,f in a['files'].items():
   for dim in WEIGHTS:
    x,y=f['scores'][dim],b['files'][file]['scores'][dim]
    spread_rows.append([number,file,dim,x,y,abs(x-y)])
audit_rows=[['Audit','Evidence']]
for path in sorted(ROOT.glob('round*-audit.json')):
 r=json.loads(path.read_text())
 for file,pin in r.get('raw_reports',{}).items(): assert hashlib.sha256((ROOT/file).read_bytes()).hexdigest()==pin
 audit_rows.append([path.name,json.dumps(r,ensure_ascii=False)])
checks=[['Item','Evidence']]
if (ROOT/'verification.json').exists(): checks += [[k,json.dumps(v)] for k,v in json.loads((ROOT/'verification.json').read_text()).items()]
prs=[['Repository','PR','Status']]
if (ROOT/'delivery.json').exists(): prs += [[r['repository'],r['url'],r['status']] for r in json.loads((ROOT/'delivery.json').read_text())]
notes=[['Topic','Meaning'],['Scope','36 initial-viewport originals:20admin-console,8settings,4auth,4member-home; five synthetic users, unconfigured apps/groups/connections, open unsubmitted Create User form.'],['Conditions','1280x900 and390x844,OSlight/dark,DPR1,normal serviceworker behavior. Read each manifest for source/browser.'],['Gate','Owner progression: arithmetic mean of Claude/Sol quality totals over identical capture sets, rounded half-up to one decimal; >=8.0 accepts. Separate cohort ratings remain visible and are not vetoes. Not a competitive ranking.'],['Brand','Separate five equal weights; never added to quality.'],['Gemini','Advisory only after primaries satisfied; absent image access means no score.'],['MySlop','Configured credential returns401; no successful shared-board post.']]
markdown=['# KyIdentity Council score history','','Raw cohort means are preserved. The combined progression result is rounded half-up to one decimal;8.0 or higher passes.','','| Round | Reviewer | Console | Settings | Sign-in | Launcher | Satisfied |','| --- | --- | ---: | ---: | ---: | ---: | --- |']
for number in range(1,max(n for _,n in reports)+1):
 for who,label in [('opus','Claude Opus5.5'),('sol','GPT Sol'),('gemini','Gemini4Argon')]:
  r=reports.get((who,number));values=[f"{r['means'][c]:.4f}" if r and c in r['means'] else ('No score' if r else 'Deferred' if who=='gemini' else 'Pending') for c in ['admin-console','settings','auth','member-home']]
  markdown.append(f"| {number} | {label} | {' | '.join(values)} | {r['satisfied'] if r else '—'} |")
markdown += ['', '## Combined progression', '', '| Round | Claude input | Sol input | Combined exact | Rounded | Accepted |', '| --- | ---: | ---: | ---: | ---: | --- |']
for row in progression_rows[1:]: markdown.append('| '+' | '.join(map(str,row[:6]))+' |')
(ROOT/'COUNCIL.md').write_text('\n'.join(markdown)+'\n')
for name,rows in [('rounds',round_rows),('scores',score_rows),('spreads',spread_rows)]:
 with (ROOT/f'{name}.csv').open('w',newline='') as f: csv.writer(f,lineterminator='\n').writerows(rows)
def column(index):
    result = ""
    while index:
        index, rem = divmod(index - 1, 26)
        result = chr(65 + rem) + result
    return result

def sheet(rows):
    widths = [min(70, max(12, max(len(str(row[c])) if c < len(row) and row[c] is not None else 0 for row in rows) + 2)) for c in range(max(map(len, rows)))]
    cols = "".join(f'<col min="{i}" max="{i}" width="{width}" customWidth="1"/>' for i, width in enumerate(widths, 1))
    out = [f'<worksheet xmlns="{NS}"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>{cols}</cols><sheetData>']
    for r, row in enumerate(rows, 1):
        out.append(f'<row r="{r}">')
        for c, value in enumerate(row, 1):
            ref = f"{column(c)}{r}"
            if value is None:
                continue
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                out.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                out.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escape(str(value))}</t></is></c>')
        out.append("</row>")
    out.append(f'</sheetData><autoFilter ref="A1:{column(max(map(len, rows)))}{len(rows)}"/></worksheet>')
    return "".join(out)

sheets = [("Progression", progression_rows), ("Rounds", round_rows), ("Scores", score_rows), ("Brand fit", brand_rows), ("Audits", audit_rows), ("Evidence", evidence), ("Spreads", spread_rows), ("Checks", checks), ("Read me", notes), ("Pull requests", prs)]
workbook = ROOT / "KyIdentity-Council.xlsx"
with zipfile.ZipFile(workbook, "w", zipfile.ZIP_DEFLATED) as z:
    types = ['<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>']
    for i in range(1, len(sheets) + 1):
        types.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    z.writestr("[Content_Types].xml", "".join(types) + "</Types>")
    z.writestr("_rels/.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    z.writestr("xl/workbook.xml", f'<workbook xmlns="{NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + "".join(f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>' for i, (name, _) in enumerate(sheets, 1)) + "</sheets></workbook>")
    z.writestr("xl/_rels/workbook.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1)) + "</Relationships>")
    for i, (_, rows) in enumerate(sheets, 1):
        z.writestr(f"xl/worksheets/sheet{i}.xml", sheet(rows))
with zipfile.ZipFile(workbook) as z:
    assert z.testzip() is None
    for file in z.namelist():
        ET.fromstring(z.read(file))

print("Validated reports, arithmetic, evidence and workbook XML")
