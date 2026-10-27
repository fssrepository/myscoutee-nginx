#!/usr/bin/env python3
"""Build the two-page branded guide locally; reportlab is a documentation dependency."""
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'output/pdf/MyScoutee_Nginx_Guide.pdf'
FONT=Path('/usr/share/fonts/truetype/dejavu')
pdfmetrics.registerFont(TTFont('Guide',str(FONT/'DejaVuSans.ttf')))
pdfmetrics.registerFont(TTFont('GuideBold',str(FONT/'DejaVuSans-Bold.ttf')))
BLUE=colors.HexColor('#253d70');PURPLE=colors.HexColor('#663fe0');GRAY=colors.HexColor('#526078')
body=ParagraphStyle('Body',fontName='Guide',fontSize=8.5,leading=12,textColor=BLUE,spaceAfter=6)
small=ParagraphStyle('Small',parent=body,fontSize=8,leading=11,spaceAfter=0)
heading=ParagraphStyle('Heading',parent=body,fontName='GuideBold',fontSize=13,leading=18,spaceBefore=10,spaceAfter=6)
title=ParagraphStyle('Title',parent=body,fontName='GuideBold',fontSize=25,leading=30,spaceAfter=12)

def p(text,style=body):return Paragraph(text,style)
def table(rows,widths):
    cells=[[p(str(c),small) for c in row] for row in rows]
    t=Table(cells,colWidths=widths,hAlign='LEFT')
    t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeaff')),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fc')]),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6),('LINEBELOW',(0,0),(-1,0),.7,PURPLE)]))
    return t

def furniture(canvas,doc):
    canvas.saveState()
    width,height=A4
    if doc.page == 1:
        canvas.drawImage(str(ROOT/'docs/assets/myscoutee-logo.png'),42,height-75,width=35,height=35,mask='auto',preserveAspectRatio=True)
        canvas.setFont('GuideBold',11);canvas.setFillColor(BLUE);canvas.drawString(87,height-52,'MyScoutee')
        canvas.setFont('Guide',8);canvas.setFillColor(GRAY);canvas.drawString(87,height-67,'Native nginx extensions')
    else:
        canvas.setFont('GuideBold',8);canvas.setFillColor(BLUE);canvas.drawString(42,height-52,'MYSCOUTEE / NGINX')
    canvas.setStrokeColor(colors.HexColor('#dde3ee'));canvas.line(42,43,width-42,43)
    canvas.setFont('Guide',7);canvas.drawString(42,29,'MSC-127  |  1.4.6  |  BSD-3-Clause  |  nginx 1.29.6')
    canvas.drawRightString(width-42,29,f'{doc.page} / 2')
    canvas.restoreState()

flow=[p('One shared proxy implementation',title),p('Native C/C++ modules for MyScoutee and MyScoutee Template. The application image inherits this nginx base; both projects pin the released GHCR image by digest. Only their own configuration, data and frontend bundle stay in the application.'),
      p('What runs at the edge',heading),
      table([['Capability','Behavior'],
      ['Coordinate eligibility','S2 spherical lookup against the complete bundled GeoJSON snapshot. Polygon, MultiPolygon, holes and partition specificity. No per-request backend call.'],
      ['IP policy','Individual IPv4/IPv6 response messages. Native shared-memory cache and background refresh; updates require no nginx restart or reload.'],
      ['Scanner defense','100 requests to unknown application paths within 600 seconds create a persistent IP ban with bounded path evidence.'],
      ['Rate limiting','Native nginx limits: 30 requests/s, burst 120; unknown paths: 2/s, burst 10. Excess requests return 429.'],
      ['Availability','Authenticated backend leases expire after 20 seconds; public JSON and SSE. Kubernetes reads EndpointSlice snapshots over verified TLS.'],
      ['Shared behavior','Security headers, transport policy, SSI switches, browser diagnostic endpoint and async browser recorder.']], [118,393]),
      Spacer(1,10),p('The landing, demo and public content stay available',heading),
      p('Coordinate eligibility belongs to the existing /api/auth/eligibility contract. It controls login eligibility rather than applying a geographic IP ban to the site. Backend authentication checks remain authoritative. AUTH_REGION_SECURITY_ENABLED=false disables this gate.'),
      p('Build-time inputs',heading),
      p('The application supplies its countryPartitions.json and an endpoint inventory generated from its Spring, Angular and nginx routes. Literal paths use nginx’s native hash map. The image contains no Go, Python or Lua runtime helper. File refresh, persistence and Kubernetes reads run on a native background thread.'),
      PageBreak(),p('Operate and verify',title),
      table([['State','Container location'],
      ['Operator IP → message list','/etc/nginx/myscoutee-operator/<br/>nginx-blocked-ips.json'],
      ['Automatic bans and findings','/var/lib/nginx/myscoutee/<br/>scanner-blocked-ips.json'],
      ['Basic traffic checkpoint','/var/lib/nginx/myscoutee/<br/>traffic-summary.json']], [150,361]),
      Spacer(1,10),p('Persistent state and removal',heading),
      p('Mount the operator directory read-only and the state directory on persistent storage writable by nginx UID 101. Valid policy changes refresh in the background; invalid operator updates retain the last valid cache. Manual messages take precedence. Remove an operator entry or delete an automatic-ban entry from the findings file to clear that ban. Findings are never automatically published to GitHub.'),
      p('A quick traffic summary, without browser debug',heading),
      p('Daily counters show source attribution, estimated sessions, HTML/application requests, demo, login, articles, further activity and no further HTTP activity. Read the current summary inside the container at http://127.0.0.1:9081/internal/traffic-summary. A file checkpoint is written every 30 seconds.'),
      p('An Instagram browser does not by itself prove a paid click. Lack of follow-up HTTP activity does not prove lack of clicks or reading. Optional detailed browser diagnostics remain separate: when enabled, nginx SSI inserts the async script into served HTML; otherwise the script tag is absent.'),
      p('Focused container checks',heading),
      table([['Suite','Coverage'],
      ['edge-test.py','Shared workers, hot updates, custom IPv4/IPv6 messages, 99/100 threshold, persistent replacement/unban, readiness/SSE, SSI and Meta metrics.'],
      ['kubernetes-test.py','Local TLS/token validation, ready/terminating endpoints and rejection of incomplete snapshots.'],
      ['native-test.py','Polygon holes, islands, specificity, invalid coordinates, in-memory lookup; optional full-seed cities and matched load comparison.'],
      ['Local tools / browser tests','Traffic inference regressions and browser lifecycle/interaction diagnostics. These scripts are not deployed in the runtime image.']], [126,385]),
      Spacer(1,10),p('Bounds',heading),p('One state cache holds up to 8,192 scanner/operator IP entries, 16,384 active visit slots and 32 readiness services with 128 instances each. Separate proxy instances have separate in-memory state. Local container measurements are not a production throughput guarantee.'),
      p('Source and exact commands: github.com/fssrepository/myscoutee-nginx',small)]
OUTPUT.parent.mkdir(parents=True,exist_ok=True)
SimpleDocTemplate(str(OUTPUT),pagesize=A4,rightMargin=42,leftMargin=42,topMargin=100,bottomMargin=58,title='MyScoutee nginx - Native proxy guide',author='MyScoutee / fssrepository').build(flow,onFirstPage=furniture,onLaterPages=furniture)
print(OUTPUT)
