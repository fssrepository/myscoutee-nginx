#!/usr/bin/env python3
"""Infer possible MyScoutee journeys from existing nginx combined access logs.

No click telemetry is added. Offline analysis uses only the Python standard
library; --netcup additionally uses Paramiko and the saved, fingerprint-pinned
SSH configuration. Reports omit IPs, raw user agents and arbitrary query values.
"""

import argparse
import base64
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import stat
import sys
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo


ROOT = Path(globals().get('PROJECT_ROOT', Path.cwd()))
LOG_PATTERN = re.compile(
    r'^(?:\S+Z\s+)?(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) HTTP/[^\"]+" '
    r'(?P<status>\d{3}) \S+ "(?P<referer>[^\"]*)" "(?P<ua>[^\"]*)"'
)
STATIC_IMPORT = re.compile(
    r'\bimport\s*(?:[^;\n"\']*?\s*from\s*)?["\']\./([^"\']+\.js)["\']'
)
DYNAMIC_IMPORT = re.compile(r'\bimport\(\s*["\']\./([^"\']+\.js)["\']\s*\)')
SELECTOR = re.compile(r'selectors:\s*\[\s*\[\s*["\']([^"\']+)["\']')
AUTOMATION = re.compile(r'bot|crawl|spider|headless|censys|python|curl|wget|Go-http', re.I)
SAFE_ROUTES = {
    '/': 'Nyitóoldal', '/entry': 'Nyitóoldal', '/index.html': 'Nyitóoldal',
    '/game': 'Játékoldal', '/home': 'Játékoldal', '/admin': 'Adminfelület',
    '/operator': 'Operátori felület', '/privacy-policy': 'Adatvédelmi oldal',
    '/terms': 'Felhasználási feltételek', '/mcp/authorize': 'MCP-engedélyezés',
}
LABELS = {
    'app-demo-bootstrap-selector': 'Demóprofil-választó',
    'app-home': 'Játékoldal',
    'app-explanation-popup': 'Magyarázat / útmutató',
    'app-document-viewer': 'Dokumentumolvasó',
    'app-activities-popup': 'Aktivitások',
    'app-profile-editor': 'Profilszerkesztő',
    'app-profile-view-popup': 'Profil megtekintése',
    'app-operator-page': 'Operátori felület',
    'app-admin': 'Adminfelület',
}
# These are already loaded on entry or opened automatically. Their download
# cannot identify the Login, consent, setup or footer button that was pressed.
STARTUP_SELECTORS = {'app-root', 'app-entry-page', 'app-entry-landing'}
LIMITS = [
    'Kérés látható, kattintás és sikeres képernyőmegjelenítés nem bizonyított.',
    'IP + böngészőjelleg szerinti csoportok; NAT, VPN, IP-váltás és több fül miatt nem személyazonosságok.',
    'Cache-ből kiszolgált, offline és kizárólag helyi műveleteknek nincs feltétlenül szerveroldali nyoma.',
    'Az előtöltés-felismerés heurisztika; az ismeretlen / más buildből származó chunkokból nincs felületkövetkeztetés.',
    'A Firebase/Google saját hosztjaira menő kérések nem szerepelnek ebben az nginx-naplóban.',
]
COVERAGE = [
    {'action': 'Ideiglenes landing-debug', 'signal': 'POST /__landing-debug, külön nginx-fájlból',
     'limit': 'Kliensjelzés, nem emberazonosítás. 15 másodperces csomagok az első percben; korai távozáskor best-effort küldés.'},
    {'action': 'More article / további cikkek', 'signal': 'GET /api/landing/articles',
     'limit': 'A cikklista megnyitása vagy lapozása valószínű; konkrét cikk elolvasása nem bizonyított.'},
    {'action': 'Konkrét cikk megnyitása', 'signal': 'Nincs egyedi, megbízható kérés',
     'limit': 'Az eagerDetail már a kliensen van; egy kép letöltése önmagában nem bizonyít cikknyitást.'},
    {'action': 'Lábléc: Rólunk / Partnerek / Országok / Hibajelentés',
     'signal': 'Nincs egyedi kérés', 'limit': 'Helyi popupállapotot váltanak; a kód és a tartalom már betöltött.'},
    {'action': 'Belépés gomb / Firebase ablak', 'signal': 'Önmagában nem azonosítható',
     'limit': 'A belépési popup a nyitóoldal chunkjában van. Firebase-konfiguráció induláskor is betöltődik.'},
    {'action': 'Belépés feldolgozása', 'signal': 'POST /api/auth/session/login',
     'limit': 'A HTTP státusz látható; a válasz törzse és a belépési mód nem. A 2xx nem bizonyít UI-sikert.'},
    {'action': 'Demó / Explore', 'signal': 'GET /api/auth/demo-users vagy önálló lazy modul',
     'limit': 'A lista lekérése erős közvetett jel; a modul önmagában előtöltés is lehet.'},
    {'action': 'Adatvédelem / Feltételek a láblécből', 'signal': 'Dokumentumkérés esetenként látható',
     'limit': 'A tartalom előre vagy automatikusan is betöltődhet; a lábléc adott gombja nem azonosítható.'},
    {'action': 'Külső böngésző megnyitása', 'signal': 'Azonos IP-n új, nem WebView böngésző + dokumentumkérés',
     'limit': 'Csak lehetséges átadás; közös IP-n más látogató is lehet. A gombnyomás nem látható.'},
]

DEBUG_MARKS = set(('bootstrap.ready bootstrap.failed route.ready landing.rendered landing.content.failed '
    'login.click about.open partners.open countries.open bug.open article.open '
    'privacy.open privacy.close privacy.accepted privacy.rejected terms.open terms.close '
    'auth.open auth.close auth.success auth.failed auth.cancelled auth.blocked auth.network '
    'auth.google auth.facebook auth.email auth.popup.request auth.email.verification '
    'setup.open setup.close setup.save setup.failed location.request location.granted location.denied '
    'location.prompt location.unavailable location.timeout location.cancelled location.unsupported '
    'notifications.request notifications.granted notifications.denied notifications.default '
    'browser.request browser.unsupported install.request install.accepted install.dismissed '
    'network.offline network.online visible hidden').split())


def clean_debug_message(value):
    """Apply the recorder's bounded redaction again to untrusted log input."""
    value = value[:1024]
    value = re.sub(r'''(?:https?|wss?|file|blob|data|chrome-extension):[^\s"'<>)]*|www\.[^\s"'<>)]*''', '[url]', value, flags=re.I)
    value = re.sub(r'\b(?:Bearer|Basic)\s+\S+', '[credential]', value, flags=re.I)
    value = re.sub(r'\b[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}\b', '[email]', value)
    value = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[ip]', value)
    value = re.sub(r'''\b(?:password|passwd|token|secret|authorization|cookie|email|userId|uid)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)''', '[credential]', value, flags=re.I)
    value = re.sub(r'''"[^"\r\n]*"|'[^'\r\n]*'|`[^`\r\n]*`''', '[value]', value)
    value = re.sub(r'\b[A-Za-z0-9_+/.=-]{24,}\b', '[id]', value)
    value = re.sub(r'\b\d{5,}\b|\b\d+\.\d{3,}\b', '[number]', value)
    return re.sub(r'[\x00-\x20\x7f-\x9f]+', ' ', value).strip()[:160]


PAGE_EVENTS = {'init', 'ready', 'dom', 'load', 'focus', 'blur', 'hidden', 'visible',
               'activated', 'freeze', 'resume', 'pageshow', 'pageshow.cached', 'pagehide', 'pagehide.cached'}
PAGE_TIMINGS = {'responseStart', 'responseEnd', 'domInteractive', 'domContentLoadedEventStart',
                'loadEventStart', 'activationStart', 'workerStart', 'first-paint', 'first-contentful-paint'}


def safe_page(value, elapsed):
    """Optional lifecycle diagnostics contain only bounded enums, flags and timings."""
    try:
        if not isinstance(value, dict):
            return None
        for key, maximum in [('initial', 2047), ('state', 2047), ('offsetMs', 10000000), ('hiddenForMs', 60000)]:
            if type(value.get(key)) is not int or not 0 <= value[key] <= maximum:
                return None
        context = value.get('context')
        if (not isinstance(context, list) or len(context) != 2 or any(type(v) is not int for v in context)
                or context[0] not in (0, 1, 2) or context[1] not in (0, 1)
                or value.get('navigation') not in {'unknown', 'navigate', 'reload', 'back_forward'}
                or value.get('delivery') not in {'', 'cache', 'navigational-prefetch'}):
            return None
        timing = value.get('timing', {})
        events = value.get('events', [])
        if not isinstance(timing, dict) or not isinstance(events, list):
            return None
        result = {k: value[k] for k in ('initial', 'state', 'offsetMs', 'hiddenForMs', 'context', 'navigation', 'delivery')}
        result['timing'] = {k: v for k, v in timing.items() if k in PAGE_TIMINGS and type(v) is int and 0 <= v <= 10000000}
        result['events'] = [e for e in events[:12] if isinstance(e, list) and len(e) == 3
                            and type(e[0]) is int and 0 <= e[0] <= elapsed and e[1] in PAGE_EVENTS
                            and type(e[2]) is int and 0 <= e[2] <= 2047]
        return result
    except (TypeError, ValueError):
        return None


def safe_debug(value):
    """Read only the bounded v1 schema; never echo arbitrary query values."""
    try:
        if len(value) > 3500:
            return None
        data = json.loads(value)
        if (not isinstance(data, dict) or data.get('v') != 1
                or not re.fullmatch(r'[a-f0-9]{16}', data.get('id', ''))
                or data.get('reason') not in {'tick', 'end', 'hidden', 'freeze', 'pagehide', 'route'}):
            return None
        def integer(key, maximum):
            v = data.get(key)
            if type(v) is not int or not 0 <= v <= maximum:
                raise ValueError(key)
            return v
        result = {key: integer(key, maximum) for key, maximum in
                  [('seq', 8), ('ms', 60000), ('visibleMs', 60000), ('errorCount', 100), ('dropped', 1000000)]}
        if result['seq'] < 1 or result['visibleMs'] > result['ms']:
            return None
        result.update(v=1, id=data['id'], reason=data['reason'])
        interaction = data.get('interactionMs')
        if interaction is not None and (type(interaction) is not int or not 0 <= interaction <= result['ms']):
            return None
        result['interactionMs'] = interaction
        counts = data.get('counts', {})
        result['counts'] = {k: counts.get(k, 0) for k in ('pointer', 'key', 'click')}
        if any(type(v) is not int or not 0 <= v <= 65535 for v in result['counts'].values()):
            return None
        result['marks'] = []
        for item in data.get('marks', [])[:24]:
            if (isinstance(item, list) and len(item) == 2 and type(item[0]) is int
                    and 0 <= item[0] <= result['ms'] and item[1] in DEBUG_MARKS):
                result['marks'].append(item)
        result['errors'] = []
        for error in data.get('errors', [])[:4]:
            if not isinstance(error, dict):
                continue
            if (re.fullmatch(r'(?:[A-Za-z]{1,24}Error|Error|DOMException)', error.get('name', ''))
                    and re.fullmatch(r'[a-f0-9]{1,8}', error.get('code', ''))
                    and re.fullmatch(r'(?:(?:main|chunk|polyfills)-[A-Za-z0-9_-]+\.js)?', error.get('file', ''))
                    and all(type(error.get(k)) is int and 0 <= error[k] <= n
                            for k, n in [('line', 10000000), ('column', 10000000), ('ms', result['ms'])])):
                item = {k: error[k] for k in ('name', 'code', 'file', 'line', 'column', 'ms')}
                detail = error.get('detail')
                if (isinstance(detail, dict) and detail.get('source') in {'angular', 'window', 'promise', 'resource'}
                        and isinstance(detail.get('message'), str) and isinstance(detail.get('stack'), list)):
                    item['detail'] = {'source': detail['source'], 'message': clean_debug_message(detail['message']),
                                      'stack': [frame for frame in detail['stack'][:3] if isinstance(frame, str)
                                                and re.fullmatch(r'(?:[A-Za-z_$][A-Za-z0-9_.$<>]{0,63} )?(?:[A-Za-z0-9_-]{1,64}\.m?js|<anonymous>):\d{1,8}:\d{1,8}', frame)]}
                result['errors'].append(item)
        page = safe_page(data.get('page'), result['ms'])
        if page is not None:
            result['page'] = page
        return result
    except (ValueError, TypeError, AttributeError, KeyError):
        return None


@dataclass
class Request:
    time: datetime
    ip: str
    method: str
    path: str
    status: int
    ua: str
    params: dict
    traffic_source: str = 'direct_or_unknown'

    @property
    def client(self):
        # Retains the same identifiers used by the earlier traffic review.
        return hashlib.sha256(self.ip.encode()).hexdigest()[:6]

    @property
    def engine(self):
        # Service-worker precache requests omit the Instagram suffix but retain
        # the same WebView UA. Never classify these as a Chrome handoff.
        return self.ua.split(' Instagram ', 1)[0].split(' [FB', 1)[0]


def parse_line(line):
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    value = match.groupdict()
    try:
        ipaddress.ip_address(value['ip'])
        target = urlsplit(value['url'])
        params = parse_qs(target.query, max_num_fields=100)
        # Whitelist non-identifying controls. Do not retain tokens, coordinates,
        # search text, article/profile IDs or marketing query values.
        safe_params = {}
        source = params.get('utm_source', [''])[0].lower()
        medium = params.get('utm_medium', [''])[0].lower()
        paid = medium in {'paid', 'cpc', 'ppc', 'paid_social', 'paidsocial', 'display'}
        meta = source in {'ig', 'fb', 'facebook', 'instagram', 'meta'}
        referer_host = urlsplit(value['referer']).hostname or ''
        meta_referrer = any(referer_host == host or referer_host.endswith('.' + host)
                            for host in ['facebook.com', 'instagram.com'])
        traffic_source = ('meta_paid' if meta and paid else 'meta_campaign' if meta
                                        else 'other_paid' if source and paid else 'other_campaign' if source
                                        else 'meta_referral' if meta_referrer else 'meta_browser' if
                                        re.search(r'Instagram|FBAN|FBAV', value['ua']) else 'direct_or_unknown')
        if target.path == '/__landing-debug':
            debug = safe_debug(params.get('d', [''])[0])
            if debug:
                safe_params['debug'] = debug
        for key in ('page', 'pageSize'):
            item = params.get(key, [''])[0]
            if re.fullmatch(r'\d{1,4}', item):
                safe_params[key] = int(item)
        return Request(datetime.strptime(value['time'], '%d/%b/%Y:%H:%M:%S %z'),
                       value['ip'], value['method'], target.path,
                       int(value['status']), value['ua'], safe_params, traffic_source)
    except (ValueError, OverflowError):
        return None


def browser(ua):
    if 'Instagram' in ua:
        return 'Instagram WebView' if '; wv)' in ua else 'Instagram'
    if 'FBAN' in ua or 'FBAV' in ua:
        return 'Facebook alkalmazás'
    if '; wv)' in ua or 'Version/4.0 Chrome/' in ua:
        return 'Android WebView (háttérkérés is lehet)'
    if 'Edg/' in ua or 'EdgA/' in ua:
        return 'Edge'
    if 'Chrome/' in ua or 'CriOS/' in ua:
        return 'Chrome'
    if 'Firefox/' in ua or 'FxiOS/' in ua:
        return 'Firefox'
    if 'Safari/' in ua:
        return 'Safari'
    return 'Egyéb böngésző'


def external_browser(ua):
    return not re.search(r'Instagram|FBAN|FBAV|; wv\)|Version/4.0 Chrome/', ua) and browser(ua) in {
        'Chrome', 'Firefox', 'Safari', 'Edge'}


class Catalog:
    """Use the existing stamped worker and emitted JS; never rebuild assets."""

    def __init__(self, directory=None):
        self.build_id = None
        self.precache = set()
        self.initial = set()
        self.labels = {}
        self.known = set()
        if directory is None:
            return
        directory = Path(directory)
        self.build_id = json.loads((directory / 'app-version.json').read_text())['buildId']
        worker = (directory / 'app-sw.js').read_text()
        for array in re.findall(r'const\s+PRECACHE_(?:CORE|BUILD)_URLS\s*=\s*(\[[\s\S]*?\]);', worker):
            # The canonical core list uses single quotes; build list is JSON.
            self.precache.update('/' + path.removeprefix('./')
                                 for path in re.findall(r'["\']([^"\']+)["\']', array))
        sources = {f.name: f.read_text() for f in directory.glob('*.js') if f.name != 'app-sw.js'}
        self.known = {'/' + name for name in sources}
        graph = {name: STATIC_IMPORT.findall(text) for name, text in sources.items()}
        roots = re.findall(r'<script\b[^>]*\bsrc=["\']([^"\']+\.js)["\']',
                           (directory / 'index.html').read_text())
        pending = [name.lstrip('./') for name in roots]
        while pending:
            name = pending.pop()
            if '/' + name in self.initial:
                continue
            self.initial.add('/' + name)
            pending.extend(graph.get(name, []))
        dynamic = {name for source in sources.values() for name in DYNAMIC_IMPORT.findall(source)}
        for name in dynamic:
            selectors = SELECTOR.findall(sources.get(name, ''))
            if not selectors or STARTUP_SELECTORS.intersection(selectors):
                continue
            # In emitted Angular components the outer component follows its
            # bundled helpers. Label as a possible surface, never as a click.
            selector = selectors[-1]
            label = LABELS.get(selector, selector.removeprefix('app-').replace('-', ' '))
            self.labels['/' + name] = label


def event(request, kind, confidence, description, evidence=None):
    return {'time': request.time.isoformat(), 'kind': kind, 'confidence': confidence,
            'description': description,
            'evidence': evidence or f'{request.method} {request.path} → {request.status}'}


def api_event(request):
    debug = request.params.get('debug')
    if request.path == '/__landing-debug' and request.method == 'POST' and request.status == 204 and debug:
        interaction = ('nincs megfigyelt interakció' if debug['interactionMs'] is None
                       else f"első interakció +{debug['interactionMs']} ms")
        item = event(request, 'landing_debug', 'kliensjelzés',
                     f"Landing +{debug['ms']} ms; látható {debug['visibleMs']} ms; {interaction}; "
                     f"JS-hibajelzés {debug['errorCount']}; ok: {debug['reason']}.",
                     f"POST /__landing-debug → 204; {debug['id']}/{debug['seq']}")
        item['debug'] = debug
        return item
    key = (request.method, request.path)
    rules = {
        ('GET', '/api/landing/content'): ('background', 'megfigyelt', 'Nyitóoldali tartalom lekérése; nem cikknyitási jel.'),
        ('GET', '/api/deployment/configuration/firebase-config'): ('background', 'megfigyelt', 'Firebase-konfiguráció lekérése; induláskor is történik, nem Belépés-kattintás.'),
        ('GET', '/api/landing/articles'): ('articles', 'valószínű', 'További cikkek listája / lapozása; a More article felület használatára utal.'),
        ('GET', '/api/auth/demo-users'): ('demo_selector', 'valószínű', 'Demóprofil-lista lekérése; Explore / demóválasztó használatára utal.'),
        ('GET', '/api/auth/eligibility'): ('eligibility', 'megfigyelt', 'Helyalapú belépési jogosultság ellenőrzése; nem bizonyít engedélykérést vagy belépést.'),
        ('POST', '/api/auth/session/login'): ('login', 'megfigyelt', 'Belépési munkamenet-kérés; a mód és a válasz törzse nem látható.'),
        ('GET', '/api/auth/me'): ('session', 'megfigyelt', 'Munkamenet / profil lekérése; korábbi belépés visszaállítása is lehet.'),
        ('GET', '/api/auth/me/profile-ext'): ('profile', 'megfigyelt', 'Profiladatok lekérése.'),
        ('POST', '/api/auth/me/logout'): ('logout', 'megfigyelt', 'Kijelentkezési kérés.'),
        ('POST', '/api/privacy/consents'): ('consent', 'megfigyelt', 'Adatvédelmi hozzájárulás mentési kérése.'),
        ('POST', '/api/game-cards/query'): ('game', 'valószínű', 'Játékkártyák lekérése; játékfelület betöltése / frissítése valószínű.'),
    }
    rule = rules.get(key)
    if not rule and request.method == 'GET' and request.path in {
            '/api/help/active', '/api/privacy/active', '/api/terms/active', '/api/explanation/active'}:
        rule = ('document', 'lehetséges', 'Dokumentum / útmutató lekérése; automatikus előtöltés is lehet, konkrét gomb nem azonosítható.')
    if not rule:
        return None
    kind, confidence, description = rule
    if not (200 <= request.status < 300 or request.status == 304):
        confidence = 'megfigyelt'
        description = 'Sikertelen kérés; a művelet teljesülése nem állítható. ' + description
    details = ', '.join(f'{key}={value}' for key, value in request.params.items() if key != 'trafficSource')
    evidence = f'{request.method} {request.path} → {request.status}' + (f' ({details})' if details else '')
    return event(request, kind, confidence, description, evidence)


def precache_windows(rows, catalog):
    """Find dense worker fanout; suppress also earlier entry-load dependencies.

    Request initiator / Sec-Fetch-Dest is absent in the existing log. Conservatively
    hide module/document guesses for the complete local burst, not API evidence.
    """
    candidates = [row for row in rows if row.method == 'GET' and row.path in catalog.precache
                  and (200 <= row.status < 300 or row.status == 304)]
    windows = []
    cluster = []
    for row in candidates:
        if cluster and (row.time - cluster[0].time).total_seconds() > 45:
            if len({item.path for item in cluster}) >= 20:
                windows.append((cluster[0].time - timedelta(seconds=5), cluster[-1].time + timedelta(seconds=2)))
            cluster = []
        cluster.append(row)
    if len({item.path for item in cluster}) >= 20:
        windows.append((cluster[0].time - timedelta(seconds=5), cluster[-1].time + timedelta(seconds=2)))
    return windows


def analyze(requests, catalog, gap_minutes=30):
    grouped = defaultdict(list)
    embedded = defaultdict(list)
    for request in sorted(requests, key=lambda row: row.time):
        grouped[(request.client, request.engine)].append(request)
        if re.search(r'Instagram|FBAN|FBAV', request.ua):
            embedded[request.client].append(request.time)
    sessions = []
    for (client, engine), rows in grouped.items():
        chunks = [[]]
        for row in rows:
            if chunks[-1] and row.time - chunks[-1][-1].time > timedelta(minutes=gap_minutes):
                chunks.append([])
            chunks[-1].append(row)
        for rows in chunks:
            windows = precache_windows(rows, catalog)
            in_precache = lambda row: any(start <= row.time <= end for start, end in windows)
            events = []
            if windows:
                events.append(event(rows[0], 'precache', 'valószínű',
                                    'Tömeges service-worker előtöltés; az érintett modulok és HTML-fájlok nem kattintási bizonyítékok.',
                                    f'{len(windows)} előtöltési hullám, legalább 20 különböző manifest-erőforrással/hullám'))
            seen_lazy = set()
            for row in rows:
                api = api_event(row)
                if api:
                    events.append(api)
                elif row.method == 'GET' and 200 <= row.status < 400:
                    if row.path in SAFE_ROUTES and not in_precache(row):
                        events.append(event(row, 'page', 'lehetséges',
                                            f'{SAFE_ROUTES[row.path]} HTML-kérése; navigáció, újratöltés vagy háttérletöltés lehet.'))
                    elif row.path in catalog.labels and row.path not in catalog.initial and not in_precache(row) and row.path not in seen_lazy:
                        seen_lazy.add(row.path)
                        events.append(event(row, 'lazy_surface', 'lehetséges',
                                            f'{catalog.labels[row.path]} lazy modul betöltése; felületnyitás vagy előtöltés lehet.'))
            # Match only a native browser document against the preceding
            # embedded-browser request on this IP. A bare WebView worker UA
            # is never a native browser. Matching IPs do not establish identity.
            for row in rows:
                if (not external_browser(row.ua) or row.path not in SAFE_ROUTES
                        or row.method != 'GET' or not 200 <= row.status < 300
                        or in_precache(row)):
                    continue
                previous = bisect_right(embedded[client], row.time) - 1
                if previous >= 0 and row.time - embedded[client][previous] <= timedelta(minutes=5):
                    events.append(event(row, 'browser_handoff', 'lehetséges',
                                        'Külső böngésző dokumentumkérése beágyazott böngésző után, azonos hálózati csoportból; átadás vagy másik látogató lehet.'))
                    break
            # Collapse identical polling/retry evidence in a short interval,
            # keeping count, last timestamp and HTTP-status differences.
            compact = []
            recent = {}
            for item in sorted(events, key=lambda value: value['time']):
                key = (item['kind'], item['evidence'])
                previous = recent.get(key)
                if previous and datetime.fromisoformat(item['time']) - datetime.fromisoformat(previous.get('lastTime', previous['time'])) <= timedelta(seconds=30):
                    previous['count'] = previous.get('count', 1) + 1
                    previous['lastTime'] = item['time']
                else:
                    compact.append(item)
                    recent[key] = item
            sessions.append({'client': client,
                             'trafficSource': next((row.traffic_source for row in rows
                                                    if row.traffic_source in {'meta_paid', 'meta_campaign', 'other_paid', 'other_campaign'}),
                                                   next((row.traffic_source for row in rows
                                                         if row.traffic_source != 'direct_or_unknown'), 'direct_or_unknown')),
                             'browser': sorted({browser(row.ua) for row in rows}),
                             'first': rows[0].time.isoformat(), 'last': rows[-1].time.isoformat(),
                             'requestCount': len(rows),
                             'statusCounts': dict(Counter(row.status for row in rows)),
                             'unknownJsRequests': sum(row.path.endswith('.js') and row.path not in catalog.known and row.path != '/app-sw.js' for row in rows),
                             'events': compact})
    return sorted(sessions, key=lambda value: value['first'])


def traffic_summary(sessions):
    """Access-log metrics; optional debug evidence never defines engagement."""
    groups = {}
    for session in sessions:
        source = session.get('trafficSource', 'direct_or_unknown')
        group = groups.setdefault(source, dict(sessions=0, htmlResponses=0, applicationRequests=0,
                    furtherActivity=0, noFurtherActivity=0, demo=0, login=0, articles=0, debugSessions=0))
        group['sessions'] += 1
        events = session['events']
        kinds = {item['kind'] for item in events}
        html = any(item['kind'] == 'page' for item in events)
        group['htmlResponses'] += int(html)
        group['applicationRequests'] += int(bool(kinds & {'background', 'eligibility', 'demo_selector', 'login', 'articles', 'profile', 'game', 'session'}))
        active = bool(kinds & {'demo_selector', 'login', 'articles', 'profile', 'game', 'consent', 'logout'}) or any(
            item['kind'] == 'page' and not any(route in item['evidence'] for route in ['GET / →', 'GET /entry →', 'GET /index.html →'])
            for item in events)
        group['furtherActivity'] += int(active)
        group['noFurtherActivity'] += int(not active)
        for column, kind in [('demo', 'demo_selector'), ('login', 'login'), ('articles', 'articles'), ('debugSessions', 'landing_debug')]:
            group[column] += int(kind in kinds)
    return {'sources': groups, 'sessions': len(sessions),
            'noFurtherActivity': sum(row['noFurtherActivity'] for row in groups.values()),
            'furtherActivity': sum(row['furtherActivity'] for row in groups.values()),
            'basis': 'access_log', 'note': 'Nincs további látható műveleti kérés ≠ bizonyított kattintáshiány. A háttérletöltés és debugjel nem aktivitás.'}


def render_summary(summary):
    lines = ['Forgalmi statisztika – access log, debugmérő nélkül',
             f"Munkamenetcsoportok: {summary['sessions']}; további aktivitás: {summary['furtherActivity']}; további aktivitás nem látszik: {summary['noFurtherActivity']}",
             'Forrás | csoport | HTML-jel | alkalmazáskérés | további aktivitás | nincs további jel | demó | belépési kérés | cikklista']
    for source, values in sorted(summary['sources'].items()):
        lines.append(source + ' | ' + ' | '.join(str(values[key]) for key in ['sessions', 'htmlResponses', 'applicationRequests', 'furtherActivity', 'noFurtherActivity', 'demo', 'login', 'articles']))
    return '\n'.join(lines + [summary['note']]) + '\n'


def netcup_lines(config_path, since, tail, debug=False):
    """Read-only adapter for the existing saved SSH_* / pinned fingerprint file.

    The release helpers' remote-transport.sh instead consumes REMOTE_* settings
    and OpenSSH known_hosts; it does not support this retained fingerprint file.
    """
    import paramiko

    config_path = Path(config_path)
    if stat.S_IMODE(config_path.stat().st_mode) not in (0o600, 0o400):
        raise ValueError('Az SSH-konfiguráció jogosultsága 0600 vagy 0400 legyen.')
    config = {}
    for line in config_path.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            words = shlex.split(value)
            if len(words) != 1:
                raise ValueError('Érvénytelen mentett SSH-konfiguráció.')
            config[key.strip()] = words[0]

    class Pinned(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            if fingerprint != config['SSH_HOST_FINGERPRINT']:
                raise ValueError('Eltérő SSH host fingerprint; kapcsolat megszakítva.')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(Pinned())
    try:
        client.connect(config['SSH_HOST'], port=int(config['SSH_PORT']),
                       username=config['SSH_USER'], password=config['SSH_PASSWORD'],
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=15, banner_timeout=15)
        interval = re.fullmatch(r'(\d+)([smhd])', since)
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=int(interval[1]) *
                  {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[interval[2]]) if interval
                  else datetime.fromisoformat(since.replace('Z', '+00:00')))
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
        commands = [shlex.join(['docker', 'logs', '--timestamps', '--since', since,
                               '--tail', str(tail), 'nginx'])]
        if debug:
            commands.append(shlex.join(['docker', 'exec', 'nginx', 'sh', '-c',
                                'if test -f /tmp/myscoutee-landing-debug.log; then tail -n ' + str(tail) +
                                ' /tmp/myscoutee-landing-debug.log; elif test -f /var/log/nginx/landing-debug.log; then tail -n ' + str(tail) +
                                ' /var/log/nginx/landing-debug.log; fi']))
        for index, command in enumerate(commands):
            channel = client.get_transport().open_session(timeout=30)
            channel.settimeout(60)
            channel.set_combine_stderr(True)
            channel.exec_command(command)
            with channel.makefile('r') as stream:
                for line in stream:
                    row = parse_line(line) if index else None
                    if not index or (row and row.time >= cutoff):
                        yield line
            if channel.recv_exit_status() != 0:
                raise ValueError('A Netcup nginx-napló olvasása sikertelen.')
    except (paramiko.SSHException, TimeoutError):
        raise OSError('A csak olvasható Netcup-kapcsolat sikertelen.') from None
    finally:
        client.close()


def page_state_label(flags):
    ready = 'complete' if flags & 64 else 'interactive' if flags & 32 else 'loading'
    prerender = str(bool(flags & 4)) if flags & 128 else 'ismeretlen'
    activation = str(bool(flags & 8)) if flags & 256 else 'ismeretlen'
    return (f"visible={bool(flags & 1)}, focus={bool(flags & 2)}, ready={ready}, "
            f"prerender={prerender}, userActivated={activation}, "
            f"transientActivation={bool(flags & 16) if flags & 256 else 'ismeretlen'}, "
            f"wasDiscarded={bool(flags & 512)}, iframe={bool(flags & 1024)}")


def render(report, local_timezone):
    zone = ZoneInfo(local_timezone)
    stamp = lambda value: datetime.fromisoformat(value).astimezone(zone).strftime('%Y-%m-%d %H:%M:%S')
    lines = ['MyScoutee – feltételezhető látogatói műveletek',
             f"Asset build: {report['assetBuildId'] or 'nincs; csak API / HTML jelek'}",
             f"Időzóna: {local_timezone}; feldolgozott kérések: {report['parsedRequests']}; automatának tűnő kihagyva: {report['automatedRequests']}"]
    lines.extend('FIGYELEM: ' + warning for warning in report['warnings'])
    lines += ['', render_summary(report.get('summary') or traffic_summary(report['sessions'])).rstrip()]
    for session in report['sessions']:
        lines += ['', f"[{session['client']}] {', '.join(session['browser'])}",
                  f"  {stamp(session['first'])} – {stamp(session['last'])}; {session['requestCount']} kérés"]
        for item in session['events']:
            count = f" ({item['count']}×)" if item.get('count', 1) > 1 else ''
            lines += [f"  {stamp(item['time'])} [{item['confidence']}] {item['description']}{count}",
                      f"    Jel: {item['evidence']}"]
            if item.get('debug'):
                page = item['debug'].get('page')
                if page:
                    purpose = ('nincs jelzés', 'prefetch/preview', 'prerender')[page['context'][0]]
                    lines.append(f"    HTML-kérés: purpose={purpose}, Sec-Fetch-User={bool(page['context'][1])}; "
                                 f"navigation={page['navigation']}, delivery={page['delivery'] or 'nincs jelzés'}")
                    lines.append(f"    Kezdőállapot: {page_state_label(page['initial'])}")
                    lines.append(f"    Most: {page_state_label(page['state'])}; hidden óta {page['hiddenForMs']} ms")
                    lines.append(f"    Navigációs időpontok (ms): {json.dumps(page['timing'])}; mérő indulása +{page['offsetMs']} ms")
                    for elapsed, name, flags in page['events']:
                        lines.append(f"    +{elapsed} ms lifecycle {name}: {page_state_label(flags)}")
                for elapsed, name in item['debug']['marks']:
                    lines.append(f'    +{elapsed} ms: {name}')
                for error in item['debug']['errors']:
                    lines.append(f"    +{error['ms']} ms: {error['name']} #{error['code']} "
                                 f"{error['file']}:{error['line']}:{error['column']}")
                    if error.get('detail'):
                        detail = error['detail']
                        lines.append(f"      {detail['source']}: {detail['message']}")
                        lines.extend('      ' + frame for frame in detail['stack'])
        if not session['events']:
            lines.append('  Nincs azonosítható műveleti jel; ebből nem következik, hogy nem kattintott.')
        if session['unknownJsRequests']:
            lines.append(f"  {session['unknownJsRequests']} ismeretlen buildhez / scripthez tartozó JS-kérés; nincs felületkövetkeztetés.")
    lines += ['', 'Mit lehet látni a jelenlegi naplóból?']
    for item in report['coverage']:
        lines.append(f"- {item['action']}: {item['signal']}. {item['limit']}")
    lines += ['', 'Korlátok:'] + ['- ' + limit for limit in report['limits']]
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', nargs='?', help='nginx access log (.gz is supported); - = stdin')
    parser.add_argument('--netcup', action='store_true', help='Read current nginx Docker logs over pinned SSH')
    parser.add_argument('--ssh-config', type=Path, default=ROOT / 'packaging/client-tools/netcup.local.env')
    parser.add_argument('--since', default='6h', help='Docker logs --since value (only with --netcup)')
    parser.add_argument('--max-lines', type=int, default=50000, help='Bound the input snapshot')
    parser.add_argument('--assets', type=Path, help='Existing stamped production output, e.g. frontend/prod')
    parser.add_argument('--client', action='append', default=[], help='Only this report IP hash; repeatable')
    parser.add_argument('--gap-minutes', type=int, default=30, help='Inactivity interval for a new session')
    parser.add_argument('--timezone', default='Europe/Prague')
    parser.add_argument('--format', choices=['text', 'json'], default='text')
    parser.add_argument('--summary', action='store_true', help='Only the short access-log statistics')
    parser.add_argument('--debug', action='store_true', help='Also read/render optional browser debug packets')
    args = parser.parse_args()
    if args.netcup == bool(args.log):
        parser.error('Adj meg egy naplófájlt / stdin-t, vagy használd a --netcup kapcsolót.')
    if not 1 <= args.max_lines <= 1000000 or args.gap_minutes < 1:
        parser.error('--max-lines: 1..1000000; --gap-minutes: pozitív egész.')
    ZoneInfo(args.timezone)
    catalog = Catalog(args.assets)
    stream = None
    try:
        if args.netcup:
            source = netcup_lines(args.ssh_config, args.since, args.max_lines, debug=args.debug)
        elif args.log == '-':
            source = sys.stdin
        else:
            stream = gzip.open(args.log, 'rt', errors='replace') if args.log.endswith('.gz') else open(args.log, errors='replace')
            source = stream
        parsed, automated, ignored, total = [], 0, 0, 0
        selected = set(args.client)
        for line in source:
            total += 1
            if total > args.max_lines:
                break
            request = parse_line(line)
            if not request:
                ignored += 1
            elif AUTOMATION.search(request.ua) or 'Mozilla/' not in request.ua:
                automated += 1
            elif not selected or request.client in selected:
                if request.path != '/__landing-debug' or args.debug:
                    parsed.append(request)
        warnings = []
        if total >= args.max_lines:
            warnings.append('A napló elérte a sorkorlátot; a kivonat hiányos lehet.')
        if ignored:
            warnings.append(f'{ignored} sor nem értelmezhető access logként (pl. nginx error log).')
        if not args.assets:
            warnings.append('Nincs build-katalógus: a service-worker előtöltés és a lazy felületek nem azonosíthatók.')
        report = {'assetBuildId': catalog.build_id, 'parsedRequests': len(parsed),
                  'automatedRequests': automated, 'warnings': warnings,
                  'sessions': analyze(parsed, catalog, args.gap_minutes),
                  'coverage': COVERAGE, 'limits': LIMITS}
        report['summary'] = traffic_summary(report['sessions'])
        output = report['summary'] if args.summary else report
        print(json.dumps(output, ensure_ascii=False, indent=2) if args.format == 'json' else
              render_summary(report['summary']) if args.summary else render(report, args.timezone), end='\n' if args.format == 'json' else '')
    finally:
        if stream:
            stream.close()
        if args.netcup and 'source' in locals():
            source.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, ImportError) as error:
        # Avoid echoing credential values, raw remote logs or arbitrary URLs.
        print(f'Hiba ({type(error).__name__}): ellenőrizd a bemenetet, a build-katalógust és az SSH-hozzáférést.', file=sys.stderr)
        sys.exit(1)
