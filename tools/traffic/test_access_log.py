"""Focused regressions for misleading journey inferences, without a server."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import quote


SPEC = importlib.util.spec_from_file_location('access_log', Path(__file__).with_name('analyze-access-log.py'))
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
WV = 'Mozilla/5.0 (Linux; Android 15; device; wv) AppleWebKit/537.36 Version/4.0 Chrome/155.0 Mobile Safari/537.36'
IG = WV + ' Instagram 451.0 Android'
CHROME = 'Mozilla/5.0 (Linux; Android 15; device) AppleWebKit/537.36 Chrome/155.0 Mobile Safari/537.36'


def request(path='/', second=0, ua=IG, method='GET', status=200, ip='192.0.2.1'):
    line = (f'{ip} - - [20/Oct/2026:07:23:{second:02d} +0200] '
            f'"{method} {path} HTTP/2.0" {status} 123 "-" "{ua}" "198.51.100.7"')
    return MODULE.parse_line(line)


def kinds(sessions):
    return [item['kind'] for session in sessions for item in session['events']]


class JourneyTests(unittest.TestCase):
    def test_access_only_summary_distinguishes_paid_visits_and_followup_without_debug(self):
        rows = [request('/?utm_source=ig&utm_medium=paid&utm_campaign=SECRET'),
                request('/api/landing/content', second=1), request('/app-sw.js', second=2),
                request('/?utm_source=google&utm_medium=cpc', ip='192.0.2.2', ua=CHROME),
                request('/api/auth/demo-users', second=3, ip='192.0.2.2', ua=CHROME),
                request('/?utm_source=ig&utm_medium=paid', ip='192.0.2.3'),
                request('/api/auth/session/login', second=4, ip='192.0.2.3', method='POST')]
        summary = MODULE.traffic_summary(MODULE.analyze(rows, self.catalog))
        self.assertEqual(summary['sources']['meta_paid']['sessions'], 2)
        self.assertEqual(summary['sources']['meta_paid']['noFurtherActivity'], 1)
        self.assertEqual(summary['sources']['meta_paid']['login'], 1)
        self.assertEqual(summary['sources']['other_paid']['demo'], 1)
        self.assertEqual(summary['furtherActivity'], 2)
        self.assertEqual(summary['sources']['meta_paid']['debugSessions'], 0)
        self.assertNotIn('SECRET', json.dumps(summary))

    def test_instagram_browser_alone_is_not_paid_ad_evidence(self):
        summary = MODULE.traffic_summary(MODULE.analyze([request('/')], self.catalog))
        self.assertIn('meta_browser', summary['sources'])
        self.assertNotIn('meta_paid', summary['sources'])

    def setUp(self):
        self.catalog = MODULE.Catalog()
        self.catalog.labels = {'/demo.js': 'Demóprofil-választó'}
        self.catalog.precache = {'/'} | {f'/chunk-{n}.js' for n in range(30)}
        self.catalog.known = set(self.catalog.labels) | self.catalog.precache

    def test_combined_and_docker_timestamps_and_untrusted_forwarded_for(self):
        row = request('/api/landing/articles?page=2&pageSize=10&userId=secret&token=secret')
        self.assertEqual(row.ip, '192.0.2.1')
        self.assertEqual(row.params, {'page': 2, 'pageSize': 10})
        self.assertEqual(MODULE.parse_line('2026-10-20T05:23:00.123Z 192.0.2.1 - - '
                                          '[20/Oct/2026:07:23:00 +0200] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"').path, '/')
        self.assertIsNone(MODULE.parse_line('2026/10/20 [error] unrelated nginx error'))

    def test_more_article_has_api_evidence_but_no_claim_of_reading_an_article(self):
        sessions = MODULE.analyze([request('/api/landing/articles?page=1&cursor=secret')], self.catalog)
        item = sessions[0]['events'][0]
        self.assertEqual(item['kind'], 'articles')
        self.assertEqual(item['confidence'], 'valószínű')
        self.assertIn('page=1', item['evidence'])
        self.assertNotIn('secret', json.dumps(sessions))

    def test_debug_packets_preserve_15_second_checkpoints_and_redact_unrecognized_data(self):
        data = {'v': 1, 'id': '0123456789abcdef', 'seq': 1, 'ms': 15000,
                'visibleMs': 15000, 'interactionMs': 5, 'reason': 'tick',
                'counts': {'pointer': 1, 'key': 0, 'click': 1}, 'errorCount': 1,
                'dropped': 0, 'marks': [[6, 'login.click'], [7, 'SECRET']],
                'errors': [{'name': 'TypeError', 'code': '1234abcd', 'file': 'chunk-ABC.js',
                            'line': 1, 'column': 2, 'ms': 10, 'message': 'SECRET'}], 'token': 'SECRET'}
        first = request('/__landing-debug?d=' + quote(json.dumps(data)), second=15, method='POST', status=204)
        data.update(seq=2, ms=30000, visibleMs=30000)
        last = request('/__landing-debug?d=' + quote(json.dumps(data)), second=30, method='POST', status=204)
        events = MODULE.analyze([first, last], self.catalog)[0]['events']
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]['debug']['marks'], [[6, 'login.click']])
        self.assertEqual(events[1]['debug']['ms'], 30000)
        self.assertNotIn('SECRET', json.dumps(events))

    def test_invalid_and_disabled_debug_packets_are_not_accepted_as_client_evidence(self):
        for payload in ('null', '[]', '{"v":1}', '{"id":[]}'):
            row = request('/__landing-debug?d=' + quote(payload), method='POST', status=204)
            self.assertNotIn('landing_debug', kinds(MODULE.analyze([row], self.catalog)))

    def test_error_details_are_bounded_redacted_and_rendered_without_raw_stack_or_urls(self):
        data = {'v': 1, 'id': '0123456789abcdef', 'seq': 1, 'ms': 15000,
                'visibleMs': 15000, 'interactionMs': None, 'reason': 'tick',
                'counts': {}, 'errorCount': 1, 'dropped': 0, 'marks': [],
                'errors': [{'name': 'TypeError', 'code': '1234abcd', 'file': 'chunk-ABC.js',
                            'line': 1, 'column': 2, 'ms': 10,
                            'detail': {'source': 'window',
                                       'message': 'Failed https://test/private?token=PRIVATE_TOKEN for private@example.com token=PRIVATE_SECRET',
                                       'stack': ['render chunk-ABC.js:1:2', 'https://test/PRIVATE_PATH.js:3:4',
                                                 'main-XYZ.js:5:6', 'ignored.js:7:8']}}]}
        row = request('/__landing-debug?d=' + quote(json.dumps(data)), method='POST', status=204)
        sessions = MODULE.analyze([row], self.catalog)
        detail = sessions[0]['events'][0]['debug']['errors'][0]['detail']
        self.assertEqual(detail['message'], 'Failed [url] for [email] [credential]')
        self.assertEqual(detail['stack'], ['render chunk-ABC.js:1:2', 'main-XYZ.js:5:6'])
        report = {'assetBuildId': None, 'parsedRequests': 1, 'automatedRequests': 0,
                  'warnings': [], 'sessions': sessions, 'coverage': [], 'limits': []}
        rendered = MODULE.render(report, 'Europe/Prague')
        self.assertIn('window: Failed [url]', rendered)
        self.assertIn('render chunk-ABC.js:1:2', rendered)
        self.assertNotIn('PRIVATE', rendered)
        self.assertNotIn('example.com', rendered)

    def test_diagnostic_message_redaction_covers_quoted_values_credentials_and_identifiers(self):
        value = ('Cannot read "PRIVATE_VALUE" password=PRIVATE_PASS Bearer PRIVATE_BEARER '
                 '123e4567-e89b-12d3-a456-426614174000 47.123456\n\x1b[31m')
        cleaned = MODULE.clean_debug_message(value)
        self.assertIn('Cannot read [value]', cleaned)
        self.assertNotIn('PRIVATE', cleaned)
        self.assertNotIn('123e4567', cleaned)
        self.assertNotIn('47.123456', cleaned)
        self.assertNotIn('\x1b', cleaned)
        self.assertLessEqual(len(MODULE.clean_debug_message('Á' * 1000)), 160)

    def test_landing_and_firebase_configuration_are_background_signals(self):
        sessions = MODULE.analyze([request('/api/landing/content'), request('/api/deployment/configuration/firebase-config')], self.catalog)
        self.assertEqual(kinds(sessions), ['background', 'background'])

    def test_lifecycle_report_preserves_hidden_duration_original_headers_and_rendering_evidence(self):
        data = {'v': 1, 'id': '0123456789abcdef', 'seq': 2, 'ms': 31000, 'visibleMs': 1000,
                'interactionMs': None, 'reason': 'pagehide', 'counts': {}, 'errorCount': 0,
                'dropped': 0, 'marks': [], 'errors': [],
                'page': {'initial': 387, 'state': 480, 'offsetMs': 200, 'hiddenForMs': 30000,
                         'context': [2, 0], 'navigation': 'navigate', 'delivery': 'navigational-prefetch',
                         'timing': {'responseEnd': 250, 'activationStart': 0, 'PRIVATE': 10},
                         'events': [[0, 'init', 387], [1000, 'hidden', 384], [31000, 'pagehide', 480],
                                    [1001, 'PRIVATE', 0]], 'url': 'PRIVATE'}}
        row = request('/__landing-debug?d=' + quote(json.dumps(data)), method='POST', status=204)
        sessions = MODULE.analyze([row], self.catalog)
        page = sessions[0]['events'][0]['debug']['page']
        self.assertEqual(page['hiddenForMs'], 30000)
        self.assertEqual(page['context'], [2, 0])
        self.assertEqual(len(page['events']), 3)
        report = {'assetBuildId': None, 'parsedRequests': 1, 'automatedRequests': 0,
                  'warnings': [], 'sessions': sessions, 'coverage': [], 'limits': []}
        output = MODULE.render(report, 'Europe/Prague')
        self.assertIn('purpose=prerender', output)
        self.assertIn('hidden óta 30000 ms', output)
        self.assertIn('lifecycle pagehide', output)
        self.assertIn('ready=complete', output)
        self.assertNotIn('PRIVATE', output)

    def test_invalid_optional_lifecycle_does_not_discard_the_original_error_or_interaction_report(self):
        for page in [None, [], {'initial': 'PRIVATE'}, {'initial': 999999}]:
            self.assertIsNone(MODULE.safe_page(page, 10))
        self.assertIn('prerender=ismeretlen', MODULE.page_state_label(1))
        self.assertIn('userActivated=ismeretlen', MODULE.page_state_label(1))

    def test_lifecycle_fields_and_samples_remain_bounded(self):
        page = {'initial': 1, 'state': 64, 'offsetMs': 100, 'hiddenForMs': 0, 'context': [0, 1],
                'navigation': 'reload', 'delivery': '', 'timing': {'responseEnd': 250, 'workerStart': -1},
                'events': [[i, 'focus', 3] for i in range(50)]}
        parsed = MODULE.safe_page(page, 31000)
        self.assertEqual(len(parsed['events']), 12)
        self.assertEqual(parsed['timing'], {'responseEnd': 250})
        for key, value in [('context', [3, 0]), ('navigation', 'PRIVATE'), ('hiddenForMs', 60001)]:
            self.assertIsNone(MODULE.safe_page({**page, key: value}, 31000))

    def test_bulk_precache_never_becomes_thirty_page_or_popup_clicks(self):
        self.catalog.labels.update({f'/chunk-{n}.js': 'Popup' for n in range(30)})
        rows = [request('/', ua=IG)] + [request(f'/chunk-{n}.js', second=2, ua=WV) for n in range(30)]
        sessions = MODULE.analyze(rows, self.catalog)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(kinds(sessions), ['precache'])

    def test_precache_does_not_hide_real_article_api_requests(self):
        rows = [request(f'/chunk-{n}.js', second=2, ua=WV) for n in range(30)]
        rows += [request('/api/landing/articles', second=3)]
        self.assertIn('articles', kinds(MODULE.analyze(rows, self.catalog)))

    def test_isolated_lazy_component_is_possible_not_confirmed_click(self):
        sessions = MODULE.analyze([request('/demo.js')], self.catalog)
        self.assertEqual(kinds(sessions), ['lazy_surface'])
        self.assertEqual(sessions[0]['events'][0]['confidence'], 'lehetséges')

    def test_unknown_chunk_from_another_build_has_no_surface_claim(self):
        sessions = MODULE.analyze([request('/chunk-OTHERBUILD.js')], self.catalog)
        self.assertEqual(kinds(sessions), [])
        self.assertEqual(sessions[0]['unknownJsRequests'], 1)

    def test_entry_static_dependency_cannot_be_a_lazy_click(self):
        self.catalog.initial.add('/demo.js')
        self.assertNotIn('lazy_surface', kinds(MODULE.analyze([request('/demo.js')], self.catalog)))

    def test_bare_webview_is_not_external_chrome(self):
        sessions = MODULE.analyze([request('/', ua=IG), request('/', ua=WV, second=3)], self.catalog)
        self.assertNotIn('browser_handoff', kinds(sessions))
        self.assertFalse(MODULE.external_browser(WV))

    def test_external_chrome_document_is_only_possible_handoff(self):
        sessions = MODULE.analyze([request('/', ua=IG), request('/', ua=CHROME, second=3)], self.catalog)
        handoffs = [item for session in sessions for item in session['events'] if item['kind'] == 'browser_handoff']
        self.assertEqual(len(handoffs), 1)
        self.assertEqual(handoffs[0]['confidence'], 'lehetséges')

    def test_external_asset_only_or_other_ip_is_not_handoff(self):
        sessions = MODULE.analyze([request('/', ua=IG), request('/demo.js', ua=CHROME, second=3),
                                   request('/', ua=CHROME, second=3, ip='192.0.2.2')], self.catalog)
        self.assertNotIn('browser_handoff', kinds(sessions))

    def test_failed_request_never_implies_success(self):
        sessions = MODULE.analyze([request('/api/auth/session/login', method='POST', status=401)], self.catalog)
        self.assertIn('Sikertelen kérés', sessions[0]['events'][0]['description'])
        self.assertEqual(sessions[0]['events'][0]['confidence'], 'megfigyelt')

    def test_repeated_calls_keep_count_and_different_status(self):
        sessions = MODULE.analyze([request('/api/auth/me', second=0), request('/api/auth/me', second=2),
                                   request('/api/auth/me', second=3, status=401)], self.catalog)
        self.assertEqual(len(sessions[0]['events']), 2)
        self.assertEqual(sessions[0]['events'][0]['count'], 2)

    def test_gap_splits_visits_and_not_people(self):
        first, last = request('/'), request('/')
        last.time += MODULE.timedelta(minutes=31)
        sessions = MODULE.analyze([last, first], self.catalog)
        self.assertEqual(len(sessions), 2)
        self.assertEqual(sessions[0]['client'], sessions[1]['client'])

    def test_reports_do_not_expose_ip_user_agent_tokens_or_unrecognized_paths(self):
        rows = [request('/api/landing/articles?token=SECRET_TOKEN&userId=PRIVATE_USER'),
                request('/api/users/PRIVATE_USER'), request('/admin/help/SECRET_TOKEN')]
        report = {'assetBuildId': 'test', 'parsedRequests': 3, 'automatedRequests': 0,
                  'warnings': [], 'sessions': MODULE.analyze(rows, self.catalog),
                  'coverage': MODULE.COVERAGE, 'limits': MODULE.LIMITS}
        for output in (json.dumps(report), MODULE.render(report, 'Europe/Prague')):
            for sensitive in ('192.0.2.1', 'SECRET_TOKEN', 'PRIVATE_USER', IG):
                self.assertNotIn(sensitive, output)

    def test_catalog_uses_emitted_dynamic_selectors_static_graph_and_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app-version.json').write_text('{"buildId":"test-build"}')
            (root / 'app-sw.js').write_text("const PRECACHE_CORE_URLS = ['./'];\nconst PRECACHE_BUILD_URLS = [\"./demo.js\"];")
            (root / 'index.html').write_text('<script type="module" src="main.js"></script>')
            (root / 'main.js').write_text('import{a}from"./shared.js";import("./demo.js");import("./entry.js");')
            (root / 'shared.js').write_text('export{};')
            (root / 'demo.js').write_text('selectors:[["app-demo-bootstrap-selector"]]')
            (root / 'entry.js').write_text('selectors:[["app-entry-page"]]')
            catalog = MODULE.Catalog(root)
            self.assertEqual(catalog.initial, {'/main.js', '/shared.js'})
            self.assertEqual(catalog.labels, {'/demo.js': 'Demóprofil-választó'})
            self.assertEqual(catalog.precache, {'/', '/demo.js'})


if __name__ == '__main__':
    unittest.main()
