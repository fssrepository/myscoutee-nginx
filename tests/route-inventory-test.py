#!/usr/bin/env python3
"""The public inventory excludes nested optional-module source and test roots."""
from pathlib import Path
import runpy
import tempfile
import unittest


GENERATOR = Path(__file__).resolve().parents[1] / 'tools/render-routes.py'


class RouteInventoryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.java = self.root / 'server/projects/profile/src/main/java'
        self.java.mkdir(parents=True)
        angular = self.root / 'frontend/src/app/app.routes.ts'
        angular.parent.mkdir(parents=True)
        angular.write_text("export const routes = [{ path: 'entry' }];")
        routing = self.root / 'config/nginx/http/routing.conf'
        routing.parent.mkdir(parents=True)
        routing.write_text('location /api/ { proxy_pass http://api; }')
        self.render = runpy.run_path(str(GENERATOR), init_globals={'PROJECT_ROOT': self.root})['inventory']

    def source(self, path, text):
        target = self.java / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def test_ignores_optional_transport_controllers_and_their_tests(self):
        self.source('com/example/PublicController.java', '''
@RestController
@RequestMapping("/public")
public class PublicController { @GetMapping("/query") void query() {} }
''')
        self.source('com/example/transport/src/main/java/InternalEndpoint.java', '''
@RestController
public class InternalEndpoint { @PostMapping(value = ExternalProtocol.PATH) void derive() {} }
''')
        self.source('com/example/transport/src/test/java/TestController.java', '''
@RestController
public class TestController { @GetMapping("/test-only") void test() {} }
''')
        rendered = self.render()
        self.assertIn('"/api/public/query" 1;', rendered)
        self.assertIn('"/entry" 1;', rendered)
        self.assertNotIn('test-only', rendered)

    def test_retains_failure_for_an_unresolved_active_public_mapping(self):
        self.source('com/example/PublicController.java', '''
@RestController
public class PublicController { @GetMapping(value = MissingProtocol.PATH) void query() {} }
''')
        with self.assertRaisesRegex(ValueError, 'Unresolved public mapping'):
            self.render()

    def test_retains_the_public_localization_dependency_endpoint(self):
        self.assertIn('"/api/i18n/bundle" 1;', self.render())


if __name__ == '__main__':
    unittest.main()
