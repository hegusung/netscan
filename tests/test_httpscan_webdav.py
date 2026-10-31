import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def _load_webdav_module():
    utils = types.ModuleType("utils")
    utils.output = types.ModuleType("utils.output")
    utils.output.Output = object
    utils.db = types.ModuleType("utils.db")
    utils.db.DB = object
    utils.utils = types.ModuleType("utils.utils")
    utils.utils.gen_random_string = lambda: None
    utils.utils.gen_bruteforce_creds = lambda: None
    http_module = types.ModuleType("lib.httpscan.http")
    http_module.HTTP = object

    modules = {
        "utils": utils,
        "utils.output": utils.output,
        "utils.db": utils.db,
        "utils.utils": utils.utils,
        "lib.httpscan.http": http_module,
    }
    path = Path(__file__).parents[1] / "scripts/lib/httpscan/modules/webdav.py"
    spec = importlib.util.spec_from_file_location("tested_webdav", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class WebDavDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.webdav = _load_webdav_module()

    def test_plain_html_200_is_not_webdav(self):
        response = {
            "code": 200,
            "headers": {"Content-Type": "text/html"},
            "content-type": "text/html",
            "html": "<html><title>Portainer</title></html>",
        }

        self.assertFalse(self.webdav.is_webdav_response(response))

    def test_webdav_evidence_is_accepted(self):
        self.assertTrue(self.webdav.is_webdav_response({"code": 207}))
        self.assertTrue(self.webdav.is_webdav_response({
            "code": 200,
            "headers": {"DAV": "1,2"},
        }))
        self.assertTrue(self.webdav.is_webdav_response({
            "code": 200,
            "headers": {},
            "content-type": "application/xml",
            "html": "<?xml version='1.0'?><D:multistatus />",
        }))


if __name__ == "__main__":
    unittest.main()
