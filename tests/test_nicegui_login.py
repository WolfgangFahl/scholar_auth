"""
Created on 2026-09-30

@author: wf
"""

import tempfile
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

from basemkit.basetest import Basetest
from fastapi import HTTPException
from nicegui import app

from scholar_auth.authorization import Authorization, UserRights
from scholar_auth.nicegui_login import NiceGuiScholarLogin
from scholar_auth.orcid import OrcidAccessToken, OrcidAuth, OrcidConfig


class TestNiceGuiLogin(Basetest):
    """
    test the ORCID login for nicegui applications
    """

    def setUp(self, debug=False, profile=True):
        Basetest.setUp(self, debug=debug, profile=profile)

    def prepare_login(self, tmpdir: str, session_storage: dict) -> NiceGuiScholarLogin:
        """
        get a login for a system directory with the given session storage in place of app.storage.user
        """
        base_path = Path(tmpdir)
        OrcidConfig.get_samples()[0].save_to_yaml_file(str(base_path / "orcid_config.yaml"))
        user_rights = {"0000-0001-2345-6789": UserRights(name="Sofia Garcia", rights="wikidatasync log")}
        Authorization(user_rights=user_rights).save_to_yaml_file(str(base_path / "userrights.yaml"))
        nicegui_login = NiceGuiScholarLogin(base_path)
        nicegui_login.orcid_auth.storage_provider = lambda: session_storage
        return nicegui_login

    def test_callback(self):
        """
        test the ORCID callback with a mocked token endpoint
        """
        session_storage = {}
        token_record = asdict(OrcidAccessToken.get_samples()[0])
        response = MagicMock()
        response.json.return_value = token_record
        with tempfile.TemporaryDirectory() as tmpdir:
            nicegui_login = self.prepare_login(tmpdir, session_storage)
            self.assertFalse(nicegui_login.has_right("log"))
            with patch("scholar_auth.orcid.requests.post", return_value=response):
                redirect = nicegui_login.handle_callback("123456")
            self.assertEqual("/", redirect.headers["location"])
            self.assertTrue(nicegui_login.has_right("log"))
            self.assertTrue(nicegui_login.has_right("wikidatasync"))
            redirect = nicegui_login.handle_logout()
            self.assertEqual("/", redirect.headers["location"])
            self.assertNotIn(OrcidAuth.TOKEN_KEY, session_storage)
            self.assertFalse(nicegui_login.has_right("log"))

    def test_failed_callback(self):
        """
        test that a failing token request leads to a 401 without details
        """
        session_storage = {}
        with tempfile.TemporaryDirectory() as tmpdir:
            nicegui_login = self.prepare_login(tmpdir, session_storage)
            with patch("scholar_auth.orcid.requests.post", side_effect=RuntimeError("client_secret=top-secret")):
                with self.assertRaises(HTTPException) as context:
                    nicegui_login.handle_callback("123456")
            self.assertEqual(401, context.exception.status_code)
            self.assertEqual("ORCID login failed", context.exception.detail)
            self.assertFalse(nicegui_login.authenticated())

    def test_register_routes(self):
        """
        test that the callback and logout routes are registered with the nicegui app
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            nicegui_login = self.prepare_login(tmpdir, {})
            nicegui_login.register_routes()
            paths = [route.path for route in app.routes]
            self.assertIn("/orcid_callback", paths)
            self.assertIn("/logout", paths)
