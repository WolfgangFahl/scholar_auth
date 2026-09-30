"""
Created on 2026-09-30

@author: wf
"""

import tempfile
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

from basemkit.basetest import Basetest

from scholar_auth.orcid import OrcidAccessToken, OrcidAuth, OrcidConfig, current_timestamp


class TestOrcid(Basetest):
    """
    test OrcidAuth, OrcidConfig and OrcidAccessToken
    """

    def setUp(self, debug=False, profile=True):
        Basetest.setUp(self, debug=debug, profile=profile)

    def configured_orcid_auth(self, tmpdir: str, session_storage: dict) -> OrcidAuth:
        """
        get an OrcidAuth with the sample configuration and the given session storage
        """
        basedir = Path(tmpdir)
        config = OrcidConfig.get_samples()[0]
        config.save_to_yaml_file(str(basedir / "orcid_config.yaml"))
        orcid_auth = OrcidAuth(basedir, storage_provider=lambda: session_storage)
        return orcid_auth

    def test_config_availability(self):
        """
        tests availability
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            basedir = Path(tmpdir) / ".solutions/scholar_auth"
            basedir.mkdir(exist_ok=True, parents=True)
            self.assertFalse(OrcidAuth(basedir).available())
            config = OrcidConfig.get_samples()[0]
            config_file_name = "orcid_config.yaml"
            config.save_to_yaml_file(str(basedir / config_file_name))
            orcid_auth = OrcidAuth(basedir, config_file_name)
            self.assertTrue(orcid_auth.available())
            authenticate_url = (
                "https://orcid.org/oauth/authorize?client_id=APP-123456789ABCDEFG&response_type=code&"
                "scope=/authenticate&redirect_uri=http://127.0.0.1:9862/orcid_callback"
            )
            self.assertEqual(orcid_auth.authenticate_url(), authenticate_url)

    def test_token_validity(self):
        """
        test the expiry check of the access token
        """
        orcid_token = OrcidAccessToken.get_samples()[0]
        self.assertTrue(orcid_token.is_valid())
        orcid_token.expires_in = 60
        orcid_token.login_timestamp = current_timestamp() - 120
        self.assertFalse(orcid_token.is_valid())

    def test_login_timestamp(self):
        """
        test that the login timestamp is taken when the token is created
        """
        with patch("scholar_auth.orcid.time", return_value=2000000000):
            orcid_token = OrcidAccessToken.get_samples()[0]
        self.assertEqual(2000000000, orcid_token.login_timestamp)

    def test_login_and_logout(self):
        """
        test login with a mocked ORCID token endpoint and logout
        """
        session_storage = {}
        token_record = asdict(OrcidAccessToken.get_samples()[0])
        token_record.pop("login_timestamp")
        response = MagicMock()
        response.json.return_value = token_record
        with tempfile.TemporaryDirectory() as tmpdir:
            orcid_auth = self.configured_orcid_auth(tmpdir, session_storage)
            self.assertFalse(orcid_auth.authenticated())
            with patch("scholar_auth.orcid.requests.post", return_value=response) as post:
                self.assertTrue(orcid_auth.login("123456"))
            url = post.call_args.args[0]
            data = post.call_args.kwargs["data"]
            self.assertEqual("https://orcid.org/oauth/token", url)
            self.assertEqual("authorization_code", data["grant_type"])
            self.assertEqual("123456", data["code"])
            self.assertTrue(orcid_auth.authenticated())
            self.assertIn(OrcidAuth.TOKEN_KEY, session_storage)
            orcid_token = orcid_auth.get_cached_user_access_token()
            self.assertEqual("0000-0001-2345-6789", orcid_token.orcid)
            self.assertEqual("Sofia Garcia", orcid_token.name)
            orcid_auth.logout()
            self.assertFalse(orcid_auth.authenticated())
            self.assertEqual({}, session_storage)
            orcid_auth.logout()

    def test_sessions_are_separate(self):
        """
        test that the storage provider decides which session is logged in
        """
        sessions = {"alice": {}, "bob": {}}
        current = {"user": "alice"}
        token_record = asdict(OrcidAccessToken.get_samples()[0])
        with tempfile.TemporaryDirectory() as tmpdir:
            basedir = Path(tmpdir)
            OrcidConfig.get_samples()[0].save_to_yaml_file(str(basedir / "orcid_config.yaml"))
            orcid_auth = OrcidAuth(basedir, storage_provider=lambda: sessions[current["user"]])
            sessions["alice"][OrcidAuth.TOKEN_KEY] = token_record
            self.assertTrue(orcid_auth.authenticated())
            current["user"] = "bob"
            self.assertFalse(orcid_auth.authenticated())

    def test_not_configured(self):
        """
        test that nobody is authenticated without a configuration
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            token_record = asdict(OrcidAccessToken.get_samples()[0])
            session_storage = {OrcidAuth.TOKEN_KEY: token_record}
            orcid_auth = OrcidAuth(Path(tmpdir), storage_provider=lambda: session_storage)
            self.assertFalse(orcid_auth.available())
            self.assertFalse(orcid_auth.authenticated())
