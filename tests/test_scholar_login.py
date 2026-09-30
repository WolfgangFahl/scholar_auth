"""
Created on 2026-09-30

@author: wf
"""

import tempfile
from dataclasses import asdict
from pathlib import Path

from basemkit.basetest import Basetest

from scholar_auth.authorization import Authorization, UserRights
from scholar_auth.orcid import OrcidAccessToken, OrcidAuth, OrcidConfig
from scholar_auth.scholar_login import ScholarLogin


class TestScholarLogin(Basetest):
    """
    test the login and rights of a scholar for one system
    """

    def setUp(self, debug=False, profile=True):
        Basetest.setUp(self, debug=debug, profile=profile)
        self.orcid = "0000-0001-2345-6789"

    def prepare_system(self, tmpdir: str, rights: str, with_config: bool = True) -> Path:
        """
        prepare the directory of a system with ORCID configuration and user rights file
        """
        base_path = Path(tmpdir)
        if with_config:
            OrcidConfig.get_samples()[0].save_to_yaml_file(str(base_path / "orcid_config.yaml"))
        user_rights = {self.orcid: UserRights(name="Sofia Garcia", rights=rights)}
        Authorization(user_rights=user_rights).save_to_yaml_file(str(base_path / "userrights.yaml"))
        return base_path

    def logged_in_storage(self) -> dict:
        """
        get a session storage with the sample user logged in
        """
        token_record = asdict(OrcidAccessToken.get_samples()[0])
        storage = {OrcidAuth.TOKEN_KEY: token_record}
        return storage

    def test_anonymous(self):
        """
        test that an anonymous visitor has no rights
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = self.prepare_system(tmpdir, "wikidatasync log")
            session_storage = {}
            scholar_login = ScholarLogin(base_path, storage_provider=lambda: session_storage)
            self.assertTrue(scholar_login.available())
            self.assertIn("/oauth/authorize", scholar_login.login_url())
            self.assertFalse(scholar_login.authenticated())
            self.assertIsNone(scholar_login.current_user())
            self.assertIsNone(scholar_login.user_description())
            self.assertFalse(scholar_login.has_right("log"))
            self.assertFalse(scholar_login.has_right("wikidatasync"))

    def test_authorized(self):
        """
        test that a logged in user has exactly the rights of the user rights file
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = self.prepare_system(tmpdir, "wikidatasync")
            session_storage = self.logged_in_storage()
            scholar_login = ScholarLogin(base_path, storage_provider=lambda: session_storage)
            self.assertTrue(scholar_login.authenticated())
            self.assertEqual("Sofia Garcia (0000-0001-2345-6789)", scholar_login.user_description())
            self.assertTrue(scholar_login.has_right("wikidatasync"))
            self.assertFalse(scholar_login.has_right("log"))
            scholar_login.logout()
            self.assertFalse(scholar_login.authenticated())
            self.assertFalse(scholar_login.has_right("wikidatasync"))

    def test_logged_in_without_rights(self):
        """
        test that a logged in user that is not in the user rights file has no rights
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = self.prepare_system(tmpdir, "wikidatasync log")
            session_storage = self.logged_in_storage()
            session_storage[OrcidAuth.TOKEN_KEY]["orcid"] = "0000-0002-1825-0097"
            scholar_login = ScholarLogin(base_path, storage_provider=lambda: session_storage)
            self.assertTrue(scholar_login.authenticated())
            self.assertFalse(scholar_login.has_right("log"))
            self.assertFalse(scholar_login.has_right("wikidatasync"))

    def test_not_configured(self):
        """
        test that a system without ORCID configuration grants nothing
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = self.prepare_system(tmpdir, "wikidatasync log", with_config=False)
            session_storage = self.logged_in_storage()
            scholar_login = ScholarLogin(base_path, storage_provider=lambda: session_storage)
            self.assertFalse(scholar_login.available())
            self.assertIsNone(scholar_login.login_url())
            self.assertFalse(scholar_login.authenticated())
            self.assertFalse(scholar_login.has_right("log"))

    def test_missing_rights_file(self):
        """
        test that a system without user rights file grants nothing
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir)
            OrcidConfig.get_samples()[0].save_to_yaml_file(str(base_path / "orcid_config.yaml"))
            session_storage = self.logged_in_storage()
            scholar_login = ScholarLogin(base_path, storage_provider=lambda: session_storage)
            self.assertTrue(scholar_login.authenticated())
            self.assertFalse(scholar_login.has_right("log"))
