"""
Created on 2024-10-20

@author: wf
"""

import tempfile
from pathlib import Path

from basemkit.basetest import Basetest

from scholar_auth.authorization import Authorization, UserRights


class TestAuthorization(Basetest):
    """
    test the Authorization
    """

    def setUp(self, debug=False, profile=True):
        Basetest.setUp(self, debug=debug, profile=profile)

    def test_authorization(self):
        """
        Test the authorization
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_test_path = str(Path(tmpdir) / "test_userrights.yaml")
            mock_rights = {"0000-0001-2345-6789": UserRights(name="John Doe", rights="llm")}
            auth = Authorization(user_rights=mock_rights)
            auth.save_to_yaml_file(yaml_test_path)
            auth_loaded = Authorization.load(yaml_test_path)
        self.assertTrue(auth_loaded.check_right_by_orcid("0000-0001-2345-6789", "llm"))
        self.assertTrue(auth_loaded.check_right_by_orcid("0000-0001-2345-6789"))
        self.assertFalse(auth_loaded.check_right_by_orcid("0000-0001-2345-6789", "admin"))
        self.assertFalse(auth_loaded.check_right_by_orcid("0000-0002-1825-0097", "llm"))
        self.assertFalse(auth_loaded.check_right_by_orcid("0000-0002-1825-0097"))

    def test_whole_word_rights(self):
        """
        test that a right only matches as a whole word of the rights string
        """
        orcid = "0000-0001-2345-6789"
        for rights in ["wikidatasync log", "wikidatasync,log", "wikidatasync, log"]:
            auth = Authorization(user_rights={orcid: UserRights(name="John Doe", rights=rights)})
            self.assertTrue(auth.check_right_by_orcid(orcid, "wikidatasync"), rights)
            self.assertTrue(auth.check_right_by_orcid(orcid, "log"), rights)
            self.assertFalse(auth.check_right_by_orcid(orcid, "sync"), rights)
            self.assertFalse(auth.check_right_by_orcid(orcid, "wikidata"), rights)

    def test_missing_file(self):
        """
        test that a missing user rights file grants no rights
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = Authorization.load(str(Path(tmpdir) / "missing.yaml"))
        self.assertEqual({}, auth.user_rights)
        self.assertFalse(auth.check_right_by_orcid("0000-0001-2345-6789"))
