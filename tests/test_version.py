"""
Created on 2026-09-30

@author: wf
"""

import re

from basemkit.basetest import Basetest

import scholar_auth


class TestVersion(Basetest):
    """
    test the package version
    """

    def setUp(self, debug=False, profile=True):
        Basetest.setUp(self, debug=debug, profile=profile)

    def test_version(self):
        """
        test that the package carries a semantic version
        """
        version = scholar_auth.__version__
        if self.debug:
            print(version)
        self.assertIsNotNone(re.fullmatch(r"\d+\.\d+\.\d+", version), f"invalid version {version}")
