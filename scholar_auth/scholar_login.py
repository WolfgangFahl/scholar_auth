"""
Created on 2026-09-30

@author: wf

login and rights of a scholar for one system
"""

from pathlib import Path
from typing import Callable, MutableMapping, Optional

from scholar_auth.authorization import Authorization
from scholar_auth.orcid import OrcidAccessToken, OrcidAuth


class ScholarLogin:
    """
    ORCID login combined with the user rights of one system

    a system keeps its ORCID configuration and its user rights file in its own directory
    """

    def __init__(
        self,
        base_path: Path,
        storage_provider: Optional[Callable[[], MutableMapping]] = None,
        config_file_name: str = "orcid_config.yaml",
        rights_file_name: str = "userrights.yaml",
    ):
        """
        constructor

        Args:
            base_path: the directory of the system with the ORCID configuration and the user rights file
            storage_provider: function returning the storage of the current user session
            config_file_name: the name of the ORCID configuration file
            rights_file_name: the name of the user rights file
        """
        self.base_path = Path(base_path)
        self.orcid_auth = OrcidAuth(self.base_path, config_file_name, storage_provider)
        self.rights_path = self.base_path / rights_file_name
        self.authorization = Authorization.load(str(self.rights_path))

    def available(self) -> bool:
        """
        check whether the ORCID login is configured for this system

        Returns:
            bool: True if there is an ORCID configuration
        """
        is_available = self.orcid_auth.available()
        return is_available

    def login_url(self) -> Optional[str]:
        """
        get the url that starts the login at ORCID

        Returns:
            Optional[str]: the url or None if the ORCID login is not configured
        """
        url = None
        if self.available():
            url = self.orcid_auth.authenticate_url()
        return url

    def login(self, access_code: str) -> bool:
        """
        login with the code that ORCID handed to the callback

        Args:
            access_code: the authorization code

        Returns:
            bool: True if the login succeeded
        """
        is_authenticated = self.orcid_auth.login(access_code)
        return is_authenticated

    def logout(self) -> None:
        """
        logout the user of the current session
        """
        self.orcid_auth.logout()

    def authenticated(self) -> bool:
        """
        check whether the user of the current session is logged in

        Returns:
            bool: True if the user is logged in
        """
        is_authenticated = self.orcid_auth.authenticated()
        return is_authenticated

    def current_user(self) -> Optional[OrcidAccessToken]:
        """
        get the logged in user of the current session

        Returns:
            Optional[OrcidAccessToken]: the access token with name and ORCID iD or None if nobody is logged in
        """
        orcid_token = None
        if self.authenticated():
            orcid_token = self.orcid_auth.get_cached_user_access_token()
        return orcid_token

    def has_right(self, right: str) -> bool:
        """
        check whether the user of the current session is logged in and has the given right

        Args:
            right: the name of the right

        Returns:
            bool: True if the user is logged in and the user rights file grants the right
        """
        granted = False
        orcid_token = self.current_user()
        if orcid_token is not None:
            granted = self.authorization.check_right_by_orcid(orcid_token.orcid, right)
        return granted

    def user_description(self) -> Optional[str]:
        """
        describe the logged in user of the current session

        Returns:
            Optional[str]: name and ORCID iD or None if nobody is logged in
        """
        description = None
        orcid_token = self.current_user()
        if orcid_token is not None:
            description = f"{orcid_token.name} ({orcid_token.orcid})"
        return description
