"""
Created on 2026-09-30

@author: wf

ORCID OAuth login - moved from snapquery/orcid.py and made independent of the web framework
"""

from dataclasses import asdict, field
from pathlib import Path
from time import time
from typing import Callable, MutableMapping, Optional

import requests
from basemkit.yamlable import lod_storable


def current_timestamp() -> int:
    """
    get the current time

    Returns:
        int: the current time in seconds since the epoch
    """
    timestamp = int(time())
    return timestamp


@lod_storable
class OrcidConfig:
    """
    orcid authentication configuration
    """

    url: str
    client_id: str
    client_secret: str
    redirect_uri: str = "http://127.0.0.1:9862/orcid_callback"
    api_endpoint: str = "https://pub.orcid.org/v3.0"
    search_token: Optional[str] = None

    @classmethod
    def get_samples(cls) -> list["OrcidConfig"]:
        """
        get sample configurations

        Returns:
            list[OrcidConfig]: the samples
        """
        lod = [
            {
                "url": "https://orcid.org",
                "client_id": "APP-123456789ABCDEFG",
                "client_secret": "<KEY>",
                "redirect_uri": "http://127.0.0.1:9862/orcid_callback",
                "api_endpoint": "https://sandbox.orcid.org/v3.0",
            }
        ]
        samples = [OrcidConfig.from_dict2(d) for d in lod]
        return samples

    def authenticate_url(self) -> str:
        """
        get the url that starts the login at ORCID

        Returns:
            str: the authorize url for the authorization code flow
        """
        url = (
            f"{self.url}/oauth/authorize?client_id={self.client_id}"
            f"&response_type=code&scope=/authenticate&redirect_uri={self.redirect_uri}"
        )
        return url


@lod_storable
class OrcidAccessToken:
    """
    orcid access token response
    """

    orcid: str
    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int
    scope: str
    name: str
    login_timestamp: int = field(default_factory=current_timestamp)

    @classmethod
    def get_samples(cls) -> list["OrcidAccessToken"]:
        """
        get sample access tokens

        Returns:
            list[OrcidAccessToken]: the samples
        """
        lod = [
            {
                "access_token": "f5af9f51-07e6-4332-8f1a-c0c11c1e3728",
                "token_type": "bearer",
                "refresh_token": "f725f747-3a65-49f6-a231-3e8944ce464d",
                "expires_in": 631138518,
                "scope": "/activities/update /read-limited",
                "name": "Sofia Garcia",
                "orcid": "0000-0001-2345-6789",
            }
        ]
        samples = [OrcidAccessToken.from_dict2(d) for d in lod]
        return samples

    def is_valid(self) -> bool:
        """
        check whether this access token has not expired yet

        Returns:
            bool: True if the token is still valid
        """
        time_passed = current_timestamp() - self.login_timestamp
        valid = self.expires_in - time_passed >= 0
        return valid


class OrcidAuth:
    """
    authenticate with orcid

    the session storage is supplied by the calling application as a function
    returning the mapping that belongs to the current user session
    """

    TOKEN_KEY = "orcid_token"

    def __init__(
        self,
        base_path: Optional[Path] = None,
        config_file_name: str = "orcid_config.yaml",
        storage_provider: Optional[Callable[[], MutableMapping]] = None,
    ):
        """
        constructor

        Args:
            base_path: the directory of the configuration file, default: ~/.solutions/scholar_auth
            config_file_name: the name of the configuration file
            storage_provider: function returning the storage of the current user session,
                default: a single in-memory storage
        """
        if base_path is None:
            base_path = Path.home() / ".solutions/scholar_auth"
        self.base_path = base_path
        self.config_file_name = config_file_name
        self.memory_storage: dict = {}
        if storage_provider is None:
            storage_provider = self.get_memory_storage
        self.storage_provider = storage_provider
        self.config = self.load_config()

    def get_memory_storage(self) -> MutableMapping:
        """
        get the in-memory storage used when the application supplies none

        Returns:
            MutableMapping: the in-memory storage
        """
        storage = self.memory_storage
        return storage

    def get_config_path(self) -> Path:
        """
        get the path of the configuration file

        Returns:
            Path: the configuration file path
        """
        config_path = self.base_path / self.config_file_name
        return config_path

    def config_exists(self) -> bool:
        """
        check whether the configuration file exists

        Returns:
            bool: True if the configuration file exists
        """
        exists = self.get_config_path().exists()
        return exists

    def available(self) -> bool:
        """
        check whether the ORCID login is configured

        Returns:
            bool: True if a configuration has been loaded
        """
        is_available = self.config is not None
        return is_available

    def load_config(self) -> Optional[OrcidConfig]:
        """
        load the configuration

        Returns:
            Optional[OrcidConfig]: the configuration or None if there is no configuration file
        """
        config = None
        if self.config_exists():
            config = OrcidConfig.load_from_yaml_file(str(self.get_config_path()))
        return config

    def store_config(self) -> None:
        """
        store the configuration
        """
        self.config.save_to_yaml_file(str(self.get_config_path()))

    def authenticate_url(self) -> str:
        """
        get the url that starts the login at ORCID

        Returns:
            str: the authorize url
        """
        url = self.config.authenticate_url()
        return url

    def authenticated(self) -> bool:
        """
        check whether the user of the current session is logged in

        Returns:
            bool: True if there is a valid access token for the current session
        """
        is_authenticated = False
        if self.available():
            orcid_token = self.get_cached_user_access_token()
            if orcid_token is not None:
                is_authenticated = orcid_token.is_valid()
        return is_authenticated

    def get_cached_user_access_token(self) -> Optional[OrcidAccessToken]:
        """
        get the access token of the current session

        Returns:
            Optional[OrcidAccessToken]: the access token or None if the user is not logged in
        """
        orcid_token = None
        orcid_token_record = self.storage_provider().get(self.TOKEN_KEY, None)
        if orcid_token_record:
            orcid_token = OrcidAccessToken.from_dict2(orcid_token_record)
        return orcid_token

    def login(self, access_code: str) -> bool:
        """
        login with the code that ORCID handed to the callback

        Args:
            access_code: the authorization code

        Returns:
            bool: True if the login succeeded

        Raises:
            requests.RequestException: if the token request fails
        """
        orcid_token = self._retrieve_token(access_code)
        self.storage_provider()[self.TOKEN_KEY] = asdict(orcid_token)
        is_authenticated = True
        return is_authenticated

    def _retrieve_token(self, code: str) -> OrcidAccessToken:
        """
        exchange the authorization code for an access token

        URL=https://sandbox.orcid.org/oauth/token
         HEADER: Accept: application/json
         HEADER: Content-Type: application/x-www-form-urlencoded
         METHOD: POST
         DATA:
           client_id=[Your client ID]
           client_secret=[Your client secret]
           grant_type=authorization_code
           code=Six-digit code

        Args:
            code: the authorization code

        Returns:
            OrcidAccessToken: the access token
        """
        url = f"{self.config.url}/oauth/token"
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "grant_type": "authorization_code",
            "code": code,
        }
        resp = requests.post(url, data=data)
        resp.raise_for_status()
        resp_json = resp.json()
        orcid_token = OrcidAccessToken.from_dict2(resp_json)
        return orcid_token

    def logout(self) -> None:
        """
        logout the user of the current session by deleting the cached access token
        """
        self.storage_provider().pop(self.TOKEN_KEY, None)
