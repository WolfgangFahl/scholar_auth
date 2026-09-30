"""
Created on 2026-09-30

@author: wf

ORCID login for nicegui applications - needs the optional nicegui dependency
"""

from pathlib import Path
from typing import MutableMapping

from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from nicegui import app

from scholar_auth.scholar_login import ScholarLogin


class NiceGuiScholarLogin(ScholarLogin):
    """
    ORCID login that keeps the session in the nicegui user storage
    and serves the ORCID callback and the logout
    """

    def __init__(
        self,
        base_path: Path,
        callback_path: str = "/orcid_callback",
        logout_path: str = "/logout",
        home_path: str = "/",
        config_file_name: str = "orcid_config.yaml",
        rights_file_name: str = "userrights.yaml",
    ):
        """
        constructor

        Args:
            base_path: the directory of the system with the ORCID configuration and the user rights file
            callback_path: the path of the redirect uri registered at ORCID
            logout_path: the path that logs the user out
            home_path: the path to go to after login and logout
            config_file_name: the name of the ORCID configuration file
            rights_file_name: the name of the user rights file
        """
        super().__init__(
            base_path,
            storage_provider=self.get_user_storage,
            config_file_name=config_file_name,
            rights_file_name=rights_file_name,
        )
        self.callback_path = callback_path
        self.logout_path = logout_path
        self.home_path = home_path

    def get_user_storage(self) -> MutableMapping:
        """
        get the nicegui storage of the current user session

        Returns:
            MutableMapping: app.storage.user
        """
        storage = app.storage.user
        return storage

    def handle_callback(self, code: str) -> RedirectResponse:
        """
        handle the redirect from ORCID

        Args:
            code: the authorization code

        Returns:
            RedirectResponse: the redirect to the home path

        Raises:
            HTTPException: 401 if the login fails
        """
        try:
            self.login(code)
        except Exception as ex:
            raise HTTPException(status_code=401, detail="ORCID login failed") from ex
        response = RedirectResponse(self.home_path)
        return response

    def handle_logout(self) -> RedirectResponse:
        """
        logout the user of the current session

        Returns:
            RedirectResponse: the redirect to the home path
        """
        self.logout()
        response = RedirectResponse(self.home_path)
        return response

    def register_routes(self) -> None:
        """
        register the ORCID callback and the logout route with the nicegui app
        """

        @app.get(self.callback_path)
        async def orcid_callback(code: str):
            response = self.handle_callback(code)
            return response

        @app.get(self.logout_path)
        async def orcid_logout():
            response = self.handle_logout()
            return response
