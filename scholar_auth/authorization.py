"""
Created on 2024-10-20

@author: wf

moved from snapquery/authorization.py
"""

from dataclasses import field
from pathlib import Path
from typing import Optional

from basemkit.yamlable import lod_storable


@lod_storable
class UserRights:
    """
    the rights of a single user
    """

    name: str
    rights: str


@lod_storable
class Authorization:
    """
    Authorization check.
    """

    user_rights: dict[str, UserRights] = field(default_factory=dict)

    @classmethod
    def default_yaml_path(cls) -> Path:
        """
        get the default path of the user rights file

        Returns:
            Path: ~/.solutions/scholar_auth/userrights.yaml
        """
        yaml_path = Path.home() / ".solutions/scholar_auth/userrights.yaml"
        return yaml_path

    @classmethod
    def load(cls, yaml_path: Optional[str] = None) -> "Authorization":
        """
        Load user rights from a YAML file.

        Args:
            yaml_path: the path of the user rights file, default: see default_yaml_path

        Returns:
            Authorization: the loaded user rights, without any rights if the file does not exist
        """
        if yaml_path is None:
            yaml_path = str(cls.default_yaml_path())
        if Path(yaml_path).exists():
            authorization = cls.load_from_yaml_file(yaml_path)
        else:
            print(f"YAML file not found: {yaml_path}")
            authorization = cls()
        return authorization

    def check_right_by_orcid(self, orcid: str, rights: Optional[str] = None) -> bool:
        """
        Check if the user with the given ORCID has rights.

        Args:
            orcid: the ORCID iD of the user
            rights: the specific right to check, if None any known user passes

        Returns:
            bool: True if the user is known and has the given right
        """
        ok = False
        user_right = self.user_rights.get(orcid)
        if user_right is not None:
            ok = rights is None or rights in user_right.rights
        return ok
