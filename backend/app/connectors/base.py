"""Connector architecture. A connector turns a project into (workspace root, repository metadata, commit sha).

New platforms (GitLab, Bitbucket, Azure DevOps, Jenkins) implement `Connector` and register in REGISTRY; the
scanner engine is platform-agnostic and consumes only the workspace + RepoMetadata.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..scanner.model import RepoMetadata


@dataclass
class AcquiredWorkspace:
    root: Path
    metadata: RepoMetadata
    commit_sha: str = ""
    sha_resolver: Callable[[str, str, str], str | None] | None = None


class ConnectorError(Exception):
    pass


class Connector(ABC):
    name: str = ""
    display_name: str = ""
    status: str = "available"  # available | planned

    @abstractmethod
    def acquire(self, *, project, secret: str | None, workdir: Path, upload_path: Path | None,
                progress: Callable[[str], None]) -> AcquiredWorkspace:
        ...


class PlannedConnector(Connector):
    status = "planned"

    def acquire(self, **_kw) -> AcquiredWorkspace:
        raise ConnectorError(f"{self.display_name} connector is not implemented yet - upload a ZIP of the repository instead.")


class GitLabConnector(PlannedConnector):
    name, display_name = "gitlab", "GitLab CI"


class BitbucketConnector(PlannedConnector):
    name, display_name = "bitbucket", "Bitbucket Pipelines"


class AzureDevOpsConnector(PlannedConnector):
    name, display_name = "azure_devops", "Azure DevOps Pipelines"


class JenkinsConnector(PlannedConnector):
    name, display_name = "jenkins", "Jenkins"


def registry() -> dict[str, Connector]:
    from .github import GitHubConnector
    from .upload import UploadConnector

    items = [GitHubConnector(), UploadConnector(), GitLabConnector(), BitbucketConnector(), AzureDevOpsConnector(), JenkinsConnector()]
    return {c.name: c for c in items}
