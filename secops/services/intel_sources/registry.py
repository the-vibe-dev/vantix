from __future__ import annotations

from secops.services.intel_sources.base import SourceAdapter
from secops.services.intel_sources.cisa_kev import CisaKevAdapter
from secops.services.intel_sources.epss import EpssAdapter
from secops.services.intel_sources.exploitdb import ExploitDbAdapter
from secops.services.intel_sources.github_advisories import GithubAdvisoriesAdapter
from secops.services.intel_sources.gitlab_advisories import GitlabAdvisoriesAdapter
from secops.services.intel_sources.nuclei_templates import NucleiTemplatesAdapter
from secops.services.intel_sources.osv import OsvAdapter
from secops.services.intel_sources.rss import OpenwallOssSecurityAdapter, SeclistsFullDisclosureAdapter
from secops.services.intel_sources.vulncheck import VulnCheckAdapter

ADAPTERS: dict[str, type[SourceAdapter]] = {
    "cisa_kev": CisaKevAdapter,
    "first_epss": EpssAdapter,
    "github_advisories": GithubAdvisoriesAdapter,
    "gitlab_advisories": GitlabAdvisoriesAdapter,
    "exploitdb": ExploitDbAdapter,
    "nuclei_templates": NucleiTemplatesAdapter,
    "osv": OsvAdapter,
    "openwall_oss_security": OpenwallOssSecurityAdapter,
    "seclists_fulldisclosure": SeclistsFullDisclosureAdapter,
    "vulncheck": VulnCheckAdapter,
}

DEFAULT_SOURCES = [
    "cisa_kev",
    "github_advisories",
    "exploitdb",
    "nuclei_templates",
    "openwall_oss_security",
    "seclists_fulldisclosure",
]


def available_sources(include_optional: bool = False) -> list[str]:
    if include_optional:
        return sorted(ADAPTERS)
    return list(DEFAULT_SOURCES)


def adapter_for(name: str) -> SourceAdapter:
    try:
        return ADAPTERS[name]()
    except KeyError as exc:
        raise ValueError(f"Unknown vulnerability intel source: {name}") from exc
