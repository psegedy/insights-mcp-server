from typing import Any
from insights_mcp_server.tools import InsightsTools
from insights_mcp_server.mcp import MCP, InsightsMCP


class VmaasTools(InsightsTools):
    def __init__(self, mcp: InsightsMCP):
        super().__init__(mcp)

    @MCP.tool()
    async def get_vmaas_openapi(self) -> dict[str, Any]:
        """Get Red Hat Insights VMAAS OpenAPI specification in JSON format."""
        return await MCP.insights_client.get("vmaas/v3/openapi.json")

    @MCP.tool()
    async def get_cve_details(self, cve: str) -> dict[str, Any]:
        """Get details about a specific CVE."""
        return await MCP.insights_client.get(f"vmaas/v3/cves/{cve}")

    @MCP.tool()
    async def get_cves_details(
        self, cves: list[str],
        page: int, page_size: int, errata_associated: bool, published_since: str, modified_since: str,
    ) -> dict[str, Any]:
        """Get details about a list of CVEs.
        
        Args:
            cves: List of CVEs to get details for. CVE string can be also regex.
            page: Page number to get.
            page_size: Number of CVEs to get per page.
            errata_associated: Return only those CVEs which are associated with at least one errata. Defaults to false.
            published_since: Filter CVEs published since a specific date. Example: 2025-04-05T01:23:45+02:00
            modified_since: Filter CVEs modified since a specific date. Example: 2025-04-05T01:23:45+02:00
        """
        return await MCP.insights_client.post(f"vmaas/v3/cves", json={
            "cve_list": cves,
            "page": page,
            "page_size": page_size,
            "errata_associated": errata_associated,
            "published_since": published_since,
            "modified_since": modified_since,
        })
    
    @MCP.tool()
    async def get_erratum_details(self, erratum: str) -> dict[str, Any]:
        """Get details about a specific erratum."""
        return await MCP.insights_client.get(f"vmaas/v3/errata/{erratum}")
    
    @MCP.tool()
    async def get_errata_details(
        self, errata: list[str],
        page: int, page_size: int, published_since: str, modified_since: str, type: str, severity: str,
    ) -> dict[str, Any]:
        """Get details about a list of errata.
        
        Args:
            errata: List of errata to get details for. Erratum string can be also regex.
            page: Page number to get.
            page_size: Number of errata to get per page.
            published_since: Filter errata published since a specific date. Example: 2025-04-05T01:23:45+02:00
            modified_since: Filter errata modified since a specific date. Example: 2025-04-05T01:23:45+02:00
            type: Filter errata by type. Example: security, bugfix, enhancement.
            severity: Filter errata by severity. Example: low, moderate, important, critical.
        """
        return await MCP.insights_client.post(f"vmaas/v3/errata", json={
            "errata_list": errata,
            "page": page,
            "page_size": page_size,
            "published_since": published_since,
            "modified_since": modified_since,
            "type": type,
            "severity": severity,
        })
    
    @MCP.tool()
    async def get_repository_details(self, repository: str) -> dict[str, Any]:
        """Get details about a specific repository."""
        return await MCP.insights_client.get(f"vmaas/v3/repos/{repository}")
    
    @MCP.tool()
    async def get_repositories_details(self, repositories: list[str], show_packages: bool, has_packages: bool, page: int, page_size: int) -> dict[str, Any]:
        """Get details about a list of repositories.
        
        Args:
            repositories: List of repositories to get details for. Repository string can be also regex. Example: ["rhel-8-for-x86_64-appstream-rpms","rhel-8-for-x86_64-baseos-rpms"]
            show_packages: Show updated package names in a repo since the last modified_since. Defaults to false.
            has_packages: Return only repositories having advisories with packages released since the last modified_since. Defaults to false.
        """
        return await MCP.insights_client.post(f"vmaas/v3/repos", json={
            "repository_list": repositories,
            "show_packages": show_packages,
            "has_packages": has_packages,
            "page": page,
            "page_size": page_size,
        })
    
    @MCP.tool()
    async def get_package_details(self, package: str) -> dict[str, Any]:
        """Get details about a specific package."""
        return await MCP.insights_client.get(f"vmaas/v3/packages/{package}")
    
    @MCP.tool()
    async def get_packages_details(self, packages: list[str], page: int, page_size: int) -> dict[str, Any]:
        """Get details about a list of packages.
        
        Args:
            packages: List of packages to get details for. Package string can be also regex. Example: ["kernel-2.6.32-696.20.1.el6.x86_64", "kernel-2.6.32-696.20.1.el6.x86_64"]
            page: Page number to get.
            page_size: Number of packages to get per page.
        """
        return await MCP.insights_client.get(f"vmaas/v3/packages", params={"package_list": packages, "page": page, "page_size": page_size})
    
    @MCP.tool()
    async def get_package_updates(self, packages: list[str], repositories: list[str], releasever: str, basearch: str, modules: list[dict[str, Any]]) -> dict[str, Any]:
        """Get updates for a list of packages.
        
        Args:
            packages: List of packages to get updates for. Package string can be also regex. Example: ["kernel-2.6.32-696.20.1.el6.x86_64", "bash-0:4.4.20-5.el8.x86_64"]
            repositories: List of repositories to get updates for. Repository string can be also regex. Example: ["rhel-8-for-x86_64-appstream-rpms","rhel-8-for-x86_64-baseos-rpms"]
            releasever: Filter updates by release version. Example: 8.1
            basearch: Filter updates by base architecture. Example: x86_64
            modules: Filter updates by modules. Example: [{"module_name": "container-tools", "module_stream": "rhel8"}]
        """
        return await MCP.insights_client.post(f"vmaas/v3/updates", json={
            "package_list": packages,
            "repository_list": repositories,
            "releasever": releasever,
            "basearch": basearch,
            "modules_list": modules,
        })
    
    @MCP.tool()
    async def get_package_vulnerabilities(self, packages: list[str], repositories: list[str], releasever: str, basearch: str, modules: list[dict[str, Any]], extended: bool) -> dict[str, Any]:
        """Get vulnerabilities for a list of packages.
        
        Args:
            packages: List of packages to get vulnerabilities for. Package string can be also regex. Example: ["kernel-2.6.32-696.20.1.el6.x86_64", "bash-0:4.4.20-5.el8.x86_64"]
            repositories: List of repositories to get vulnerabilities for. Repository string can be also regex. Example: ["rhel-8-for-x86_64-appstream-rpms","rhel-8-for-x86_64-baseos-rpms"]
            releasever: Filter vulnerabilities by release version. Example: 8.1
            basearch: Filter vulnerabilities by base architecture. Example: x86_64
            modules: Filter vulnerabilities by modules. Example: [{"module_name": "container-tools", "module_stream": "rhel8"}]
            extended: Return extended information about vulnerabilities. Defaults to false.
        """
        return await MCP.insights_client.post(f"vmaas/v3/vulnerabilities", json={
            "package_list": packages,
            "repository_list": repositories,
            "releasever": releasever,
            "basearch": basearch,
            "modules_list": modules,
            "extended": extended,
        })
