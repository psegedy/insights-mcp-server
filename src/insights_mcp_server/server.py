import click

from insights_mcp_server.mcp import MCP
from insights_mcp_server.tools.vulnerability import VulnerabilityTools
from insights_mcp_server.tools.vmaas import VmaasTools

TOKEN_ENDPOINT = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
HCC_API_BASE = "https://console.redhat.com/api"
USER_AGENT = "insights-mcp/1.0"


@click.command()
@click.option(
    "--refresh-token",
    envvar="HCC_REFRESH_TOKEN",
    required=True,
    help="Oauth2 refresh token to get an access token for console.redhat.com",
)
def main(refresh_token: str) -> None:
    # mcp = InsightsMCP()
    MCP.register_tools([VulnerabilityTools, VmaasTools])
    MCP.init_insights_client(refresh_token)
    MCP.run(transport="stdio")
