import httpx
from typing import Any
# from mcp.server.fastmcp import Context
from mcp.server.fastmcp import FastMCP
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oauth2.rfc6749 import OAuth2Token

from insights_mcp_server.tools import InsightsTools


TOKEN_ENDPOINT = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
HCC_API_BASE = "https://console.redhat.com/api"
USER_AGENT = "insights-mcp/1.0"


class InsightsClient(AsyncOAuth2Client):
    def __init__(self, refresh_token: str):
        token_dict = {"refresh_token": refresh_token}
        token = OAuth2Token(token_dict)
        headers = {"User-Agent": USER_AGENT}
        super().__init__("rhsm-api", token=token, token_endpoint=TOKEN_ENDPOINT, headers=headers)

    async def _api_call(self, fn, *args, **kwargs) -> dict[str, Any]:
        if "access_token" not in self.token or self.token.is_expired():
            await self.refresh_token()
        try:
            response = await fn(*args, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError:
            return {f"Unexpected HTTP status code": f"{response.status_code}, content: {response.content}"}
        except Exception as exc:
            return {f"Unhadled error": str(exc)}
    
    async def get(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{HCC_API_BASE}/{endpoint}"
        return await self._api_call(super().get, url, params=params)

    async def post(self, endpoint: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{HCC_API_BASE}/{endpoint}"
        return await self._api_call(super().post, url, json=json)


class InsightsMCP(FastMCP):
    def __init__(
        self, name: str | None = None, instructions: str | None = None, **settings: Any
    ):
        name = name or "Red Hat Insights"
        super().__init__(name, instructions, **settings)
    
    def init_insights_client(self, refresh_token: str):
        self.insights_client = InsightsClient(refresh_token)

    def register_tools(self, tools: list[type[InsightsTools]]):
        for tool in tools:
            tool(self)

# Initialize FastMCP server
MCP = InsightsMCP()
