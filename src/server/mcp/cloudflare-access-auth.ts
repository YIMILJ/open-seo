import { getHostedBaseUrl } from "@/lib/auth";
import { MCP_OAUTH_SCOPES } from "@/lib/oauth-resource";
import { resolveCloudflareAccessContext } from "@/middleware/ensure-user/cloudflareAccess";
import { recordMcpAuthorized } from "@/server/features/activation/mcpActivation";
import { createWorkersOAuthMcpProps, MCP_ROUTE } from "@/server/mcp/context";
import { handleAuthenticatedOpenSeoMcpRequest } from "@/server/mcp/transport";

/**
 * Adapts Cloudflare Access Managed OAuth to OpenSEO's MCP transport.
 *
 * Access validates the client's opaque OAuth token at the edge and forwards a
 * signed Cf-Access-Jwt-Assertion. We verify that assertion again against the
 * configured team issuer and application AUD before constructing tool props.
 * Requests without the assertion continue to OpenSEO's built-in OAuth provider.
 */
export async function handleMcpCloudflareAccessRequest(
  request: Request,
  env: unknown,
  ctx: ExecutionContext,
): Promise<Response | null> {
  const url = new URL(request.url);
  if (
    url.pathname !== MCP_ROUTE ||
    request.method === "OPTIONS" ||
    !request.headers.has("cf-access-jwt-assertion")
  ) {
    return null;
  }

  const context = await resolveCloudflareAccessContext(request.headers);
  const props = createWorkersOAuthMcpProps({
    userId: context.userId,
    userEmail: context.userEmail,
    organizationId: context.organizationId,
    baseUrl: getHostedBaseUrl(),
    clientId: "cloudflare-managed-oauth",
    scopes: [...MCP_OAUTH_SCOPES],
  });

  await recordMcpAuthorized(context.organizationId);
  return handleAuthenticatedOpenSeoMcpRequest(request, props, env, ctx);
}
