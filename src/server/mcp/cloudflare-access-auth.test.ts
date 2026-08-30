import { beforeEach, describe, expect, it, vi } from "vitest";
import { MCP_OAUTH_SCOPES } from "@/lib/oauth-resource";
import { MCP_AUTH_CONTEXT_PROP } from "@/server/mcp/context";
import type { handleAuthenticatedOpenSeoMcpRequest } from "@/server/mcp/transport";

const mocks = vi.hoisted(() => ({
  resolveCloudflareAccessContext: vi.fn(),
  recordMcpAuthorized: vi.fn(),
  handleAuthenticatedOpenSeoMcpRequest:
    vi.fn<typeof handleAuthenticatedOpenSeoMcpRequest>(),
}));

vi.mock("@/lib/auth", () => ({
  getHostedBaseUrl: () => "https://seo.starflowlabs.com",
}));

vi.mock("@/middleware/ensure-user/cloudflareAccess", () => ({
  resolveCloudflareAccessContext: mocks.resolveCloudflareAccessContext,
}));

vi.mock("@/server/features/activation/mcpActivation", () => ({
  recordMcpAuthorized: mocks.recordMcpAuthorized,
}));

vi.mock("@/server/mcp/transport", () => ({
  handleAuthenticatedOpenSeoMcpRequest:
    mocks.handleAuthenticatedOpenSeoMcpRequest,
}));

import { handleMcpCloudflareAccessRequest } from "@/server/mcp/cloudflare-access-auth";

const env = {};
const ctx: ExecutionContext = {
  waitUntil() {},
  passThroughOnException() {},
  props: {},
};

function request(path = "/mcp", headers?: HeadersInit, method = "POST") {
  return new Request(`https://seo.starflowlabs.com${path}`, {
    method,
    headers,
  });
}

describe("handleMcpCloudflareAccessRequest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.resolveCloudflareAccessContext.mockResolvedValue({
      userId: "access-user-1",
      userEmail: "person@example.com",
      organizationId: "shared-org-1",
      emailVerified: true,
    });
    mocks.recordMcpAuthorized.mockResolvedValue(undefined);
    mocks.handleAuthenticatedOpenSeoMcpRequest.mockResolvedValue(
      new Response("mcp response"),
    );
  });

  it("turns a verified Managed OAuth Access assertion into MCP auth props", async () => {
    const mcpRequest = request("/mcp", {
      "Cf-Access-Jwt-Assertion": "signed-access-assertion",
      Authorization: "Bearer opaque-cloudflare-oauth-token",
    });

    const response = await handleMcpCloudflareAccessRequest(
      mcpRequest,
      env,
      ctx,
    );

    expect(await response?.text()).toBe("mcp response");
    expect(mocks.resolveCloudflareAccessContext).toHaveBeenCalledWith(
      mcpRequest.headers,
    );
    expect(mocks.recordMcpAuthorized).toHaveBeenCalledWith("shared-org-1");
    const [passedRequest, props, passedEnv, passedCtx] =
      mocks.handleAuthenticatedOpenSeoMcpRequest.mock.calls[0];
    expect(passedRequest).toBe(mcpRequest);
    expect(passedEnv).toBe(env);
    expect(passedCtx).toBe(ctx);
    expect(props).toMatchObject({
      [MCP_AUTH_CONTEXT_PROP]: {
        userId: "access-user-1",
        userEmail: "person@example.com",
        organizationId: "shared-org-1",
        baseUrl: "https://seo.starflowlabs.com",
        clientId: "cloudflare-managed-oauth",
        scopes: [...MCP_OAUTH_SCOPES],
      },
    });
  });

  it("leaves requests without an Access assertion for the built-in OAuth provider", async () => {
    await expect(
      handleMcpCloudflareAccessRequest(
        request("/mcp", { Authorization: "Bearer internal-oauth-token" }),
        env,
        ctx,
      ),
    ).resolves.toBeNull();
    expect(mocks.resolveCloudflareAccessContext).not.toHaveBeenCalled();
  });

  it("does not consume assertions outside the MCP endpoint", async () => {
    await expect(
      handleMcpCloudflareAccessRequest(
        request("/api/health", {
          "Cf-Access-Jwt-Assertion": "signed-access-assertion",
        }),
        env,
        ctx,
      ),
    ).resolves.toBeNull();
  });

  it("leaves OPTIONS requests for the MCP CORS handler", async () => {
    await expect(
      handleMcpCloudflareAccessRequest(
        request(
          "/mcp",
          { "Cf-Access-Jwt-Assertion": "signed-access-assertion" },
          "OPTIONS",
        ),
        env,
        ctx,
      ),
    ).resolves.toBeNull();
  });
});
