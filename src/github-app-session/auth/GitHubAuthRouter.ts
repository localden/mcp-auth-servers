import express, { RequestHandler } from "express";
import { clientRegistrationHandler, ClientRegistrationHandlerOptions } from "@modelcontextprotocol/sdk/server/auth/handlers/register.js";
import { tokenHandler, TokenHandlerOptions } from "@modelcontextprotocol/sdk/server/auth/handlers/token.js";
import { authorizationHandler, AuthorizationHandlerOptions } from "@modelcontextprotocol/sdk/server/auth/handlers/authorize.js";
import { revocationHandler, RevocationHandlerOptions } from "@modelcontextprotocol/sdk/server/auth/handlers/revoke.js";
import { metadataHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/metadata.js";
import { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";

export type AuthRouterOptions = {
    provider: OAuthServerProvider;
    issuerUrl: URL;
    serviceDocumentationUrl?: URL;
    authorizationOptions?: Omit<AuthorizationHandlerOptions, "provider">;
    clientRegistrationOptions?: Omit<ClientRegistrationHandlerOptions, "clientsStore">;
    revocationOptions?: Omit<RevocationHandlerOptions, "provider">;
    tokenOptions?: Omit<TokenHandlerOptions, "provider">;
};

export function githubAuthRouter(options: AuthRouterOptions): RequestHandler {
    const issuer = options.issuerUrl;

    if (issuer.protocol !== "https:" && issuer.hostname !== "localhost" && issuer.hostname !== "127.0.0.1") {
        throw new Error("Issuer URL must be HTTPS");
    }
    if (issuer.hash) {
        throw new Error("Issuer URL must not have a fragment");
    }
    if (issuer.search) {
        throw new Error("Issuer URL must not have a query string");
    }

    const authorization_endpoint = "/authorize";
    const token_endpoint = "/token";
    const registration_endpoint = options.provider.clientsStore.registerClient ? "/register" : undefined;
    const revocation_endpoint = options.provider.revokeToken ? "/revoke" : undefined;

    const baseUrl = issuer.href.endsWith('/') ? issuer.href : `${issuer.href}/`;

    const metadata = {
        issuer: issuer.href,
        service_documentation: options.serviceDocumentationUrl?.href,

        authorization_endpoint: `${baseUrl}authorize`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],

        token_endpoint: `${baseUrl}token`,
        token_endpoint_auth_methods_supported: ["none"],
        grant_types_supported: ["authorization_code", "refresh_token"],

        revocation_endpoint: revocation_endpoint ? `${baseUrl}revoke` : undefined,
        revocation_endpoint_auth_methods_supported: revocation_endpoint ? ["client_secret_post"] : undefined,

        registration_endpoint: registration_endpoint ? `${baseUrl}register` : undefined,
    };

    const router = express.Router();

    router.use(
        authorization_endpoint,
        authorizationHandler({ provider: options.provider, ...options.authorizationOptions })
    );

    router.use(
        token_endpoint,
        tokenHandler({ provider: options.provider, ...options.tokenOptions })
    );

    router.use("/.well-known/oauth-authorization-server", metadataHandler(metadata));

    if (registration_endpoint) {
        router.use(
            registration_endpoint,
            clientRegistrationHandler({
                clientsStore: options.provider.clientsStore,
                ...options,
            })
        );
    }

    if (revocation_endpoint) {
        router.use(
            revocation_endpoint,
            revocationHandler({ provider: options.provider, ...options.revocationOptions })
        );
    }

    return router;
}