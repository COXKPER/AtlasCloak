local utils = dofile("public/lib/utils.lua")

local base_url = utils.get_base_url() .. "/auth/realms/master"

response:json({
    issuer = base_url,
    authorization_endpoint = base_url .. "/protocol/openid-connect/auth",
    token_endpoint = base_url .. "/protocol/openid-connect/token",
    userinfo_endpoint = base_url .. "/protocol/openid-connect/userinfo",
    jwks_uri = base_url .. "/protocol/openid-connect/certs",
    introspection_endpoint = base_url .. "/protocol/openid-connect/token/introspect",
    revocation_endpoint = base_url .. "/protocol/openid-connect/revoke",
    end_session_endpoint = base_url .. "/protocol/openid-connect/logout",
    code_challenge_methods_supported = {
        "plain",
        "S256"
    },
    grant_types_supported = {
        "authorization_code",
        "client_credentials",
        "password",
        "refresh_token"
    },
    response_types_supported = {
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
    },
    subject_types_supported = {
        "public",
        "pairwise"
    },
    id_token_signing_alg_values_supported = {
        "HS256",
        "RS256"
    },
    scopes_supported = {
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access"
    },
    token_endpoint_auth_methods_supported = {
        "client_secret_basic",
        "client_secret_post"
    },
    claims_supported = {
        "aud",
        "sub",
        "iss",
        "auth_time",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "email",
        "roles",
        "realm_access"
    }
})
