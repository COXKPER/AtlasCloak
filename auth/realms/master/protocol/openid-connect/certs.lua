-- JWKS (JSON Web Key Set) endpoint for OpenID Connect
response:json({
    keys = {
        {
            kid = "atlascloak-master-key-1",
            kty = "RSA",
            alg = "RS256",
            use = "sig",
            n = "u1M0_EXAMPLE_KEY_N_STRING_ATLASCLOAK_TELAMON_KEYCLOAK_SIMULATION",
            e = "AQAB"
        }
    }
})
