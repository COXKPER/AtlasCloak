local utils = dofile("public/lib/utils.lua")

if request.method ~= "POST" then
    response:setStatus(405)
    response:json({ error = "method_not_allowed" })
    return
end

local form = utils.parse_form(request.body)
local token = form.token or request:getParam("token")

if not token or token == "" then
    response:json({ active = false })
    return
end

local db = utils.get_db()
local ok, payload, err = utils.validate_token(db, token)

if not ok then
    db:close()
    response:json({ active = false })
    return
end

local username = payload.username or payload.sub or payload.preferred_username
local roles = payload.roles or (username and utils.get_user_roles(db, username)) or { "user" }
local client_id = payload.client_id or payload.aud or "account"
local exp = payload.exp or (os.time() + 3600)
local scope = payload.scope or "openid profile email"

db:close()

response:json({
    active = true,
    scope = scope,
    client_id = client_id,
    username = username,
    sub = username,
    exp = exp,
    iat = payload.iat or (exp - 3600),
    iss = utils.get_base_url() .. "/auth/realms/master",
    token_type = "Bearer",
    roles = roles,
    realm_access = {
        roles = roles
    }
})
