local utils = dofile("public/lib/utils.lua")

local auth_header = request.headers["authorization"]
if not auth_header or not string.match(auth_header, "^[Bb]earer%s+(.+)$") then
    response:setStatus(401)
    response:setHeader("WWW-Authenticate", 'Bearer realm="master"')
    response:json({ error = "unauthorized", error_description = "Bearer token missing" })
    return
end

local access_token = string.match(auth_header, "^[Bb]earer%s+(.+)$")

local db = utils.get_db()
local ok, token_data, err_msg = utils.validate_token(db, access_token)

if not ok then
    db:close()
    response:setStatus(401)
    response:setHeader("WWW-Authenticate", 'Bearer realm="master" error="invalid_token"')
    response:json({ error = "invalid_token", error_description = err_msg or "Invalid token" })
    return
end

local username = token_data.username or token_data.sub
local user_data_str = db:get("user:" .. (username or ""))
local roles = token_data.roles or utils.get_user_roles(db, username)
db:close()

if not user_data_str then
    if token_data.is_client then
        -- M2M client
        response:json({
            sub = username,
            client_id = username,
            roles = roles
        })
        return
    end
    
    response:setStatus(404)
    response:json({ error = "user_not_found" })
    return
end

local user_data = json.decode(user_data_str)

response:json({
    sub = user_data.username,
    preferred_username = user_data.username,
    email = user_data.email or "",
    given_name = user_data.firstName or "",
    family_name = user_data.lastName or "",
    name = (user_data.firstName or "") .. " " .. (user_data.lastName or ""),
    roles = roles,
    realm_access = {
        roles = roles
    }
})
