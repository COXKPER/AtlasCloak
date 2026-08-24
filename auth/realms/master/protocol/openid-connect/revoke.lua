local utils = dofile("public/lib/utils.lua")

if request.method ~= "POST" then
    response:setStatus(405)
    response:json({ error = "method_not_allowed" })
    return
end

local form = utils.parse_form(request.body)
local token = form.token or request:getParam("token")

if token and token ~= "" then
    local db = utils.get_db()
    utils.revoke_token(db, token)
    
    local event = {
        type = "TOKEN_REVOKE",
        username = "client",
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Revoked token: " .. string.sub(token, 1, 12) .. "..."
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    db:close()
end

response:setStatus(200)
response:json({ status = "revoked" })
