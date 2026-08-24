local utils = dofile("public/lib/utils.lua")
utils.apply_security_headers()

-- RFC 8628 §3.1 — Device Authorization Request
if request.method ~= "POST" then
    response:setStatus(405)
    response:json({ error = "method_not_allowed" })
    return
end

local db = utils.get_db()

if not utils.get_policies(db).device_flow_enabled then
    db:close()
    response:setStatus(400)
    response:json({ error = "unauthorized_client", error_description = "Device flow is disabled for this realm" })
    return
end

local form = utils.parse_form(request.body)
local client_id = form.client_id
local client_secret = form.client_secret

local auth_hdr = request.headers["authorization"]
if auth_hdr and string.match(auth_hdr, "^[Bb]asic%s+(.+)$") then
    local raw_creds = utils.base64_decode(string.match(auth_hdr, "^[Bb]asic%s+(.+)$"))
    local cid, csec = string.match(raw_creds, "([^:]+):?(.*)")
    if cid then client_id, client_secret = cid, csec end
end

if not client_id or client_id == "" then
    db:close()
    response:setStatus(400)
    response:json({ error = "invalid_client", error_description = "client_id is required" })
    return
end

local cdata_str = db:get(utils.rk("client:") .. client_id)
if not cdata_str then
    db:close()
    response:setStatus(401)
    response:json({ error = "invalid_client", error_description = "Client not found" })
    return
end

local cdata = json.decode(cdata_str)
if cdata.client_type == "confidential" and cdata.secret ~= client_secret then
    db:close()
    response:setStatus(401)
    response:json({ error = "unauthorized_client", error_description = "Invalid client secret" })
    return
end

local device_code, user_code = utils.device_create_grant(db, client_id, form.scope)

local event = {
    type = "DEVICE_AUTHZ_REQUEST",
    username = "client:" .. client_id,
    ip = utils.get_client_ip(),
    time = os.time(),
    detail = "Device authorization requested (user_code issued)"
}
local events_str = db:get(utils.rk("meta:events"))
local events = events_str and json.decode(events_str) or {}
table.insert(events, event)
db:put(utils.rk("meta:events"), json.encode(events))
db:close()

local base = utils.get_base_url()
response:json({
    device_code = device_code,
    user_code = user_code,
    verification_uri = base .. "/device",
    verification_uri_complete = base .. "/device?user_code=" .. utils.url_encode(user_code),
    expires_in = 600,
    interval = 5
})