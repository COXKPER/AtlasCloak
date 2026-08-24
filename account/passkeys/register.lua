local utils = dofile("public/lib/utils.lua")
utils.apply_security_headers()

local db = utils.get_db()
utils.ensure_admin_exists(db)

local username, _ = utils.get_session_user(db)
if not username then
    db:close()
    response:setStatus(401)
    response:json({ error = "not_authenticated" })
    return
end

if not utils.get_policies(db).passkeys_enabled then
    db:close()
    response:setStatus(404)
    response:json({ error = "passkeys_disabled" })
    return
end

if request.method ~= "POST" then
    db:close()
    response:setStatus(405)
    response:json({ error = "method_not_allowed" })
    return
end

local function load_user(db)
    local us = db:get(utils.rk("user:") .. username)
    return us and json.decode(us) or {}
end

-- ── Parse payload ─────────────────────────────────────────────────────────────
local ok_json, att = pcall(json.decode, request.body or "")
if not ok_json or type(att) ~= "table" or type(att.response) ~= "table" then
    db:close()
    response:setStatus(400)
    response:json({ error = "malformed_payload" })
    return
end

-- ── clientDataJSON ────────────────────────────────────────────────────────────
local cd_ok, cd = pcall(json.decode, utils.base64url_decode(att.response.clientDataJSON or ""))
if not cd_ok or type(cd) ~= "table" then
    db:close()
    response:setStatus(400)
    response:json({ error = "bad_client_data" })
    return
end

local challenge_rec = utils.wa_consume_challenge(db, tostring(cd.challenge))
if not challenge_rec then
    db:close()
    response:setStatus(400)
    response:json({ error = "challenge_unknown" })
    return
end
if challenge_rec.username ~= username then
    db:close()
    response:setStatus(403)
    response:json({ error = "challenge_user_mismatch" })
    return
end
if cd.type ~= "webauthn.create" then
    db:close()
    response:setStatus(400)
    response:json({ error = "type_mismatch", got = tostring(cd.type) })
    return
end

-- ── Attestation object → authData → COSE key ─────────────────────────────────
local cbor = dofile("public/lib/cbor.lua")
local att_obj_bin = utils.base64url_decode(att.response.attestationObject or "")
local att_obj = att_obj_bin and cbor.decode(att_obj_bin) or nil
if type(att_obj) ~= "table" or type(att_obj.authData) ~= "string" then
    db:close()
    response:setStatus(400)
    response:json({ error = "bad_attestation_object" })
    return
end

local parsed, perr = utils.parse_authenticator_data(att_obj.authData)
if not parsed then
    db:close()
    response:setStatus(400)
    response:json({ error = "bad_authenticator_data", detail = perr })
    return
end

local rp_host = (utils.get_base_url():match("^https?://([^/]+)")) or (request.host or "localhost")
local rp_id = rp_host:match("^[^:]+") or rp_host   -- WebAuthn rpId excludes the port

if parsed.rp_id_hash ~= crypto.sha256_raw(rp_id) then
    db:close()
    response:setStatus(400)
    response:json({ error = "rpId_mismatch" })
    return
end
if not parsed.up then
    db:close()
    response:setStatus(400)
    response:json({ error = "user_presence_missing" })
    return
end
if not parsed.at or not parsed.cose_key then
    db:close()
    response:setStatus(400)
    response:json({ error = "no_attested_credential" })
    return
end

local x_b64u, y_b64u = utils.cose_key_to_xy(parsed.cose_key)
if not x_b64u then
    db:close()
    response:setStatus(400)
    response:json({ error = "unsupported_cose_key" })
    return
end

-- ── Store credential ──────────────────────────────────────────────────────────
local ud = load_user(db)
ud.passkeys = ud.passkeys or {}
for _, pk in ipairs(ud.passkeys) do
    if pk.cred_id == parsed.cred_id_b64u then
        db:close()
        response:setStatus(409)
        response:json({ error = "already_registered" })
        return
    end
end

table.insert(ud.passkeys, {
    cred_id = parsed.cred_id_b64u,
    x = x_b64u,
    y = y_b64u,
    aaguid = parsed.aaguid_hex,
    sign_count = parsed.sign_count or 0,
    added = os.time(),
    label = os.date("%Y-%m-%d %H:%M")
})

db:put(utils.rk("wa_cred:" .. parsed.cred_id_b64u), json.encode({
    username = username,
    x = x_b64u,
    y = y_b64u,
    sign_count = parsed.sign_count or 0
}))
db:put(utils.rk("user:") .. username, json.encode(ud))

local event = {
    type = "PASSKEY_ADDED",
    username = username,
    ip = utils.get_client_ip(),
    time = os.time(),
    detail = "Passkey registered"
}
local events_str = db:get(utils.rk("meta:events"))
local events = events_str and json.decode(events_str) or {}
table.insert(events, event)
if #events > 100 then
    local trimmed = {}
    for i = #events - 99, #events do table.insert(trimmed, events[i]) end
    events = trimmed
end
db:put(utils.rk("meta:events"), json.encode(events))

db:close()
response:json({ ok = true })