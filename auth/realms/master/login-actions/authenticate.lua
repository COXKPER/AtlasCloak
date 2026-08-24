local utils = dofile("public/lib/utils.lua")

if request.method ~= "POST" then
    response:setStatus(405)
    response:write("Method Not Allowed")
    return
end

local client_id = request:getParam("client_id")
local redirect_uri = request:getParam("redirect_uri")
local state = request:getParam("state")

local form = utils.parse_form(request.body)
local username = form.username
local password = form.password

local db = utils.get_db()
utils.ensure_admin_exists(db)

-- 1. Validate Security Token & Anti-Bot Protection
local ok, err_msg = utils.validate_security_token(db, form, "login")
if not ok then
    local event = {
        type = "SECURITY_BLOCKED",
        username = username or "anonymous",
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Blocked login: " .. (err_msg or "Invalid security token")
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    db:close()
    local redirect_to = "/auth/realms/master/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=" .. utils.url_encode(err_msg or "Security validation failed")
    response:redirect(redirect_to, 302)
    return
end

-- 2. Brute Force Protection: Check if Account is Locked
local locked, remaining = utils.check_account_locked(db, username or "")
if locked then
    local mins = math.ceil(remaining / 60)
    db:close()
    local redirect_to = "/auth/realms/master/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=" .. utils.url_encode("Account temporarily locked due to multiple failed login attempts. Try again in " .. mins .. " minute(s).")
    response:redirect(redirect_to, 302)
    return
end

local user_data_str = db:get("user:" .. (username or ""))

if not user_data_str then
    db:close()
    local redirect_to = "/auth/realms/master/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=Invalid+username+or+password"
    response:redirect(redirect_to, 302)
    return
end

local user_data = json.decode(user_data_str)

-- 3. Check if user account is enabled
if user_data.enabled == false then
    db:close()
    local redirect_to = "/auth/realms/master/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=Account+is+disabled"
    response:redirect(redirect_to, 302)
    return
end

-- 4. Verify password
local pw_ok, needs_rehash = utils.verify_password(password, user_data.password)
if not pw_ok then
    local just_locked, fail_count, max_f = utils.record_login_failure(db, username, utils.get_client_ip())
    
    local event_type = just_locked and "ACCOUNT_LOCKED" or "LOGIN_ERROR"
    local event_detail = just_locked and ("Account locked after " .. fail_count .. " failed attempts") or ("Invalid credentials (attempt " .. fail_count .. "/" .. max_f .. ")")
    
    local event = {
        type = event_type,
        username = username,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = event_detail
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    if #events > 100 then
        local new = {}
        for i = #events - 99, #events do table.insert(new, events[i]) end
        events = new
    end
    db:put("meta:events", json.encode(events))

    local err_text = "Invalid username or password"
    if just_locked then
        err_text = "Account has been locked due to too many failed attempts."
    end

    db:close()
    local redirect_to = "/auth/realms/master/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=" .. utils.url_encode(err_text)
    response:redirect(redirect_to, 302)
    return
end

-- Transparently upgrade legacy password hash to secure PBKDF2 format
if needs_rehash then
    user_data.password = utils.hash_password(password)
    db:put("user:" .. username, json.encode(user_data))
end

-- Reset brute force failure counter on successful login
utils.reset_login_failures(db, username)

-- 5. Login successful: Create session
local session_id = utils.uuid()
local session_data = {
    username = username,
    ip = utils.get_client_ip(),
    started = os.time(),
    last_access = os.time()
}
db:put("session:" .. session_id, username)
db:put("session_data:" .. session_id, json.encode(session_data))

local sessions_str = db:get("meta:session_list")
local sessions = sessions_str and json.decode(sessions_str) or {}
table.insert(sessions, session_id)
db:put("meta:session_list", json.encode(sessions))

local event = {
    type = "LOGIN",
    username = username,
    ip = utils.get_client_ip(),
    time = os.time(),
    detail = "Login successful"
}
local events_str = db:get("meta:events")
local events = events_str and json.decode(events_str) or {}
table.insert(events, event)
if #events > 100 then
    local new = {}
    for i = #events - 99, #events do table.insert(new, events[i]) end
    events = new
end
db:put("meta:events", json.encode(events))

-- Check if user must change password (e.g. initial admin)
local must_change = (user_data.must_change_password == true)

db:close()

if must_change and (not redirect_uri or redirect_uri == "" or redirect_uri == "/account" or redirect_uri == "/admin") then
    utils.redirect("/account/password?forced=true", "ATLAS_SESSION=" .. session_id .. "; Path=/; HttpOnly; SameSite=Lax")
    return
end

local code_challenge = request:getParam("code_challenge")
local code_challenge_method = request:getParam("code_challenge_method")
local response_type = request:getParam("response_type") or "code"
local response_mode = request:getParam("response_mode") or "query"
local nonce = request:getParam("nonce")
local scope = request:getParam("scope") or "openid"

local redirect_to = "/auth/realms/master/protocol/openid-connect/auth?client_id=" .. utils.url_encode(client_id or "") .. 
                    "&redirect_uri=" .. utils.url_encode(redirect_uri or "") .. 
                    "&state=" .. utils.url_encode(state or "") .. 
                    "&response_type=" .. utils.url_encode(response_type) .. 
                    "&response_mode=" .. utils.url_encode(response_mode) .. 
                    "&nonce=" .. utils.url_encode(nonce or "") .. 
                    "&scope=" .. utils.url_encode(scope)

if code_challenge and code_challenge ~= "" then
    redirect_to = redirect_to .. "&code_challenge=" .. utils.url_encode(code_challenge) .. "&code_challenge_method=" .. utils.url_encode(code_challenge_method or "S256")
end
utils.redirect(redirect_to, "ATLAS_SESSION=" .. session_id .. "; Path=/; HttpOnly; SameSite=Lax")
