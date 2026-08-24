local utils = dofile("public/lib/utils.lua")
local RB = "/auth/realms/" .. utils.get_realm()

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
    local events_str = db:get(utils.rk("meta:events"))
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put(utils.rk("meta:events"), json.encode(events))
    
    db:close()
    local redirect_to = "" .. RB .. "/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=" .. utils.url_encode(err_msg or "Security validation failed")
    response:redirect(redirect_to, 302)
    return
end

-- 2. Brute Force Protection: Check if Account is Locked
local locked, remaining = utils.check_account_locked(db, username or "")
if locked then
    local mins = math.ceil(remaining / 60)
    db:close()
    local redirect_to = "" .. RB .. "/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=" .. utils.url_encode("Account temporarily locked due to multiple failed login attempts. Try again in " .. mins .. " minute(s).")
    response:redirect(redirect_to, 302)
    return
end

local user_data_str = db:get(utils.rk("user:") .. (username or ""))

if not user_data_str then
    db:close()
    local redirect_to = "" .. RB .. "/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=Invalid+username+or+password"
    response:redirect(redirect_to, 302)
    return
end

local user_data = json.decode(user_data_str)

-- 3. Check if user account is enabled
if user_data.enabled == false then
    db:close()
    local redirect_to = "" .. RB .. "/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=Account+is+disabled"
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
    local events_str = db:get(utils.rk("meta:events"))
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    if #events > 100 then
        local new = {}
        for i = #events - 99, #events do table.insert(new, events[i]) end
        events = new
    end
    db:put(utils.rk("meta:events"), json.encode(events))

    local err_text = "Invalid username or password"
    if just_locked then
        err_text = "Account has been locked due to too many failed attempts."
    end

    db:close()
    local redirect_to = "" .. RB .. "/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=" .. utils.url_encode(err_text)
    response:redirect(redirect_to, 302)
    return
end

-- Transparently upgrade legacy password hash to secure PBKDF2 format
if needs_rehash then
    user_data.password = utils.hash_password(password)
    db:put(utils.rk("user:") .. username, json.encode(user_data))
end

-- Reset brute force failure counter on successful login
utils.reset_login_failures(db, username)

local must_change = (user_data.must_change_password == true)
local ctx = utils.capture_oidc_context()

-- 5. MFA gate: challenge TOTP holders; force enrollment when the realm
--    policy requires MFA for every login.
local totp_cfg = utils.get_user_totp(db, username)
local policies = utils.get_policies(db)

if totp_cfg or policies.mfa_required_all then
    local must_enroll = (totp_cfg == nil)
    local mfa_token = utils.create_pending_mfa(db, username, ctx)
    db:close()
    local target = RB .. "/login-actions/totp?mfa=" .. mfa_token .. (must_enroll and "&enroll=1" or "")
    if must_change then target = target .. "&must_change=1" end
    utils.redirect(target)
    return
end

-- 6. Login successful (single factor): Create session
local session_id = utils.create_session(db, username)
db:close()

if must_change and (not redirect_uri or redirect_uri == "" or redirect_uri == "/account" or redirect_uri == "/admin") then
    utils.redirect("/account/password?forced=true", "ATLAS_SESSION=" .. session_id .. "; Path=/; HttpOnly; SameSite=Lax")
    return
end

utils.redirect(utils.build_auth_resume_url(ctx), "ATLAS_SESSION=" .. session_id .. "; Path=/; HttpOnly; SameSite=Lax")
