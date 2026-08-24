local utils = dofile("public/lib/utils.lua")
utils.apply_security_headers()

if request.method ~= "POST" then
    response:setStatus(405)
    response:write("Method Not Allowed")
    return
end

local form = utils.parse_form(request.body)
local mfa_token = form.mfa or request:getParam("mfa") or ""

local db = utils.get_db()
local pending = utils.get_pending_mfa(db, mfa_token)

if not pending then
    db:close()
    response:redirect(utils.realm_url() .. "/protocol/openid-connect/auth?error=" .. utils.url_encode("Your verification session expired. Please sign in again."))
    return
end

local username = pending.username
local ctx = pending.context or {}
local code = form.code or ""

-- ── Enrollment mode (policy-forced first-time setup) ──────────────────────────
local secret = pending.enroll_secret
if not secret and utils.get_user_totp(db, username) then
    secret = nil -- user already enrolled; normal verify below
end
if not secret and not utils.get_user_totp(db, username) then
    secret = utils.totp_generate_secret()
    utils.update_pending_mfa(db, mfa_token, { enroll_secret = secret })
end

local verified = false
local attempts = tonumber(pending.attempts) or 0

if code ~= "" then
    attempts = attempts + 1
    local check_secret = secret or (utils.get_user_totp(db, username) or {}).secret
    if check_secret and utils.totp_verify(check_secret, code) then
        verified = true
        if secret then
            -- Persist enrollment on the realm-scoped user record.
            local u_str = db:get(utils.rk("user:") .. username)
            if u_str then
                local ud = json.decode(u_str)
                ud.totp = { enabled = true, secret = secret, enrolled = os.time() }
                db:put(utils.rk("user:") .. username, json.encode(ud))
            end
        end
        local consumed = utils.consume_pending_mfa(db, mfa_token)
        if not consumed then verified = false end
    else
        utils.update_pending_mfa(db, mfa_token, { attempts = attempts })
    end
end

if verified then
    local session_id = utils.create_session(db, username)

    local event = {
        type = "MFA_SUCCESS",
        username = username,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = secret and "TOTP enrollment completed" or "TOTP challenge passed"
    }
    local events_str = db:get(utils.rk("meta:events"))
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put(utils.rk("meta:events"), json.encode(events))
    db:close()

    local cookie = "ATLAS_SESSION=" .. session_id .. "; Path=/; HttpOnly; SameSite=Lax"
    if pending.must_change then
        utils.redirect("/account/password?forced=true", cookie)
        return
    end
    utils.redirect(utils.build_auth_resume_url(ctx), cookie)
    return
end

db:close()

-- ── Render the challenge / enrollment page ────────────────────────────────────
local alert_html = ""
if code ~= "" then
    alert_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Invalid verification code (' .. math.max(0, 5 - attempts) .. ' attempts left). Try again.</div>'
end

local body_html
if secret and not verified then
    -- Forced enrollment: show the manual-entry secret + otpauth URI.
    local account_label = utils.get_realm() .. ":" .. username
    local uri = utils.totp_otpauth_uri("AtlasCloak", account_label, secret)
    body_html = [[
        <div class="alert alert-info"><span class="alert-icon"><i class="fa-solid fa-shield-halved"></i></span>
            <strong>Two-factor authentication is required.</strong> Set up your authenticator app to continue.
        </div>
        <ol style="font-size:13px;color:var(--text);padding-left:18px;line-height:1.7;">
            <li>Open Google Authenticator / Aegis / FreeOTP</li>
            <li>Choose <strong>Enter a setup key</strong> (manual entry)</li>
            <li>Paste the secret below (type: Time-based)</li>
        </ol>
        <div style="background:rgba(0,0,0,0.25);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:16px;">
            <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Secret Key</div>
            <code style="font-size:16px;font-weight:700;letter-spacing:2px;color:var(--accent);word-break:break-all;">]] .. utils.html_escape(secret) .. [[</code>
        </div>
        <details style="margin-bottom:16px;font-size:12px;color:var(--text-muted);">
            <summary style="cursor:pointer;">otpauth:// URI</summary>
            <code style="word-break:break-all;font-size:11px;">]] .. utils.html_escape(uri) .. [[</code>
        </details>
        <form method="POST" action="]] .. utils.html_escape(request.path) .. [[" data-enroll-form>
            <input type="hidden" name="mfa" value="]] .. utils.html_escape(mfa_token) .. [[">
            <input type="hidden" name="enroll" value="1">
            <div class="form-group">
                <label>Enter the 6-digit code</label>
                <input type="text" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="123456" required autocomplete="one-time-code">
            </div>
            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-check"></i> Verify &amp; Enable 2FA</button>
        </form>
    ]]
else
    body_html = [[
        <p style="font-size:13px;color:var(--text-muted);margin-bottom:16px;">
            Enter the 6-digit code from your authenticator app for account
            <strong style="color:var(--text);">]] .. utils.html_escape(username) .. [[</strong>.
        </p>
        <form method="POST" action="]] .. utils.html_escape(request.path) .. [[">
            <input type="hidden" name="mfa" value="]] .. utils.html_escape(mfa_token) .. [[">
            <div class="form-group">
                <label>Verification Code</label>
                <input type="text" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="123456" required autocomplete="one-time-code" autofocus>
            </div>
            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-shield-halved"></i> Verify Code</button>
        </form>
    ]]
end

response:write(utils.render_auth_page("Two-Factor Verification", "Security Check", alert_html .. body_html))