local utils = dofile("public/lib/utils.lua")
utils.apply_security_headers()

local db = utils.get_db()
utils.ensure_admin_exists(db)

local username, _ = utils.get_session_user(db)
if not username then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=account&redirect_uri=/account/twofactor", 302)
    return
end

local msg_html = ""

-- ── POST actions ──────────────────────────────────────────────────────────────
if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local action = form.action or ""
    local u_str = db:get(utils.rk("user:") .. username)
    local ud = u_str and json.decode(u_str) or {}

    if action == "begin_enroll" and not (ud.totp and ud.totp.enabled) then
        -- Generate a fresh candidate secret; only activated after code check.
        local secret = utils.totp_generate_secret()
        db:put("totp_enroll:" .. username, json.encode({ secret = secret, exp = os.time() + 600 }))
    elseif action == "confirm_enroll" then
        local e_str = db:get("totp_enroll:" .. username)
        local e = e_str and json.decode(e_str)
        if e and os.time() <= e.exp and utils.totp_verify(e.secret, form.code or "") then
            ud.totp = { enabled = true, secret = e.secret, enrolled = os.time() }
            db:put(utils.rk("user:") .. username, json.encode(ud))
            db:delete("totp_enroll:" .. username)

            local event = {
                type = "MFA_ENABLED", username = username, ip = utils.get_client_ip(),
                time = os.time(), detail = "User enrolled TOTP two-factor authentication"
            }
            local events_str = db:get(utils.rk("meta:events"))
            local events = events_str and json.decode(events_str) or {}
            table.insert(events, event)
            db:put(utils.rk("meta:events"), json.encode(events))
            msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Two-factor authentication is now active on your account.</div>'
        else
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Invalid code — make sure your clock is correct and try again.</div>'
        end
    elseif action == "disable" then
        local pw_ok = ud.password and utils.verify_password(form.password or "", ud.password)
        if pw_ok and ud.totp and ud.totp.enabled then
            ud.totp = nil
            db:put(utils.rk("user:") .. username, json.encode(ud))
            local event = {
                type = "MFA_DISABLED", username = username, ip = utils.get_client_ip(),
                time = os.time(), detail = "User disabled TOTP two-factor authentication"
            }
            local events_str = db:get(utils.rk("meta:events"))
            local events = events_str and json.decode(events_str) or {}
            table.insert(events, event)
            db:put(utils.rk("meta:events"), json.encode(events))
            msg_html = '<div class="alert alert-warning"><span class="alert-icon">!</span> Two-factor authentication has been disabled.</div>'
        else
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Wrong password — 2FA was NOT disabled.</div>'
        end
    end
end

-- ── Current state ────────────────────────────────────────────────────────────
local u_str = db:get(utils.rk("user:") .. username)
local ud = u_str and json.decode(u_str) or {}
local totp_enabled = ud.totp and ud.totp.enabled
local pending_secret = nil
local e_str = db:get("totp_enroll:" .. username)
local e = e_str and json.decode(e_str)
if e and os.time() <= e.exp then pending_secret = e.secret end
db:close()

local body_html = ""

if totp_enabled then
    body_html = [[
        <div style="display:flex;align-items:center;gap:12px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:12px;padding:14px 18px;margin-bottom:20px;">
            <i class="fa-solid fa-shield-halved" style="font-size:22px;color:#22c55e;"></i>
            <div>
                <strong style="color:#22c55e;">Two-Factor Authentication Active</strong>
                <div style="font-size:12px;color:var(--text-muted);">Enrolled ]] .. os.date("%Y-%m-%d %H:%M", tonumber(ud.totp.enrolled) or os.time()) .. [[ · TOTP (6 digits / 30 s)</div>
            </div>
        </div>
        <form method="POST" action="/account/twofactor">
            <input type="hidden" name="action" value="disable">
            <div class="form-group">
                <label>Confirm Password to Disable 2FA</label>
                <input type="password" name="password" required autocomplete="current-password" placeholder="Your current password">
            </div>
            <button type="submit" class="btn btn-danger"><i class="fa-solid fa-shield-virus"></i> Disable Two-Factor</button>
        </form>
    ]]
elseif pending_secret then
    local uri = utils.totp_otpauth_uri("AtlasCloak", utils.get_realm() .. ":" .. username, pending_secret)
    body_html = [[
        <h3 style="margin-bottom:10px;font-size:15px;color:var(--text);">Finish Setup</h3>
        <ol style="font-size:13px;color:var(--text);padding-left:18px;line-height:1.8;margin-bottom:16px;">
            <li>Add a key manually in your authenticator app</li>
            <li>Paste this secret (type: <strong>Time-based</strong>, 6 digits, 30 s)</li>
            <li>Enter the current 6-digit code below</li>
        </ol>
        <div style="background:rgba(0,0,0,0.25);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:16px;">
            <code style="font-size:16px;font-weight:700;letter-spacing:2px;color:var(--accent);word-break:break-all;">]] .. utils.html_escape(pending_secret) .. [[</code>
        </div>
        <details style="margin-bottom:16px;font-size:12px;color:var(--text-muted);">
            <summary style="cursor:pointer;">otpauth:// URI</summary>
            <code style="word-break:break-all;font-size:11px;">]] .. utils.html_escape(uri) .. [[</code>
        </details>
        <form method="POST" action="/account/twofactor">
            <input type="hidden" name="action" value="confirm_enroll">
            <div class="form-group">
                <label>6-Digit Verification Code</label>
                <input type="text" name="code" maxlength="6" inputmode="numeric" pattern="[0-9]*" placeholder="123456" required autocomplete="one-time-code">
            </div>
            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-check"></i> Activate 2FA</button>
        </form>
    ]]
else
    body_html = [[
        <p style="font-size:13px;color:var(--text-muted);margin-bottom:18px;line-height:1.8;">
            Add a second factor so a stolen password alone cannot access your account.
            Works with Google Authenticator, Aegis, FreeOTP, 1Password, Authy.
        </p>
        <form method="POST" action="/account/twofactor">
            <input type="hidden" name="action" value="begin_enroll">
            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-shield-halved"></i> Set Up Two-Factor Authentication</button>
        </form>
    ]]
end

local content = msg_html .. '<div class="card"><div class="card-header"><h3><i class="fa-solid fa-mobile-screen" style="margin-right:8px;"></i> Authenticator App (TOTP)</h3></div><div class="card-body">' .. body_html .. '</div></div>'
response:write(utils.render_account_page("Two-Factor", "twofactor", ud, content))