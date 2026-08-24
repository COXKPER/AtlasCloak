local utils = dofile("public/lib/utils.lua")
utils.apply_security_headers()

local db = utils.get_db()

-- The device page requires an authenticated user; bounce to the realm login.
local username, _ = utils.get_session_user(db)

if not username then
    db:close()
    local return_to = "/device"
    local _uc = request:getParam("user_code") or ""
    if _uc ~= "" then
        return_to = "/device?user_code=" .. utils.url_encode(_uc)
    end
    response:redirect(utils.realm_url() .. "/protocol/openid-connect/auth?client_id=account&redirect_uri=" .. utils.url_encode(return_to))
    return
end

if not utils.get_policies(db).device_flow_enabled then
    db:close()
    response:setStatus(404)
    response:write("Device flow is disabled on this realm")
    return
end

local form = utils.parse_form(request.body)
local action = form.action or ""
local msg_html = ""
local confirm_html = ""
local input_html = ""

local function load_by_user_code(uc)
    uc = (uc or ""):upper():gsub("%s", "")
    if uc == "" then return nil, nil end
    local dc = db:get("dev_uc:" .. uc)
    if not dc then return nil, nil end
    local rec_str = db:get("dev:" .. dc)
    if not rec_str then return nil, nil end
    local rec = json.decode(rec_str)
    if os.time() > (rec.exp or 0) then return nil, nil end
    return dc, rec
end

-- ── Approve / Deny ────────────────────────────────────────────────────────────
if action == "approve" or action == "deny" then
    local ok, err = utils.validate_security_token(db, form, "device_confirm")
    local dc = form.device_code or ""
    local rec_str = ok and db:get("dev:" .. dc) or nil
    if not ok or not rec_str then
        msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' ..
            utils.html_escape(err or "Unknown or expired device request.") .. '</div>'
    else
        local rec = json.decode(rec_str)
        rec.status = (action == "approve") and "approved" or "denied"
        rec.approved_by = username
        rec.approved_at = os.time()
        db:put("dev:" .. dc, json.encode(rec))
        db:delete("dev_uc:" .. rec.user_code)

        local event = {
            type = action == "approve" and "DEVICE_APPROVED" or "DEVICE_DENIED",
            username = username,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Device flow " .. rec.status .. " for client: " .. (rec.client_id or "?")
        }
        local events_str = db:get(utils.rk("meta:events"))
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put(utils.rk("meta:events"), json.encode(events))

        if action == "approve" then
            msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> <strong>Device approved.</strong> Return to your device — it will sign in automatically. You can close this page.</div>'
        else
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Device request denied. You can close this page.</div>'
        end
    end

-- ── Show confirmation screen when a valid code was submitted ────────────────
else
    local code_input = form.user_code or request:getParam("user_code") or ""
    local dc, rec = load_by_user_code(code_input)

    if not rec then
        if code_input ~= "" then
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Invalid or expired code. Check the code shown on your device and try again.</div>'
        end
        input_html = [[
            <form method="POST" action="/device">
                <div class="form-group">
                    <label>Device Code</label>
                    <input type="text" name="user_code" value="]] .. utils.html_escape(code_input:upper()) .. [["
                           placeholder="XXXX-XXXX" maxlength="9" required
                           style="text-transform:uppercase;font-family:'JetBrains Mono',monospace;font-size:18px;letter-spacing:3px;text-align:center;">
                    <small style="color:var(--text-muted);font-size:11px;">Enter the code displayed on the device you are signing in from.</small>
                </div>
                <button type="submit" class="btn btn-primary"><i class="fa-solid fa-magnifying-glass"></i> Continue</button>
            </form>
        ]]
    elseif rec.status ~= "pending" then
        msg_html = '<div class="alert alert-info"><span class="alert-icon">i</span> This device request was already ' .. utils.html_escape(rec.status) .. '.</div>'
    else
        -- Confirmation screen listing client + requested scopes.
        local scope_items = ""
        local SCOPE_INFO = {
            openid      = { icon = "fa-id-card",         desc = "Verify your identity (required)" },
            profile     = { icon = "fa-user",            desc = "Read your basic profile (name, username)" },
            email       = { icon = "fa-envelope",        desc = "Read your email address" },
            address     = { icon = "fa-location-dot",    desc = "Read your postal address" },
            phone       = { icon = "fa-phone",           desc = "Read your phone number" },
            offline_access = { icon = "fa-rotate",       desc = "Stay signed in (refresh token)" },
        }
        for sc in string.gmatch(rec.scope or "openid profile email", "%S+") do
            local info = SCOPE_INFO[sc] or { icon = "fa-tag", desc = sc }
            scope_items = scope_items .. '<li><i class="fa-solid ' .. info.icon .. '" style="width:16px;color:var(--accent);"></i> ' ..
                utils.html_escape(info.desc) .. '</li>'
        end

        local cdata_str = db:get(utils.rk("client:") .. (rec.client_id or ""))
        local cdata = cdata_str and json.decode(cdata_str) or {}
        local client_label = cdata.name or rec.client_id or "Unknown application"

        local sec_token = utils.generate_security_token(db, "device_confirm")
        confirm_html = [[
            <div style="background:rgba(0,0,0,0.2);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:16px;">
                <div style="font-size:13px;color:var(--text);margin-bottom:10px;">
                    <strong>]] .. utils.html_escape(client_label) .. [[</strong> on another device wants to sign in as
                    <strong>]] .. utils.html_escape(username) .. [[</strong>.
                </div>
                <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">It will be able to:</div>
                <ul style="padding-left:20px;font-size:13px;color:var(--text);display:flex;flex-direction:column;gap:6px;">]] .. scope_items .. [[</ul>
            </div>
            <form method="POST" action="/device">
                <input type="hidden" name="device_code" value="]] .. utils.html_escape(dc) .. [[">
                ]] .. utils.render_security_fields(sec_token) .. [[
                <div style="display:flex;gap:10px;">
                    <button type="submit" name="action" value="approve" class="btn btn-primary"><i class="fa-solid fa-check"></i> Approve</button>
                    <button type="submit" name="action" value="deny" class="btn btn-secondary"><i class="fa-solid fa-xmark"></i> Deny</button>
                </div>
            </form>
        ]]
    end
end

db:close()
response:write(utils.render_auth_page("Device Sign-In", "Connect your device", msg_html .. confirm_html .. input_html))