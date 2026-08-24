local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/realm-settings", 302)
    return
end

local msg_html = ""
local current_tab = request:getParam("tab") or "general"

if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local action = form.action or "save_general"
    
    if action == "save_general" then
        local reg_enabled = (form.registration_enabled == "on" or form.registration_enabled == "true")
        utils.set_registration_enabled(db, reg_enabled)
        
        local realm_display_name = form.realm_display_name or "Atlas"
        if realm_display_name == "" then realm_display_name = "Atlas" end
        db:put(utils.rk("setting:realm_display_name"), realm_display_name)
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> General settings saved!</div>'
        current_tab = "general"
        
    elseif action == "save_tokens" then
        local token_lifespan = form.token_lifespan or "3600"
        local token_format = form.token_format or "jwt"
        local jwt_secret = form.jwt_secret or ""
        
        db:put(utils.rk("setting:token_lifespan"), token_lifespan)
        db:put(utils.rk("setting:token_format"), token_format)
        if jwt_secret ~= "" then
            db:put(utils.rk("setting:jwt_secret"), jwt_secret)
        end
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Token & JWT configuration saved!</div>'
        current_tab = "tokens"
        
    elseif action == "save_security" then
        local brute_force_enabled = (form.brute_force_enabled == "on" or form.brute_force_enabled == "true")
        local max_failures = form.max_login_failures or "5"
        local lockout_duration = form.lockout_duration or "900"
        
        db:put(utils.rk("setting:brute_force_enabled"), brute_force_enabled and "true" or "false")
        db:put(utils.rk("setting:max_login_failures"), max_failures)
        db:put(utils.rk("setting:lockout_duration"), lockout_duration)
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Security & Brute Force protection saved!</div>'
        current_tab = "security"
        
    elseif action == "save_password_policy" then
        local pwd_min_length = form.pwd_min_length or "6"
        local pwd_req_upper = (form.pwd_req_upper == "on" or form.pwd_req_upper == "true")
        local pwd_req_lower = (form.pwd_req_lower == "on" or form.pwd_req_lower == "true")
        local pwd_req_number = (form.pwd_req_number == "on" or form.pwd_req_number == "true")
        local pwd_req_symbol = (form.pwd_req_symbol == "on" or form.pwd_req_symbol == "true")
        
        db:put(utils.rk("setting:pwd_min_length"), pwd_min_length)
        db:put(utils.rk("setting:pwd_req_upper"), pwd_req_upper and "true" or "false")
        db:put(utils.rk("setting:pwd_req_lower"), pwd_req_lower and "true" or "false")
        db:put(utils.rk("setting:pwd_req_number"), pwd_req_number and "true" or "false")
        db:put(utils.rk("setting:pwd_req_symbol"), pwd_req_symbol and "true" or "false")
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Password policy updated!</div>'
        current_tab = "password_policy"
        
    elseif action == "save_theme" then
        local logo = form.custom_logo or "/images/default.png"
        if logo == "" then logo = "/images/default.png" end
        
        local valid_logo, logo_err = utils.validate_logo_url(logo)
        if not valid_logo then
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(logo_err) .. '</div>'
        else
            local bg_type = form.bg_type or "gradient"
            local bg_value = form.bg_value or ""
            
            if bg_type == "gradient" and (not bg_value or bg_value == "") then
                bg_value = "linear-gradient(135deg, #090d16 0%, #0f172a 45%, #1e1b4b 100%)"
            end
            
            db:put(utils.rk("setting:custom_logo"), logo)
            db:put(utils.rk("setting:bg_type"), bg_type)
            db:put(utils.rk("setting:bg_value"), bg_value)
            
            msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Branding and theme settings saved successfully!</div>'
        end
        current_tab = "theme"

    elseif action == "check_update" then
        local ok_token, token_err = utils.validate_security_token(db, form, "system_update")
        if not ok_token then
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(token_err) .. ' — reload the page and try again.</div>'
        else
            local remote_version, fetch_err = utils.fetch_remote_version()
            if not remote_version then
                msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Could not reach GitHub: ' .. utils.html_escape(fetch_err or "network error") .. '</div>'
            else
                local cmp = utils.compare_versions(remote_version, utils.version)
                local cmp_html
                if cmp > 0 then
                    cmp_html = '<span class="badge badge-warning">Update available: v' .. utils.html_escape(remote_version) .. '</span>'
                elseif cmp < 0 then
                    cmp_html = '<span class="badge badge-info">Local is newer (v' .. utils.html_escape(utils.version) .. ' &gt; v' .. utils.html_escape(remote_version) .. ')</span>'
                else
                    cmp_html = '<span class="badge badge-success">Up to date</span>'
                end
                msg_html = '<div class="alert alert-info"><span class="alert-icon"><i class="fa-solid fa-magnifying-glass"></i></span> Installed: <strong>v' .. utils.html_escape(utils.version) .. '</strong> &nbsp;·&nbsp; Latest on GitHub: <strong>v' .. utils.html_escape(remote_version) .. '</strong> &nbsp;' .. cmp_html .. '</div>'
            end
        end
        current_tab = "updates"

    elseif action == "run_upgrade" then
        local ok_token, token_err = utils.validate_security_token(db, form, "system_update")
        if not ok_token then
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(token_err) .. ' — reload the page and try again.</div>'
            current_tab = "updates"
        else
            local lines = {}
            
            -- 1. Download the latest main tarball (pinned URL — no user input reaches the shell)
            local dl_ok = os.execute("rm -rf /tmp/atlascloak-update /tmp/atlascloak-update.tar.gz && mkdir -p /tmp/atlascloak-update && (curl -fsSL --max-time 90 -o /tmp/atlascloak-update.tar.gz https://github.com/COXKPER/AtlasCloak/archive/refs/heads/main.tar.gz || wget -qT 90 -O /tmp/atlascloak-update.tar.gz https://github.com/COXKPER/AtlasCloak/archive/refs/heads/main.tar.gz)")
            if not dl_ok then
                table.insert(lines, "[FAIL] Download from github.com/COXKPER/AtlasCloak failed (curl/wget unavailable or network error).")
            end
            
            -- 2. Extract + verify archive structure before touching anything
            if dl_ok then
                local ex_ok = os.execute("tar xzf /tmp/atlascloak-update.tar.gz -C /tmp/atlascloak-update && test -f /tmp/atlascloak-update/AtlasCloak-main/lib/utils.lua && test -f /tmp/atlascloak-update/AtlasCloak-main/index.lua")
                if not ex_ok then
                    table.insert(lines, "[FAIL] Extracted archive failed verification (lib/utils.lua missing). Update aborted, system untouched.")
                    dl_ok = false
                end
            end
            
            -- 3. Backup current installation (database atlascloak.db lives outside public/ and is never touched)
            if dl_ok then
                os.execute("mkdir -p backups")
                local bk_ok = os.execute("tar czf backups/atlascloak-backup-" .. os.time() .. ".tar.gz -C public . 2>/dev/null")
                if bk_ok then
                    table.insert(lines, "[OK] Current installation backed up to backups/atlascloak-backup-" .. os.time() .. ".tar.gz")
                else
                    table.insert(lines, "[WARN] Backup step reported an error — continuing with update.")
                end
            end
            
            -- 4. Apply: overlay new files over public/ (no deletions; runtime data preserved)
            if dl_ok then
                local cp_ok = os.execute("cp -a /tmp/atlascloak-update/AtlasCloak-main/. public/")
                if cp_ok then
                    local new_version = utils.read_local_version_file()
                    table.insert(lines, "[OK] Update applied successfully. Installed version is now v" .. utils.html_escape(new_version or "?") .. " (effective on next request).")
                    table.insert(lines, "[OK] Restarting Telamon is NOT required — Lua routes reload per request.")
                else
                    table.insert(lines, "[FAIL] Copy step failed (disk full or permissions?). Restore from the backup in backups/.")
                end
            end
            
            os.execute("rm -rf /tmp/atlascloak-update /tmp/atlascloak-update.tar.gz")
            
            local upgrade_failed = lines[1] and string.find(lines[1], "%[FAIL%]", 1, true) ~= nil
            local event = {
                type = upgrade_failed and "UPDATE_FAILED" or "SYSTEM_UPDATE",
                username = admin_user,
                ip = utils.get_client_ip(),
                time = os.time(),
                detail = upgrade_failed and "Self-update from GitHub failed" or "Self-update from GitHub applied"
            }
            local events_str = db:get(utils.rk("meta:events"))
            local events = events_str and json.decode(events_str) or {}
            table.insert(events, event)
            if #events > 100 then
                local new_events = {}
                for i = #events - 99, #events do table.insert(new_events, events[i]) end
                events = new_events
            end
            db:put(utils.rk("meta:events"), json.encode(events))
            
            local alert_cls = upgrade_failed and "alert-error" or "alert-success"
            local icon = upgrade_failed and "✕" or "✓"
            msg_html = '<div class="alert ' .. alert_cls .. '"><span class="alert-icon">' .. icon .. '</span> Self-update finished with result:<br><pre style="margin-top:6px;font-size:11px;color:#cbd5e1;background:#0f172a;padding:8px;border-radius:6px;overflow-x:auto;">' .. utils.html_escape(table.concat(lines, "\n")) .. '</pre></div>'
            current_tab = "updates"
        end

    elseif action == "save_policies" then
        local function t(v) return (v == "on" or v == "true") and "true" or "false" end
        db:put(utils.rk("policy:pkce_required"), t(form.pol_pkce_required))
        db:put(utils.rk("policy:mfa_required_all"), t(form.pol_mfa_required_all))
        db:put(utils.rk("policy:mfa_required_admins"), t(form.pol_mfa_required_admins))
        db:put(utils.rk("policy:passkeys_enabled"), t(form.pol_passkeys_enabled))
        db:put(utils.rk("policy:device_flow_enabled"), t(form.pol_device_flow_enabled))
        db:put(utils.rk("policy:consent_default"), t(form.pol_consent_default))
        local idle = tonumber(form.session_idle_timeout) or 0
        if idle < 0 then idle = 0 end
        db:put(utils.rk("setting:session_idle_timeout"), tostring(idle))

        msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Realm policies saved.</div>'
        current_tab = "policies"

    elseif action == "create_realm" then
        local ok_token, token_err = utils.validate_security_token(db, form, "realm_admin")
        if not ok_token then
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(token_err) .. '</div>'
        else
            local ok_create, err_create = utils.create_realm(db, form.realm_name or "")
            if ok_create then
                msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Realm <strong>' .. utils.html_escape(form.realm_name) .. '</strong> created. Its endpoints are live at <code>/auth/realms/' .. utils.html_escape(form.realm_name) .. '/…</code> immediately.</div>'
            else
                msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(err_create or "Could not create realm") .. '</div>'
            end
        end
        current_tab = "realms"

    elseif action == "delete_realm" then
        local ok_token, token_err = utils.validate_security_token(db, form, "realm_admin")
        if not ok_token then
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(token_err) .. '</div>'
        else
            local ok_del, err_del = utils.delete_realm(db, form.realm_name or "")
            if ok_del then
                msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Realm <strong>' .. utils.html_escape(form.realm_name) .. '</strong> deleted together with its data.</div>'
            else
                msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(err_del or "Could not delete realm") .. '</div>'
            end
        end
        current_tab = "realms"

    elseif action == "import_realm" then
        local json_payload = form.json_payload or ""
        local ok, parse_result = pcall(json.decode, json_payload)
        if not ok or type(parse_result) ~= "table" then
            msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Invalid JSON format provided.</div>'
        else
            local imp_ok, imp_err = utils.import_realm_data(db, parse_result)
            if not imp_ok then
                msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Import failed: ' .. utils.html_escape(imp_err) .. '</div>'
            else
                msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Realm data imported successfully!</div>'
            end
        end
        current_tab = "export_import"
    end
    
    local event = {
        type = "REALM_CONFIG_UPDATE",
        username = admin_user,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Updated realm settings tab: " .. current_tab
    }
    local events_str = db:get(utils.rk("meta:events"))
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put(utils.rk("meta:events"), json.encode(events))
end

-- Fetch current settings
local reg_enabled = utils.is_registration_enabled(db)
local realm_display_name = utils.get_realm_display_name(db)
local token_lifespan = db:get(utils.rk("setting:token_lifespan")) or "3600"
local token_format = db:get(utils.rk("setting:token_format")) or "jwt"
-- Note: never fetch/render the actual JWT secret here (T2) — get_jwt_secret()
-- would generate + persist a secret as a side effect of merely viewing the page.

local bf_cfg = utils.get_brute_force_config(db)
local policy = utils.get_password_policy(db)

-- Realm policies + realm registry
local pol = utils.get_policies(db)
local realms = utils.get_realms(db)
local realm_admin_sec_token = utils.generate_security_token(db, "realm_admin")
local idle_timeout = utils.get_session_idle_timeout(db)

-- One-time CSRF tokens for privileged actions (10-minute expiry, single use)
local update_sec_token = utils.generate_security_token(db, "system_update")

db:close()

-- Tab navigation helper
local function tab_class(t)
    return (t == current_tab) and "tab-btn active" or "tab-btn"
end

-- General Tab Content
local general_tab_html = [[
    <form method="POST" action="/admin/realm-settings?tab=general">
        <input type="hidden" name="action" value="save_general">
        <div class="form-group">
            <label>Realm Identifier</label>
            <input type="text" value="master" disabled style="background:rgba(255,255,255,0.03);color:var(--text-muted);">
            <small style="color:var(--text-muted);font-size:11px;">Primary system realm identifier</small>
        </div>
        <div class="form-group">
            <label>Display Name</label>
            <input type="text" name="realm_display_name" value="]] .. utils.html_escape(realm_display_name) .. [[" placeholder="Atlas">
            <small style="color:var(--text-muted);font-size:11px;">Shown in browser tab titles (e.g. <code>Atlas - AtlasCloak</code>), login page, and console headers.</small>
        </div>

        <div class="card" style="margin:20px 0;background:rgba(0,0,0,0.2);">
            <div class="card-header">
                <h3>Login & Registration Features</h3>
            </div>
            <div class="toggle-row">
                <div>
                    <div class="toggle-label">User Self-Registration</div>
                    <div class="toggle-desc">Allow anonymous visitors to create an account through the registration portal</div>
                </div>
                <label class="toggle">
                    <input type="checkbox" name="registration_enabled" ]] .. (reg_enabled and "checked" or "") .. [[>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="toggle-row">
                <div>
                    <div class="toggle-label">Anti-Bot Protection (Challenge Token & Honeypot)</div>
                    <div class="toggle-desc">Cryptographic one-time challenge token + bot trap fields on all auth forms</div>
                </div>
                <span class="badge badge-success">Always Active</span>
            </div>
        </div>

        <button type="submit" class="btn btn-primary" style="width:auto;">Save General Settings</button>
    </form>
]]

-- Tokens & JWT Tab Content
local tokens_tab_html = [[
    <form method="POST" action="/admin/realm-settings?tab=tokens">
        <input type="hidden" name="action" value="save_tokens">
        <div class="form-group">
            <label>Token Signature & Format</label>
            <select name="token_format">
                <option value="jwt" ]] .. (token_format == "jwt" and "selected" or "") .. [[>Signed JWT (Stateless HMAC-SHA256) — Recommended</option>
                <option value="opaque" ]] .. (token_format == "opaque" and "selected" or "") .. [[>Opaque Token (Stateful UUID)</option>
            </select>
            <small style="color:var(--text-muted);font-size:11px;">Signed JWT allows downstream APIs to verify tokens statelessly without querying AtlasCloak.</small>
        </div>
        <div class="form-group">
            <label>Access Token Lifespan (Seconds)</label>
            <input type="number" name="token_lifespan" value="]] .. utils.html_escape(token_lifespan) .. [[" min="60" max="86400">
            <small style="color:var(--text-muted);font-size:11px;">Default: 3600 seconds (1 hour)</small>
        </div>
        <div class="form-group">
            <label>JWT Signing Secret Key</label>
            <input type="text" name="jwt_secret" value="" placeholder="(unchanged — leave blank to keep current secret)">
            <small style="color:var(--text-muted);font-size:11px;">Shared secret used by HMAC-SHA256 to sign tokens. Never displayed; leave blank to keep the existing secret. A new 256-bit random secret is generated on first use.</small>
        </div>
        <button type="submit" class="btn btn-primary" style="width:auto;">Save Token Settings</button>
    </form>
]]

-- Security & Brute Force Tab Content
local security_tab_html = [[
    <form method="POST" action="/admin/realm-settings?tab=security">
        <input type="hidden" name="action" value="save_security">
        
        <div class="card" style="margin-bottom:20px;background:rgba(0,0,0,0.2);">
            <div class="card-header">
                <h3>Brute Force Detection & Account Lockout</h3>
            </div>
            <div class="toggle-row">
                <div>
                    <div class="toggle-label">Enable Brute Force Detection</div>
                    <div class="toggle-desc">Automatically lock user accounts after consecutive failed login attempts</div>
                </div>
                <label class="toggle">
                    <input type="checkbox" name="brute_force_enabled" ]] .. (bf_cfg.enabled and "checked" or "") .. [[>
                    <span class="toggle-slider"></span>
                </label>
            </div>
        </div>

        <div class="row-2">
            <div class="form-group">
                <label>Max Login Failures</label>
                <input type="number" name="max_login_failures" value="]] .. bf_cfg.max_failures .. [[" min="1" max="50">
                <small style="color:var(--text-muted);font-size:11px;">Number of failed attempts before lockout occurs (Default: 5)</small>
            </div>
            <div class="form-group">
                <label>Lockout Duration (Seconds)</label>
                <input type="number" name="lockout_duration" value="]] .. bf_cfg.lock_duration .. [[" min="30" max="86400">
                <small style="color:var(--text-muted);font-size:11px;">Duration the account remains locked (Default: 900s = 15m)</small>
            </div>
        </div>

        <button type="submit" class="btn btn-primary" style="width:auto;">Save Security Settings</button>
    </form>
]]

-- Password Policy Tab Content
local pwd_tab_html = [[
    <form method="POST" action="/admin/realm-settings?tab=password_policy">
        <input type="hidden" name="action" value="save_password_policy">
        
        <div class="form-group">
            <label>Minimum Password Length</label>
            <input type="number" name="pwd_min_length" value="]] .. policy.min_length .. [[" min="4" max="64">
            <small style="color:var(--text-muted);font-size:11px;">Minimum number of characters required (Default: 6)</small>
        </div>

        <div class="card" style="margin:20px 0;background:rgba(0,0,0,0.2);">
            <div class="card-header">
                <h3>Character Requirements</h3>
            </div>
            <div class="toggle-row">
                <div>
                    <div class="toggle-label">Require Uppercase Letter</div>
                    <div class="toggle-desc">Password must contain at least one uppercase letter (A-Z)</div>
                </div>
                <label class="toggle">
                    <input type="checkbox" name="pwd_req_upper" ]] .. (policy.req_upper and "checked" or "") .. [[>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="toggle-row">
                <div>
                    <div class="toggle-label">Require Lowercase Letter</div>
                    <div class="toggle-desc">Password must contain at least one lowercase letter (a-z)</div>
                </div>
                <label class="toggle">
                    <input type="checkbox" name="pwd_req_lower" ]] .. (policy.req_lower and "checked" or "") .. [[>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="toggle-row">
                <div>
                    <div class="toggle-label">Require Number / Digit</div>
                    <div class="toggle-desc">Password must contain at least one numeric digit (0-9)</div>
                </div>
                <label class="toggle">
                    <input type="checkbox" name="pwd_req_number" ]] .. (policy.req_number and "checked" or "") .. [[>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="toggle-row">
                <div>
                    <div class="toggle-label">Require Special Symbol</div>
                    <div class="toggle-desc">Password must contain at least one special character (!@#$%^&*)</div>
                </div>
                <label class="toggle">
                    <input type="checkbox" name="pwd_req_symbol" ]] .. (policy.req_symbol and "checked" or "") .. [[>
                    <span class="toggle-slider"></span>
                </label>
            </div>
        </div>

        <button type="submit" class="btn btn-primary" style="width:auto;">Save Password Policy</button>
    </form>
]]

-- Theme & Branding Tab Content
local theme = utils.get_theme_settings(db)
local theme_tab_html = [[
    <form method="POST" action="/admin/realm-settings?tab=theme">
        <input type="hidden" name="action" value="save_theme">
        
        <h3 style="margin-bottom:12px;font-size:16px;color:var(--text);"><i class="fa-solid fa-image" style="margin-right:8px;color:var(--primary-hover);"></i> Realm Logo Configuration</h3>
        
        <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px;padding:16px;background:rgba(0,0,0,0.25);border:1px solid var(--border);border-radius:12px;">
            <div style="width:90px;height:70px;background:rgba(15,23,42,0.9);border:1px solid var(--border);border-radius:10px;display:flex;align-items:center;justify-content:center;padding:8px;">
                <img id="logo_preview" src="]] .. utils.html_escape(theme.logo) .. [[" alt="Current Logo" style="max-height:54px;max-width:74px;object-fit:contain;" onerror="this.src='/images/default.png';">
            </div>
            <div style="flex:1;">
                <div style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px;">Current Custom Logo</div>
                <div style="font-size:12px;color:var(--text-muted);">Default path: <code>/images/default.png</code>. Supported image types: PNG, SVG, JPG, WebP (GIF is disallowed).</div>
            </div>
        </div>

        <div class="form-group">
            <label>Logo URL or Asset Path</label>
            <input type="text" id="custom_logo_input" name="custom_logo" value="]] .. utils.html_escape(theme.logo) .. [[" placeholder="/images/default.png or https://example.com/logo.png" oninput="document.getElementById('logo_preview').src=this.value || '/images/default.png';">
            <div style="display:flex;gap:8px;margin-top:8px;">
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('custom_logo_input').value='/images/default.png';document.getElementById('logo_preview').src='/images/default.png';">
                    <i class="fa-solid fa-rotate-left"></i> Reset to Default Logo
                </button>
            </div>
        </div>

        <hr style="border:none;border-top:1px solid var(--border);margin:24px 0;">

        <h3 style="margin-bottom:12px;font-size:16px;color:var(--text);"><i class="fa-solid fa-wand-magic-sparkles" style="margin-right:8px;color:var(--accent);"></i> Login & Registration Background</h3>

        <div class="form-group">
            <label>Background Type</label>
            <div style="display:flex;gap:20px;margin-top:6px;">
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:14px;color:var(--text);">
                    <input type="radio" name="bg_type" value="gradient" ]] .. (theme.bg_type == "gradient" and "checked" or "") .. [[ onchange="toggleBgType('gradient')">
                    Modern Gradient (CSS)
                </label>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:14px;color:var(--text);">
                    <input type="radio" name="bg_type" value="image" ]] .. (theme.bg_type == "image" and "checked" or "") .. [[ onchange="toggleBgType('image')">
                    Custom Image URL
                </label>
            </div>
        </div>

        <div id="gradient_group" class="form-group" style="]] .. (theme.bg_type == "image" and "display:none;" or "") .. [[">
            <label>CSS Background Gradient String</label>
            <textarea id="bg_value_gradient" name="bg_value" rows="3" placeholder="linear-gradient(135deg, #090d16 0%, #0f172a 45%, #1e1b4b 100%)" style="font-family:monospace;font-size:12px;">]] .. utils.html_escape(theme.bg_value) .. [[</textarea>
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;">
                <span style="font-size:12px;color:var(--text-muted);align-self:center;margin-right:4px;">Presets:</span>
                <button type="button" class="btn btn-sm btn-secondary" onclick="setGradient('linear-gradient(135deg, #090d16 0%, #0f172a 45%, #1e1b4b 100%)')">Deep Space (Default)</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="setGradient('radial-gradient(ellipse at 30% 20%, rgba(99,102,241,0.25) 0%, transparent 60%), linear-gradient(135deg, #020617 0%, #0f172a 100%)')">Midnight Slate</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="setGradient('linear-gradient(135deg, #0b071e 0%, #1e1035 50%, #2e0854 100%)')">Cosmic Violet</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="setGradient('linear-gradient(135deg, #022c22 0%, #064e3b 50%, #042f2e 100%)')">Emerald Matrix</button>
            </div>
        </div>

        <div id="image_group" class="form-group" style="]] .. (theme.bg_type == "image" and "" or "display:none;") .. [[">
            <label>Background Image URL</label>
            <input type="text" id="bg_value_image" placeholder="https://images.unsplash.com/photo-... or /images/custom-bg.jpg" value="]] .. (theme.bg_type == "image" and utils.html_escape(theme.bg_value) or "") .. [[">
            <small style="color:var(--text-muted);display:block;margin-top:4px;">Image will be rendered full-screen with cover fitting on desktop & mobile.</small>
        </div>

        <div style="margin-top:20px;">
            <div style="font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;">Live Background Preview</div>
            <div id="bg_live_preview" style="height:100px;border-radius:12px;border:1px solid var(--border);]] .. (theme.bg_type == "image" and ("background: url('" .. utils.html_escape(theme.bg_value) .. "') center/cover;") or ("background: " .. theme.bg_value .. ";")) .. [[display:flex;align-items:center;padding-left:24px;">
                <div style="background:rgba(15,23,42,0.85);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,0.1);padding:10px 16px;border-radius:10px;font-size:12px;color:var(--text);display:flex;align-items:center;gap:10px;">
                    <i class="fa-solid fa-desktop" style="color:var(--accent);"></i> Desktop Left-Aligned Card Preview
                </div>
            </div>
        </div>

        <script>
            function toggleBgType(type) {
                var g = document.getElementById('gradient_group');
                var img = document.getElementById('image_group');
                var g_val = document.getElementById('bg_value_gradient');
                var img_val = document.getElementById('bg_value_image');
                var prev = document.getElementById('bg_live_preview');
                if (type === 'image') {
                    g.style.display = 'none';
                    img.style.display = 'block';
                    g_val.name = '';
                    img_val.name = 'bg_value';
                    prev.style.background = 'url(' + (img_val.value || '') + ') center/cover';
                } else {
                    g.style.display = 'block';
                    img.style.display = 'none';
                    g_val.name = 'bg_value';
                    img_val.name = '';
                    prev.style.background = g_val.value || 'linear-gradient(135deg, #090d16 0%, #0f172a 45%, #1e1b4b 100%)';
                }
            }
            function setGradient(css) {
                var g_val = document.getElementById('bg_value_gradient');
                g_val.value = css;
                document.getElementById('bg_live_preview').style.background = css;
            }
            document.getElementById('bg_value_gradient').addEventListener('input', function() {
                document.getElementById('bg_live_preview').style.background = this.value;
            });
            document.getElementById('bg_value_image').addEventListener('input', function() {
                document.getElementById('bg_live_preview').style.background = 'url(' + this.value + ') center/cover';
            });
        </script>

        <button type="submit" class="btn btn-primary" style="width:auto;margin-top:20px;">
            <i class="fa-solid fa-floppy-disk"></i> Save Branding & Theme
        </button>
    </form>
]]

-- Export & Import Tab Content
local export_tab_html = [[
    <div style="display:flex;flex-direction:column;gap:20px;">
        <div class="card" style="background:rgba(0,0,0,0.2);">
            <div class="card-header">
                <h3><i class="fa-solid fa-file-export" style="margin-right:6px;"></i> Export Realm Configuration</h3>
            </div>
            <div class="card-body">
                <p style="font-size:13px;color:var(--text-muted);margin-bottom:14px;">
                    Download a full JSON snapshot of this realm, including users, roles, groups, clients, and security settings.
                </p>
                <a href="/admin/realm-settings/export" class="btn btn-primary" style="width:auto;" download>
                    <i class="fa-solid fa-download"></i> Download Realm JSON Export
                </a>
            </div>
        </div>

        <div class="card" style="background:rgba(0,0,0,0.2);">
            <div class="card-header">
                <h3><i class="fa-solid fa-file-import" style="margin-right:6px;"></i> Import / Restore Realm Configuration</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/realm-settings?tab=export_import">
                    <input type="hidden" name="action" value="import_realm">
                    <div class="form-group">
                        <label>Paste Realm JSON</label>
                        <textarea name="json_payload" rows="8" placeholder='{"realm": "master", "displayName": "Atlas", "settings": { ... }}' required style="font-family:monospace;font-size:12px;"></textarea>
                    </div>
                    <button type="submit" class="btn btn-warning" style="width:auto;" onclick="return confirm('Importing will merge / update realm settings and users. Proceed?')">
                        <i class="fa-solid fa-bolt"></i> Import Configuration
                    </button>
                </form>
            </div>
        </div>
    </div>
]]

-- System Updates & Upgrade Tab Content
local client_ip = utils.get_client_ip()
local req_headers = request and request.headers or {}

local updates_tab_html = [[
    <div style="display:flex;flex-direction:column;gap:20px;">
        <!-- Software & Legal Attribution -->
        <div class="card" style="background:rgba(0,0,0,0.25);border:1px solid var(--border);">
            <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">
                <h3><i class="fa-solid fa-code-branch" style="margin-right:8px;color:var(--primary-hover);"></i> System & License Information</h3>
                <span class="badge badge-success">AGPLv3 Compliance Active</span>
            </div>
            <div class="card-body">
                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:14px;margin-bottom:16px;">
                    <div style="background:rgba(15,23,42,0.6);padding:12px;border-radius:8px;border:1px solid var(--border);">
                        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Software</div>
                        <div style="font-size:15px;font-weight:700;color:var(--text-heading);margin-top:2px;">AtlasCloak</div>
                    </div>
                    <div style="background:rgba(15,23,42,0.6);padding:12px;border-radius:8px;border:1px solid var(--border);">
                        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Current Version</div>
                        <div style="font-size:15px;font-weight:700;color:var(--accent);margin-top:2px;">v]] .. utils.version .. [[</div>
                    </div>
                    <div style="background:rgba(15,23,42,0.6);padding:12px;border-radius:8px;border:1px solid var(--border);">
                        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">License</div>
                        <div style="font-size:15px;font-weight:700;color:#22c55e;margin-top:2px;">GNU AGPLv3</div>
                    </div>
                    <div style="background:rgba(15,23,42,0.6);padding:12px;border-radius:8px;border:1px solid var(--border);">
                        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Source Repository</div>
                        <div style="font-size:13px;font-weight:600;margin-top:4px;">
                            <a href="https://github.com/COXKPER/AtlasCloak" target="_blank" style="color:var(--primary-hover);text-decoration:none;"><i class="fa-brands fa-github"></i> COXKPER/AtlasCloak</a>
                        </div>
                    </div>
                </div>

                <div style="padding:12px 16px;background:rgba(99,102,241,0.08);border-left:3px solid var(--primary);border-radius:6px;font-size:13px;color:var(--text);">
                    <strong>Legal Attribution Notice:</strong><br>
                    This <a href="https://github.com/COXKPER/AtlasCloak" target="_blank" style="color:var(--primary-hover);font-weight:600;">AtlasCloak</a> system is licensed under the <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" style="color:var(--accent);font-weight:600;">GNU Affero General Public License v3.0 (GNU AGPLv3)</a>. Complete corresponding source code is openly distributed.
                </div>
            </div>
        </div>

        <!-- Upgrade Selection -->
        <div class="card" style="background:rgba(0,0,0,0.25);border:1px solid var(--border);">
            <div class="card-header">
                <h3><i class="fa-solid fa-cloud-arrow-down" style="margin-right:8px;color:var(--accent);"></i> Upgrade Selection & System Updates</h3>
            </div>
            <div class="card-body">
                <p style="font-size:13px;color:var(--text-muted);margin-bottom:16px;">
                    Check for new releases and pull the latest system scripts, protocol handlers, and security fixes directly from the official GitHub repository (<code>https://github.com/COXKPER/AtlasCloak</code>). Your database (<code>atlascloak.db</code>) and server config (<code>config.toml</code>) remain untouched — the current installation is archived to <code>backups/</code> before anything is applied.
                </p>

                <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:8px;">
                    <form method="POST" action="/admin/realm-settings?tab=updates" style="display:inline;">
                        <input type="hidden" name="action" value="check_update">
                        ]] .. utils.render_security_fields(update_sec_token) .. [[
                        <button type="submit" class="btn btn-secondary">
                            <i class="fa-solid fa-magnifying-glass"></i> Check for Updates
                        </button>
                    </form>
                    <form method="POST" action="/admin/realm-settings?tab=updates" style="display:inline;">
                        <input type="hidden" name="action" value="run_upgrade">
                        ]] .. utils.render_security_fields(update_sec_token) .. [[
                        <button type="submit" class="btn btn-primary" onclick="return confirm('Download the latest version from https://github.com/COXKPER/AtlasCloak, back up the current installation, and apply it now?');">
                            <i class="fa-solid fa-cloud-arrow-down"></i> Download &amp; Apply Update
                        </button>
                    </form>
                </div>

                <div style="font-size:11px;color:var(--text-muted);">
                    <i class="fa-solid fa-shield-halved" style="color:var(--success);"></i> Protected by one-time CSRF tokens &middot; every attempt is written to the audit log with the resolved client IP.
                </div>

                <div style="margin-top:16px;">
                    <div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:8px;">Manual Upgrade Guide (CLI):</div>
                    <pre style="background:#090d16;padding:12px;border-radius:8px;border:1px solid var(--border);font-family:monospace;font-size:12px;color:#38bdf8;overflow-x:auto;"># 1. Download &amp; extract the latest release:
curl -fsSL -o /tmp/atlas.tar.gz https://github.com/COXKPER/AtlasCloak/archive/refs/heads/main.tar.gz
mkdir -p /tmp/atlascloak-update &amp;&amp; tar xzf /tmp/atlas.tar.gz -C /tmp/atlascloak-update

# 2. Back up, then apply over public/:
tar czf backups/atlascloak-backup-$(date +%s).tar.gz -C public .
cp -a /tmp/atlascloak-update/AtlasCloak-main/. public/

# 3. Restarting Telamon is optional — Lua routes reload per request.</pre>
                </div>
            </div>
        </div>

        <!-- Reverse Proxy & Real Client IP Detection -->
        <div class="card" style="background:rgba(0,0,0,0.25);border:1px solid var(--border);">
            <div class="card-header">
                <h3><i class="fa-solid fa-network-wired" style="margin-right:8px;color:var(--success);"></i> Reverse Proxy & Real Client IP Support</h3>
            </div>
            <div class="card-body">
                <p style="font-size:13px;color:var(--text-muted);margin-bottom:14px;">
                    Real client IP extraction supports chained reverse proxies including <strong>Caddy, Nginx, Cloudflare, Traefik, and HAProxy</strong>.
                </p>
                <table class="table" style="font-size:12px;">
                    <thead>
                        <tr>
                            <th>Parameter</th>
                            <th>Detected Value</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Resolved Client IP</strong></td>
                            <td><code style="font-size:13px;color:var(--success);font-weight:700;">]] .. utils.html_escape(client_ip) .. [[</code></td>
                            <td><span class="badge badge-success">Active Client IP</span></td>
                        </tr>
                        <tr>
                            <td><code>X-Forwarded-For</code></td>
                            <td><code>]] .. utils.html_escape(req_headers["x-forwarded-for"] or "Not Present") .. [[</code></td>
                            <td>]] .. (req_headers["x-forwarded-for"] and '<span class="badge badge-info">Proxy Chained</span>' or '<span class="badge">Direct</span>') .. [[</td>
                        </tr>
                        <tr>
                            <td><code>X-Real-IP</code></td>
                            <td><code>]] .. utils.html_escape(req_headers["x-real-ip"] or "Not Present") .. [[</code></td>
                            <td>]] .. (req_headers["x-real-ip"] and '<span class="badge badge-info">Forwarded</span>' or '<span class="badge">None</span>') .. [[</td>
                        </tr>
                        <tr>
                            <td><code>CF-Connecting-IP</code></td>
                            <td><code>]] .. utils.html_escape(req_headers["cf-connecting-ip"] or "Not Present") .. [[</code></td>
                            <td>]] .. (req_headers["cf-connecting-ip"] and '<span class="badge badge-warning">Cloudflare CDN</span>' or '<span class="badge">None</span>') .. [[</td>
                        </tr>
                        <tr>
                            <td><code>X-Forwarded-Proto</code></td>
                            <td><code>]] .. utils.html_escape(req_headers["x-forwarded-proto"] or "http") .. [[</code></td>
                            <td><span class="badge badge-info">]] .. utils.html_escape(string.upper(req_headers["x-forwarded-proto"] or "http")) .. [[</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
]]

-- Realm Policies Tab Content
local function pol_toggle(name, label, desc, checked)
    return [[
        <div class="toggle-row">
            <div>
                <div class="toggle-label">]] .. label .. [[</div>
                <div class="toggle-desc">]] .. desc .. [[</div>
            </div>
            <label class="toggle">
                <input type="checkbox" name="]] .. name .. [[" ]] .. (checked and "checked" or "") .. [[>
                <span class="toggle-slider"></span>
            </label>
        </div>
    ]]
end

local policies_tab_html = [[
    <form method="POST" action="/admin/realm-settings?tab=policies">
        <input type="hidden" name="action" value="save_policies">
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:14px;">
            Policies apply to realm <code>master</code> and are stored per-realm.
        </div>
        <div class="card" style="background:rgba(0,0,0,0.2);margin-bottom:16px;">
            <div class="card-header"><h3><i class="fa-solid fa-shield-halved" style="margin-right:6px;color:var(--success);"></i> Authentication Policies</h3></div>
            ]] ..
            pol_toggle("pol_mfa_required_all", "Require MFA for all users", "Every login must enroll and verify a TOTP authenticator", pol.mfa_required_all) ..
            pol_toggle("pol_mfa_required_admins", "Require MFA for admin console", "Admins without 2FA cannot open the admin console", pol.mfa_required_admins) ..
            pol_toggle("pol_passkeys_enabled", "Allow Passkeys / WebAuthn", "Users can register passkeys and sign in passwordless", pol.passkeys_enabled) ..
            pol_toggle("pol_device_flow_enabled", "Allow Device Authorization Flow", "RFC 8628 sign-in for TVs, CLIs, and IoT devices", pol.device_flow_enabled) ..
        [[
        </div>
        <div class="card" style="background:rgba(0,0,0,0.2);margin-bottom:16px;">
            <div class="card-header"><h3><i class="fa-solid fa-key" style="margin-right:6px;color:var(--primary-hover);"></i> OAuth / OIDC Policies</h3></div>
            ]] ..
            pol_toggle("pol_pkce_required", "Require PKCE on all authorization-code flows", "Reject code flows without code_challenge (recommended for public clients)", pol.pkce_required) ..
            pol_toggle("pol_consent_default", "Require consent by default", "Clients without an explicit consent setting show the consent screen", pol.consent_default) ..
        [[
        </div>
        <div class="form-group">
            <label>Session Idle Timeout (seconds, 0 = never expire)</label>
            <input type="number" name="session_idle_timeout" value="]] .. tostring(idle_timeout) .. [[" min="0" max="2592000">
            <small style="color:var(--text-muted);font-size:11px;">Sessions idle longer than this are invalidated automatically.</small>
        </div>
        <button type="submit" class="btn btn-primary" style="width:auto;"><i class="fa-solid fa-floppy-disk"></i> Save Realm Policies</button>
    </form>
]]

-- Realms Tab Content
local realm_rows = ""
for _, r in ipairs(realms) do
    local issuer = utils.get_base_url() .. "/auth/realms/" .. r
    local del_btn = ""
    if r ~= "master" then
        del_btn = [[
            <form method="POST" action="/admin/realm-settings?tab=realms" style="display:inline;" onsubmit="return confirm('Delete realm ' + ']] .. utils.html_escape(r) .. [[' and ALL its data? This cannot be undone.');">
                <input type="hidden" name="action" value="delete_realm">
                <input type="hidden" name="realm_name" value="]] .. utils.html_escape(r) .. [[">
                ]] .. utils.render_security_fields(realm_admin_sec_token) .. [[
                <button type="submit" class="btn btn-sm btn-danger"><i class="fa-solid fa-trash"></i> Delete</button>
            </form>
        ]]
    else
        del_btn = '<span class="badge badge-success">System Realm</span>'
    end
    realm_rows = realm_rows .. [[
        <tr>
            <td><strong>]] .. utils.html_escape(r) .. [[</strong></td>
            <td><code style="font-size:11px;">]] .. utils.html_escape(issuer) .. [[</code></td>
            <td style="text-align:right;">]] .. del_btn .. [[</td>
        </tr>
    ]]
end

local realms_tab_html = [[
    <div class="card" style="background:rgba(0,0,0,0.2);margin-bottom:20px;">
        <div class="card-header"><h3><i class="fa-solid fa-globe" style="margin-right:6px;color:var(--accent);"></i> Registered Realms</h3></div>
        <div class="card-body">
            <table>
                <thead><tr><th>Realm</th><th>Issuer Base</th><th style="text-align:right;">Actions</th></tr></thead>
                <tbody>]] .. realm_rows .. [[</tbody>
            </table>
        </div>
    </div>

    <div class="card" style="background:rgba(0,0,0,0.2);">
        <div class="card-header"><h3><i class="fa-solid fa-plus" style="margin-right:6px;color:var(--primary-hover);"></i> Create New Realm</h3></div>
        <div class="card-body">
            <p style="font-size:13px;color:var(--text-muted);margin-bottom:14px;">
                A new realm gets fully isolated users, clients, roles, groups, sessions-audit, keys, and policies — served instantly under its own URL path. The <code>master</code> realm keeps its existing data untouched.
            </p>
            <form method="POST" action="/admin/realm-settings?tab=realms">
                <input type="hidden" name="action" value="create_realm">
                ]] .. utils.render_security_fields(realm_admin_sec_token) .. [[
                <div class="form-group">
                    <label>Realm Name</label>
                    <input type="text" name="realm_name" placeholder="e.g. partners, internal-b2b" required pattern="[A-Za-z0-9][A-Za-z0-9\-_.]*" maxlength="48">
                </div>
                <button type="submit" class="btn btn-primary" onclick="return confirm('Create this realm?');"><i class="fa-solid fa-plus"></i> Create Realm</button>
            </form>
        </div>
    </div>
]]

local active_section_html = general_tab_html
if current_tab == "theme" then active_section_html = theme_tab_html
elseif current_tab == "updates" then active_section_html = updates_tab_html
elseif current_tab == "tokens" then active_section_html = tokens_tab_html
elseif current_tab == "security" then active_section_html = security_tab_html
elseif current_tab == "password_policy" then active_section_html = pwd_tab_html
elseif current_tab == "export_import" then active_section_html = export_tab_html
elseif current_tab == "policies" then active_section_html = policies_tab_html
elseif current_tab == "realms" then active_section_html = realms_tab_html
end

local content = msg_html .. [[
    <div class="tab-bar">
        <a href="/admin/realm-settings?tab=general" class="]] .. tab_class("general") .. [["><i class="fa-solid fa-sliders"></i> General</a>
        <a href="/admin/realm-settings?tab=theme" class="]] .. tab_class("theme") .. [["><i class="fa-solid fa-palette"></i> Branding & Theme</a>
        <a href="/admin/realm-settings?tab=tokens" class="]] .. tab_class("tokens") .. [["><i class="fa-solid fa-key"></i> Tokens & JWT</a>
        <a href="/admin/realm-settings?tab=security" class="]] .. tab_class("security") .. [["><i class="fa-solid fa-shield-halved"></i> Brute Force</a>
        <a href="/admin/realm-settings?tab=password_policy" class="]] .. tab_class("password_policy") .. [["><i class="fa-solid fa-scroll"></i> Password Policy</a>
        <a href="/admin/whitelist" class="tab-btn"><i class="fa-solid fa-list-check"></i> URI Whitelist</a>
        <a href="/admin/realm-settings?tab=policies" class="]] .. tab_class("policies") .. [["><i class="fa-solid fa-scale-balanced"></i> Realm Policies</a>
        <a href="/admin/realm-settings?tab=realms" class="]] .. tab_class("realms") .. [["><i class="fa-solid fa-globe"></i> Realms</a>
        <a href="/admin/realm-settings?tab=updates" class="]] .. tab_class("updates") .. [["><i class="fa-solid fa-cloud-arrow-up"></i> Updates & Legal</a>
        <a href="/admin/realm-settings?tab=export_import" class="]] .. tab_class("export_import") .. [["><i class="fa-solid fa-box-archive"></i> Export / Import</a>
    </div>

    <div class="card" style="max-width:780px;">
        <div class="card-body">
            ]] .. active_section_html .. [[
        </div>
    </div>
]]

response:write(utils.render_admin_page("Realm Settings", "realm-settings", admin_user, content))
