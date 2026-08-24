local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/whitelist", 302)
    return
end

local msg_html = ""
local test_result_html = ""

if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local action = form.action or "save_whitelist"
    
    if action == "save_whitelist" then
        local enabled = (form.whitelist_enabled == "on" or form.whitelist_enabled == "true")
        local global_wl = form.global_whitelist or ""
        
        db:put("setting:whitelist_enabled", enabled and "true" or "false")
        db:put("setting:global_whitelist", global_wl)
        
        local event = {
            type = "WHITELIST_UPDATE",
            username = admin_user,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Updated URI Whitelist configuration (Enabled: " .. tostring(enabled) .. ")"
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
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-circle-check"></i></span> URI Whitelist configuration saved successfully!</div>'
        
    elseif action == "test_uri" then
        local test_client = form.test_client or ""
        local test_url = form.test_url or ""
        
        local ok, reason = utils.validate_redirect_uri(db, test_client, test_url)
        if ok then
            test_result_html = [[
                <div class="alert alert-success" style="margin-top:16px;">
                    <span class="alert-icon"><i class="fa-solid fa-circle-check"></i></span>
                    <div>
                        <strong>MATCH SUCCESS:</strong> The URI <code>]] .. utils.html_escape(test_url) .. [[</code> is <strong>ALLOWED</strong>.
                        <div style="font-size:12px;color:var(--text);margin-top:2px;">Reason: ]] .. utils.html_escape(reason or "Matched whitelist rules") .. [[</div>
                    </div>
                </div>
            ]]
        else
            test_result_html = [[
                <div class="alert alert-error" style="margin-top:16px;">
                    <span class="alert-icon"><i class="fa-solid fa-circle-xmark"></i></span>
                    <div>
                        <strong>MATCH BLOCKED:</strong> The URI <code>]] .. utils.html_escape(test_url) .. [[</code> is <strong>REJECTED</strong>.
                        <div style="font-size:12px;color:var(--text);margin-top:2px;">Reason: ]] .. utils.html_escape(reason or "Does not match any whitelist rules") .. [[</div>
                    </div>
                </div>
            ]]
        end
    end
end

-- Read current configuration
local is_enabled = utils.is_whitelist_enabled(db)
local global_whitelist = utils.get_global_whitelist(db)

-- Fetch registered clients
local clients_str = db:get("meta:client_list")
local client_list = clients_str and json.decode(clients_str) or { "account", "admin-console" }

local client_rows = ""
for _, cid in ipairs(client_list) do
    local cdata_str = db:get("client:" .. cid)
    local cdata = cdata_str and json.decode(cdata_str) or { client_id = cid, name = cid, redirect_uris = "/*" }
    local uris = cdata.redirect_uris or "/*"
    
    local badge = '<span class="badge badge-info">' .. utils.html_escape(cdata.client_type or "public") .. '</span>'
    
    client_rows = client_rows .. [[
        <tr>
            <td><strong>]] .. utils.html_escape(cdata.name or cid) .. [[</strong><br><code style="font-size:11px;">]] .. utils.html_escape(cid) .. [[</code></td>
            <td>]] .. badge .. [[</td>
            <td><code style="font-size:12px;">]] .. utils.html_escape(uris) .. [[</code></td>
            <td style="text-align:right;">
                <a href="/admin/clients" class="btn btn-sm btn-secondary"><i class="fa-solid fa-pen-to-square"></i> Edit Client</a>
            </td>
        </tr>
    ]]
end

db:close()

local status_banner = ""
if is_enabled then
    status_banner = [[
        <div style="display:flex;align-items:center;justify-content:space-between;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:12px;padding:14px 20px;margin-bottom:24px;">
            <div style="display:flex;align-items:center;gap:12px;">
                <i class="fa-solid fa-shield-check" style="font-size:24px;color:var(--success);"></i>
                <div>
                    <strong style="color:var(--success);">Strict Whitelisting Active</strong>
                    <div style="font-size:12px;color:var(--text-muted);">Only redirect URIs matching registered clients or global patterns are permitted.</div>
                </div>
            </div>
            <span class="badge badge-success">ENFORCING</span>
        </div>
    ]]
else
    status_banner = [[
        <div style="display:flex;align-items:center;justify-content:space-between;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:12px;padding:14px 20px;margin-bottom:24px;">
            <div style="display:flex;align-items:center;gap:12px;">
                <i class="fa-solid fa-triangle-exclamation" style="font-size:24px;color:var(--warning);"></i>
                <div>
                    <strong style="color:var(--warning);">Permissive Mode Active (Whitelist Disabled)</strong>
                    <div style="font-size:12px;color:var(--text-muted);">All redirect URIs are currently accepted. Recommended for local development and testing only.</div>
                </div>
            </div>
            <span class="badge badge-warning">PERMISSIVE</span>
        </div>
    ]]
end

local content = msg_html .. status_banner .. [[
    <div style="display:grid;grid-template-columns: 3fr 2fr;gap:24px;">
        <!-- Left Column: Settings Form -->
        <div>
            <div class="card">
                <div class="card-header">
                    <h3><i class="fa-solid fa-list-check" style="margin-right:6px;"></i> Whitelist Configuration</h3>
                </div>
                <div class="card-body">
                    <form method="POST" action="/admin/whitelist">
                        <input type="hidden" name="action" value="save_whitelist">
                        
                        <div class="toggle-row" style="padding:0 0 16px 0;margin-bottom:16px;border-bottom:1px solid var(--border);">
                            <div>
                                <div class="toggle-label"><strong>Enforce Redirect URI Whitelist</strong></div>
                                <div class="toggle-desc">Turn off to allow all redirect URIs (Permissive Mode for testing)</div>
                            </div>
                            <label class="toggle">
                                <input type="checkbox" name="whitelist_enabled" ]] .. (is_enabled and "checked" or "") .. [[>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                        
                        <div class="form-group">
                            <label>Global Whitelist Patterns (One per line)</label>
                            <textarea name="global_whitelist" id="global_whitelist" rows="6" style="font-family:'JetBrains Mono',monospace;font-size:13px;" placeholder="http://localhost:*&#10;https://oidcdebugger.com/*&#10;https://oauth.pstmn.io/*">]] .. utils.html_escape(global_whitelist) .. [[</textarea>
                            <small style="color:var(--text-muted);font-size:11px;">
                                Supports wildcard prefix matching (e.g. <code>http://localhost:*</code> matches any port and path).
                            </small>
                        </div>
                        
                        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px;">
                            <button type="button" class="btn btn-sm btn-secondary" onclick="addPattern('http://localhost:*')">+ localhost</button>
                            <button type="button" class="btn btn-sm btn-secondary" onclick="addPattern('http://127.0.0.1:*')">+ 127.0.0.1</button>
                            <button type="button" class="btn btn-sm btn-secondary" onclick="addPattern('https://oidcdebugger.com/*')">+ OIDC Debugger</button>
                            <button type="button" class="btn btn-sm btn-secondary" onclick="addPattern('https://oauth.pstmn.io/*')">+ Postman</button>
                        </div>
                        
                        <button type="submit" class="btn btn-primary" style="width:auto;"><i class="fa-solid fa-floppy-disk"></i> Save Whitelist Settings</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Right Column: Interactive URI Matcher Simulator -->
        <div>
            <div class="card">
                <div class="card-header">
                    <h3><i class="fa-solid fa-vial" style="margin-right:6px;"></i> Live URI Matcher Tool</h3>
                </div>
                <div class="card-body">
                    <p style="font-size:12px;color:var(--text-muted);margin-bottom:14px;">
                        Test whether a redirect URI will be accepted or rejected under the current whitelist rules.
                    </p>
                    <form method="POST" action="/admin/whitelist">
                        <input type="hidden" name="action" value="test_uri">
                        <div class="form-group">
                            <label>Client ID</label>
                            <input type="text" name="test_client" placeholder="e.g. test, account, my-app" value="test">
                        </div>
                        <div class="form-group">
                            <label>Test Redirect URI</label>
                            <input type="text" name="test_url" placeholder="https://myapp.com/callback" value="http://localhost:3000/callback" required>
                        </div>
                        <button type="submit" class="btn btn-secondary" style="width:100%;"><i class="fa-solid fa-magnifying-glass"></i> Test URI Matching</button>
                    </form>
                    
                    ]] .. test_result_html .. [[
                </div>
            </div>
        </div>
    </div>

    <!-- Client-Specific Whitelists Table -->
    <div class="card" style="margin-top:24px;">
        <div class="card-header">
            <h3><i class="fa-solid fa-cubes" style="margin-right:6px;"></i> Client-Specific Redirect URIs</h3>
            <a href="/admin/clients" class="btn btn-sm btn-secondary"><i class="fa-solid fa-plus"></i> Manage Clients</a>
        </div>
        <div style="overflow-x:auto;">
            <table>
                <thead>
                    <tr>
                        <th>Client</th>
                        <th>Type</th>
                        <th>Registered Redirect URIs</th>
                        <th style="text-align:right;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ]] .. client_rows .. [[
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function addPattern(pat) {
            var ta = document.getElementById('global_whitelist');
            if (ta.value.indexOf(pat) === -1) {
                ta.value = (ta.value.trim() + '\n' + pat).trim();
            }
        }
    </script>
]]

response:write(utils.render_admin_page("URI Whitelist", "whitelist", admin_user, content))
