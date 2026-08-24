local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local username, session_id = utils.get_session_user(db)
if not username then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=account&redirect_uri=/account", 302)
    return
end

local user_data_str = db:get("user:" .. username)
local user_data = user_data_str and json.decode(user_data_str) or { username = username }

local msg_html = ""

-- Handle Revoke App Consent
local revoke_client = request:getParam("revoke_consent")
if revoke_client and revoke_client ~= "" then
    db:delete("consent:" .. username .. ":" .. revoke_client)
    local event = {
        type = "CONSENT_REVOKE",
        username = username,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "User revoked consent for application: " .. revoke_client
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    msg_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-circle-check"></i></span> Revoked access for application <strong>' .. utils.html_escape(revoke_client) .. '</strong>. Next authorization request will prompt for consent.</div>'
end

if request.method == "POST" then
    local form = utils.parse_form(request.body)
    user_data.firstName = form.firstName or ""
    user_data.lastName = form.lastName or ""
    user_data.email = form.email or ""
    
    db:put("user:" .. username, json.encode(user_data))
    
    local event = {
        type = "UPDATE_PROFILE",
        username = username,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "User updated profile information"
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
    
    msg_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-circle-check"></i></span> Your personal information has been updated.</div>'
end

-- Find all clients this user has consented to
local clients_str = db:get("meta:client_list")
local client_list = clients_str and json.decode(clients_str) or { "account", "admin-console", "test", "m2m-service" }

local app_rows = ""
local app_count = 0
for _, cid in ipairs(client_list) do
    if cid ~= "account" and cid ~= "admin-console" and utils.has_user_consented(db, username, cid) then
        app_count = app_count + 1
        local cdata_str = db:get("client:" .. cid)
        local cdata = cdata_str and json.decode(cdata_str) or { name = cid }
        local cname = cdata.name or cid
        
        app_rows = app_rows .. [[
            <tr>
                <td><strong>]] .. utils.html_escape(cname) .. [[</strong> <small style="color:var(--text-muted);"> (<code>]] .. utils.html_escape(cid) .. [[</code>)</small></td>
                <td><span class="badge badge-success"><i class="fa-solid fa-circle-check"></i> Granted</span></td>
                <td style="text-align:right;">
                    <a href="/account?revoke_consent=]] .. utils.url_encode(cid) .. [[" class="btn btn-sm btn-danger" onclick="return confirm('Revoke access for this application?')"><i class="fa-solid fa-ban"></i> Revoke Access</a>
                </td>
            </tr>
        ]]
    end
end

db:close()

local apps_section = ""
if app_count > 0 then
    apps_section = [[
        <div class="card" style="max-width:680px;margin-top:24px;">
            <div class="card-header">
                <h3><i class="fa-solid fa-shield-halved" style="margin-right:6px;"></i> Authorized Third-Party Applications</h3>
                <span class="badge badge-info">]] .. app_count .. [[ Apps</span>
            </div>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Application</th>
                            <th>Status</th>
                            <th style="text-align:right;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ]] .. app_rows .. [[
                    </tbody>
                </table>
            </div>
        </div>
    ]]
end

local content = msg_html .. [[
    <div class="card" style="max-width:680px;">
        <div class="card-header">
            <h3><i class="fa-solid fa-user-pen" style="margin-right:6px;"></i> Personal Information</h3>
        </div>
        <div class="card-body">
            <form method="POST" action="/account">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" value="]] .. utils.html_escape(user_data.username or "") .. [[" disabled style="background:rgba(255,255,255,0.03);color:var(--text-muted);">
                    <small style="color:var(--text-muted);font-size:11px;">Username cannot be changed</small>
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="text" name="email" value="]] .. utils.html_escape(user_data.email or "") .. [[" required>
                </div>
                <div class="row-2">
                    <div class="form-group">
                        <label>First Name</label>
                        <input type="text" name="firstName" value="]] .. utils.html_escape(user_data.firstName or "") .. [[">
                    </div>
                    <div class="form-group">
                        <label>Last Name</label>
                        <input type="text" name="lastName" value="]] .. utils.html_escape(user_data.lastName or "") .. [[">
                    </div>
                </div>
                <div style="margin-top:8px;">
                    <button type="submit" class="btn btn-primary" style="width:auto;"><i class="fa-solid fa-floppy-disk"></i> Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    ]] .. apps_section .. [[
]]

response:write(utils.render_account_page("Personal Info", "profile", user_data, content))
