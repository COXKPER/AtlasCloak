local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/clients", 302)
    return
end

local msg_html = ""

-- Handle Delete Client
local delete_client = request:getParam("delete")
if delete_client and delete_client ~= "" and delete_client ~= "account" and delete_client ~= "admin-console" then
    db:delete("client:" .. delete_client)
    local clients_str = db:get("meta:client_list")
    if clients_str then
        local clients = json.decode(clients_str)
        local new_clients = {}
        for _, c in ipairs(clients) do
            if c ~= delete_client then table.insert(new_clients, c) end
        end
        db:put("meta:client_list", json.encode(new_clients))
    end
    db:close()
    response:redirect("/admin/clients", 302)
    return
end

-- Handle Add Client POST
if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local client_id = form.client_id or ""
    local client_name = form.client_name or ""
    -- Fail closed: empty redirect_uris means the client has no allowed URIs
    local redirect_uris = (form.redirect_uris or ""):gsub("^%s+", ""):gsub("%s+$", "")
    local client_type = form.client_type or "confidential"
    local consent_required = (form.consent_required == "on" or form.consent_required == "true")
    
    if client_id == "" then
        msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Client ID is required.</div>'
    elseif db:get("client:" .. client_id) then
        msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Client ID already exists.</div>'
    else
        local client_secret = utils.uuid()
        local cdata = {
            client_id = client_id,
            name = client_name,
            redirect_uris = redirect_uris,
            client_type = client_type,
            secret = client_secret,
            consent_required = consent_required,
            enabled = true,
            createdAt = os.time()
        }
        db:put("client:" .. client_id, json.encode(cdata))
        
        local clients_str = db:get("meta:client_list")
        local clients = clients_str and json.decode(clients_str) or { "account", "admin-console" }
        table.insert(clients, client_id)
        db:put("meta:client_list", json.encode(clients))
        
        local event = {
            type = "CLIENT_CREATE",
            username = admin_user,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Created client: " .. client_id .. " (Type: " .. client_type .. ")"
        }
        local events_str = db:get("meta:events")
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put("meta:events", json.encode(events))
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Client <strong>' .. utils.html_escape(client_id) .. '</strong> created! Secret: <code>' .. client_secret .. '</code></div>'
    end
end

-- Ensure default clients exist in metadata
local clients_str = db:get("meta:client_list")
local client_list = clients_str and json.decode(clients_str) or { "account", "admin-console" }

local rows = ""
for _, cid in ipairs(client_list) do
    local cdata_str = db:get("client:" .. cid)
    local cdata = cdata_str and json.decode(cdata_str) or {
        client_id = cid,
        name = (cid == "account" and "Account Management" or "Admin Console"),
        redirect_uris = (cid == "account" and "/account/*" or "/admin/*"),
        client_type = "public"
    }
    
    local is_builtin = (cid == "account" or cid == "admin-console")
    local type_badge = (cdata.client_type == "confidential") and '<span class="badge badge-warning">Confidential</span>' or '<span class="badge badge-info">Public</span>'
    local consent_badge = cdata.consent_required and '<span class="badge badge-success">Consent On</span>' or '<span class="badge badge-info" style="opacity:0.6;">Consent Off</span>'
    
    local secret_display = "-"
    if cdata.client_type == "confidential" and cdata.secret then
        secret_display = '<code>' .. string.sub(cdata.secret, 1, 8) .. '...</code>'
    end
    
    local actions = ""
    if is_builtin then
        actions = '<span class="badge badge-success">System Client</span>'
    else
        actions = '<a href="/admin/clients?delete=' .. utils.url_encode(cid) .. '" class="btn btn-sm btn-danger" onclick="return confirm(\'Delete client ' .. cid .. '?\')">Delete</a>'
    end
    
    rows = rows .. [[
        <tr>
            <td><strong><code>]] .. utils.html_escape(cid) .. [[</code></strong></td>
            <td>]] .. utils.html_escape(cdata.name or "-") .. [[</td>
            <td>]] .. type_badge .. [[</td>
            <td>]] .. consent_badge .. [[</td>
            <td>]] .. secret_display .. [[</td>
            <td><code>]] .. utils.html_escape(cdata.redirect_uris or "") .. [[</code></td>
            <td style="text-align:right;">]] .. actions .. [[</td>
        </tr>
    ]]
end

db:close()

local content = msg_html .. [[
    <div style="display:grid;grid-template-columns: 2fr 1fr;gap:20px;">
        <div class="card">
            <div class="card-header">
                <h3>OpenID Connect & M2M Clients</h3>
                <span class="badge badge-info">]] .. #client_list .. [[ Clients</span>
            </div>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Client ID</th>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Consent</th>
                            <th>Secret</th>
                            <th>Redirect URIs</th>
                            <th style="text-align:right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ]] .. rows .. [[
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3>➕ Create Client</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/clients">
                    <div class="form-group">
                        <label>Client ID *</label>
                        <input type="text" name="client_id" placeholder="e.g. backend-service, mobile-app" required>
                    </div>
                    <div class="form-group">
                        <label>Client Name</label>
                        <input type="text" name="client_name" placeholder="My Application">
                    </div>
                    <div class="form-group">
                        <label>Valid Redirect URIs</label>
                        <input type="text" name="redirect_uris" placeholder="http://localhost:3000/callback" value="">
                    </div>
                    <div class="form-group">
                        <label>Client Access Type</label>
                        <select name="client_type" style="width:100%;padding:10px 14px;background:var(--bg-input);border:1px solid var(--border);border-radius:10px;color:var(--text);">
                            <option value="confidential">Confidential (Requires Secret & M2M)</option>
                            <option value="public">Public (SPA / Frontend App)</option>
                        </select>
                    </div>
                    <div style="margin:16px 0;">
                        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:13px;color:var(--text);">
                            <input type="checkbox" name="consent_required" style="width:18px;height:18px;">
                            <span>Require User Consent Screen</span>
                        </label>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:100%;margin-top:8px;">Save Client</button>
                </form>
            </div>
        </div>
    </div>
]]

response:write(utils.render_admin_page("Clients", "clients", admin_user, content))
