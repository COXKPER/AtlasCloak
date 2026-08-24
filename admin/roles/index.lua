local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/roles", 302)
    return
end

local msg_html = ""

-- Handle Delete Role
local delete_role = request:getParam("delete")
if delete_role and delete_role ~= "" then
    if delete_role == "admin" or delete_role == "user" then
        msg_html = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-triangle-exclamation"></i></span> Cannot delete default system roles.</div>'
    else
        utils.delete_role(db, delete_role)
        local event = {
            type = "ROLE_DELETE",
            username = admin_user,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Deleted role: " .. delete_role
        }
        local events_str = db:get("meta:events")
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put("meta:events", json.encode(events))
        
        db:close()
        response:redirect("/admin/roles", 302)
        return
    end
end

-- Handle Add Role POST
if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local role_name = string.lower(form.role_name or "")
    local role_desc = form.role_description or ""
    
    if role_name == "" or not string.match(role_name, "^[a-z0-9%-_]+$") then
        msg_html = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-triangle-exclamation"></i></span> Role name must contain only lowercase letters, digits, dashes, and underscores.</div>'
    else
        utils.add_role(db, role_name, role_desc)
        local event = {
            type = "ROLE_CREATE",
            username = admin_user,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Created custom role: " .. role_name
        }
        local events_str = db:get("meta:events")
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put("meta:events", json.encode(events))
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-check"></i></span> Role <strong>' .. utils.html_escape(role_name) .. '</strong> created!</div>'
    end
end

local roles = utils.get_roles(db)
local users_str = db:get("meta:user_list")
local user_list = users_str and json.decode(users_str) or {}

-- Count users per role
local role_counts = {}
for _, r in ipairs(roles) do role_counts[r] = 0 end

for _, uname in ipairs(user_list) do
    local u_roles = utils.get_user_roles(db, uname)
    for _, ur in ipairs(u_roles) do
        role_counts[ur] = (role_counts[ur] or 0) + 1
    end
end

local rows = ""
for _, rname in ipairs(roles) do
    local rdet = utils.get_role_details(db, rname)
    local is_builtin = (rname == "admin" or rname == "user")
    local type_badge = is_builtin and '<span class="badge badge-success"><i class="fa-solid fa-lock"></i> Built-in</span>' or '<span class="badge badge-warning"><i class="fa-solid fa-tag"></i> Custom</span>'
    local u_count = role_counts[rname] or 0
    
    local actions = ""
    if is_builtin then
        actions = '<span style="font-size:12px;color:var(--text-muted);">Protected</span>'
    else
        actions = '<a href="/admin/roles?delete=' .. utils.url_encode(rname) .. '" class="btn btn-sm btn-danger" onclick="return confirm(\'Delete role ' .. rname .. '?\')"><i class="fa-solid fa-trash"></i> Delete</a>'
    end
    
    rows = rows .. [[
        <tr>
            <td><strong><code><i class="fa-solid fa-user-shield" style="margin-right:6px;color:var(--warning);"></i>]] .. utils.html_escape(rname) .. [[</code></strong></td>
            <td>]] .. utils.html_escape(rdet.description or "-") .. [[</td>
            <td>]] .. type_badge .. [[</td>
            <td><span class="badge badge-info"><i class="fa-solid fa-users"></i> ]] .. u_count .. [[ users</span></td>
            <td style="text-align:right;">]] .. actions .. [[</td>
        </tr>
    ]]
end

db:close()

local content = msg_html .. [[
    <div style="display:grid;grid-template-columns: 2fr 1fr;gap:20px;">
        <div class="card">
            <div class="card-header">
                <div style="display:flex;align-items:center;gap:12px;">
                    <h3>Realm Roles (RBAC)</h3>
                    <span class="badge badge-info">]] .. #roles .. [[ Roles</span>
                </div>
            </div>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Role Name</th>
                            <th>Description</th>
                            <th>Type</th>
                            <th>Assigned</th>
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
                <h3>➕ Create New Role</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/roles">
                    <div class="form-group">
                        <label>Role Name *</label>
                        <input type="text" name="role_name" placeholder="e.g. billing_admin, editor" required>
                        <small style="color:var(--text-muted);font-size:11px;">Lowercase alphanumeric, hyphens, and underscores.</small>
                    </div>
                    <div class="form-group">
                        <label>Description</label>
                        <textarea name="role_description" rows="3" placeholder="Brief description of permissions granted by this role"></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:100%;margin-top:8px;"><i class="fa-solid fa-plus"></i> Save Role</button>
                </form>
            </div>
        </div>
    </div>
]]

response:write(utils.render_admin_page("Role-Based Access Control", "roles", admin_user, content))
