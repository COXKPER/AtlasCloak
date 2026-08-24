local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/users/new", 302)
    return
end

local msg_html = ""

if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local username = form.username or ""
    local password = form.password or ""
    local email = form.email or ""
    local firstName = form.firstName or ""
    local lastName = form.lastName or ""
    local enabled = (form.enabled == "on" or form.enabled == "true")
    
    local pw_ok, pw_err = utils.validate_password_policy(db, password)
    
    if username == "" or password == "" then
        msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Username and password are required.</div>'
    elseif not pw_ok then
        msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(pw_err) .. '</div>'
    elseif db:get("user:" .. username) then
        msg_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> Username already exists.</div>'
    else
        local user_data = {
            username = username,
            password = utils.hash_password(password),
            email = email,
            firstName = firstName,
            lastName = lastName,
            enabled = enabled,
            createdAt = os.time()
        }
        db:put("user:" .. username, json.encode(user_data))
        
        -- Multi-role parsing
        local all_roles = utils.get_roles(db)
        local selected_roles = {}
        for _, r in ipairs(all_roles) do
            if form["role_" .. r] == "on" or form["role_" .. r] == "true" then
                table.insert(selected_roles, r)
            end
        end
        if #selected_roles == 0 then table.insert(selected_roles, "user") end
        utils.set_user_roles(db, username, selected_roles)
        
        local user_list_str = db:get("meta:user_list")
        local user_list = user_list_str and json.decode(user_list_str) or {}
        table.insert(user_list, username)
        db:put("meta:user_list", json.encode(user_list))
        
        local event = {
            type = "USER_CREATE",
            username = admin_user,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Admin created new user: " .. username .. " (Roles: " .. table.concat(selected_roles, ", ") .. ")"
        }
        local events_str = db:get("meta:events")
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put("meta:events", json.encode(events))
        
        db:close()
        response:redirect("/admin/users", 302)
        return
    end
end

local all_roles = utils.get_roles(db)
local role_checkboxes = ""
for _, r in ipairs(all_roles) do
    local checked = (r == "user") and "checked" or ""
    role_checkboxes = role_checkboxes .. [[
        <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:8px;border:1px solid var(--border);">
            <input type="checkbox" name="role_]] .. r .. [[" ]] .. checked .. [[ style="width:16px;height:16px;">
            <span><code>]] .. utils.html_escape(r) .. [[</code></span>
        </label>
    ]]
end

local policy = utils.get_password_policy(db)
db:close()

local content = msg_html .. [[
    <div class="card" style="max-width:600px;">
        <div class="card-header">
            <h3>Create New User</h3>
            <a href="/admin/users" class="btn btn-sm btn-ghost">← Back to Users</a>
        </div>
        <div class="card-body">
            <form method="POST" action="/admin/users/new">
                <div class="form-group">
                    <label>Username *</label>
                    <input type="text" name="username" placeholder="johndoe" required>
                </div>
                <div class="form-group">
                    <label>Temporary Password *</label>
                    <input type="password" name="password" placeholder="Min ]] .. policy.min_length .. [[ characters" required>
                </div>
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="text" name="email" placeholder="john@example.com">
                </div>
                <div class="row-2">
                    <div class="form-group">
                        <label>First Name</label>
                        <input type="text" name="firstName" placeholder="John">
                    </div>
                    <div class="form-group">
                        <label>Last Name</label>
                        <input type="text" name="lastName" placeholder="Doe">
                    </div>
                </div>
                <div class="form-group">
                    <label>Assigned Realm Roles</label>
                    <div style="display:grid;grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));gap:8px;margin-top:6px;">
                        ]] .. role_checkboxes .. [[
                    </div>
                </div>
                <div style="margin-bottom:20px;">
                    <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:14px;color:var(--text);">
                        <input type="checkbox" name="enabled" checked style="width:18px;height:18px;">
                        <span>User Enabled</span>
                    </label>
                </div>
                <div style="display:flex;gap:10px;">
                    <button type="submit" class="btn btn-primary" style="width:auto;">Create User</button>
                    <a href="/admin/users" class="btn btn-secondary">Cancel</a>
                </div>
            </form>
        </div>
    </div>
]]

response:write(utils.render_admin_page("Add User", "users", admin_user, content))
