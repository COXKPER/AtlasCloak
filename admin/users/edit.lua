local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/users", 302)
    return
end

local target_username = request:getParam("username") or ""
local user_data_str = db:get("user:" .. target_username)

if not user_data_str then
    db:close()
    response:redirect("/admin/users", 302)
    return
end

local user_data = json.decode(user_data_str)
local msg_html = ""

-- Handle Unlock Account
local action_param = request:getParam("action")
if action_param == "unlock" then
    utils.unlock_account(db, target_username)
    local event = {
        type = "ACCOUNT_UNLOCKED",
        username = admin_user,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Admin unlocked account: " .. target_username
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    db:close()
    response:redirect("/admin/users/edit?username=" .. utils.url_encode(target_username), 302)
    return
end

if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local action = form.action or "update"
    
    if action == "update" then
        user_data.email = form.email or ""
        user_data.firstName = form.firstName or ""
        user_data.lastName = form.lastName or ""
        
        if target_username ~= "admin" then
            user_data.enabled = (form.enabled == "on" or form.enabled == "true")
            
            -- Multi-role parsing from form
            local all_roles = utils.get_roles(db)
            local selected_roles = {}
            for _, r in ipairs(all_roles) do
                if form["role_" .. r] == "on" or form["role_" .. r] == "true" then
                    table.insert(selected_roles, r)
                end
            end
            if #selected_roles == 0 then table.insert(selected_roles, "user") end
            utils.set_user_roles(db, target_username, selected_roles)
            
            -- Groups parsing from form
            local all_groups = utils.get_groups(db)
            local selected_groups = {}
            for _, g in ipairs(all_groups) do
                if form["group_" .. g] == "on" or form["group_" .. g] == "true" then
                    table.insert(selected_groups, g)
                end
            end
            utils.set_user_groups(db, target_username, selected_groups)
        end
        
        db:put("user:" .. target_username, json.encode(user_data))
        
        local event = {
            type = "USER_UPDATE",
            username = admin_user,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Admin updated user details & memberships: " .. target_username
        }
        local events_str = db:get("meta:events")
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put("meta:events", json.encode(events))
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-check"></i></span> User details, roles, and groups updated.</div>'
        
    elseif action == "reset_password" then
        local new_pw = form.newPassword or ""
        local pw_ok, pw_err = utils.validate_password_policy(db, new_pw)
        if not pw_ok then
            msg_html = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-triangle-exclamation"></i></span> ' .. utils.html_escape(pw_err) .. '</div>'
        else
            user_data.password = utils.hash_password(new_pw)
            db:put("user:" .. target_username, json.encode(user_data))
            
            local event = {
                type = "PASSWORD_RESET",
                username = admin_user,
                ip = utils.get_client_ip(),
                time = os.time(),
                detail = "Admin reset password for user: " .. target_username
            }
            local events_str = db:get("meta:events")
            local events = events_str and json.decode(events_str) or {}
            table.insert(events, event)
            db:put("meta:events", json.encode(events))
            
            msg_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-check"></i></span> Password has been reset for ' .. utils.html_escape(target_username) .. '.</div>'
        end
    end
end

local is_enabled = (user_data.enabled ~= false)
local enabled_checked = is_enabled and "checked" or ""

-- Check Lockout Status
local is_locked, lock_remaining = utils.check_account_locked(db, target_username)
local lock_status_html = ""
if is_locked then
    local mins = math.ceil(lock_remaining / 60)
    lock_status_html = [[
        <div class="alert alert-error" style="justify-content:space-between;">
            <div>
                <strong><i class="fa-solid fa-lock"></i> Account Locked:</strong> Brute force lockout active (~]] .. mins .. [[ min remaining).
            </div>
            <a href="/admin/users/edit?username=]] .. utils.url_encode(target_username) .. [[&action=unlock" class="btn btn-sm btn-warning"><i class="fa-solid fa-lock-open"></i> Unlock Now</a>
        </div>
    ]]
end

-- Render Role Checkboxes
local all_roles = utils.get_roles(db)
local direct_roles = db:get("user_roles:" .. target_username) and json.decode(db:get("user_roles:" .. target_username)) or { "user" }
local direct_role_set = {}
for _, r in ipairs(direct_roles) do direct_role_set[r] = true end

local role_checkboxes = ""
for _, r in ipairs(all_roles) do
    local checked = direct_role_set[r] and "checked" or ""
    local disabled = (target_username == "admin" and r == "admin") and "disabled" or ""
    role_checkboxes = role_checkboxes .. [[
        <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:8px;border:1px solid var(--border);">
            <input type="checkbox" name="role_]] .. r .. [[" ]] .. checked .. [[ ]] .. disabled .. [[ style="width:16px;height:16px;">
            <span><code>]] .. utils.html_escape(r) .. [[</code></span>
        </label>
    ]]
end

-- Render Group Checkboxes
local all_groups = utils.get_groups(db)
local user_groups = utils.get_user_groups(db, target_username)
local user_group_set = {}
for _, g in ipairs(user_groups) do user_group_set[g] = true end

local group_checkboxes = ""
for _, g in ipairs(all_groups) do
    local checked = user_group_set[g] and "checked" or ""
    local gdet = utils.get_group_details(db, g)
    local r_str = gdet.roles and table.concat(gdet.roles, ", ") or ""
    group_checkboxes = group_checkboxes .. [[
        <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:8px;border:1px solid var(--border);">
            <input type="checkbox" name="group_]] .. g .. [[" ]] .. checked .. [[ style="width:16px;height:16px;">
            <div>
                <strong><i class="fa-solid fa-layer-group" style="color:var(--primary-hover);margin-right:4px;"></i>]] .. utils.html_escape(g) .. [[</strong>
                <div style="font-size:11px;color:var(--text-muted);">Inherits: ]] .. utils.html_escape(r_str) .. [[</div>
            </div>
        </label>
    ]]
end

db:close()

local content = msg_html .. lock_status_html .. [[
    <div style="display:grid;grid-template-columns: 2fr 1fr;gap:20px;">
        <div class="card">
            <div class="card-header">
                <h3>Edit User: ]] .. utils.html_escape(target_username) .. [[</h3>
                <a href="/admin/users" class="btn btn-sm btn-ghost"><i class="fa-solid fa-arrow-left"></i> Back to Users</a>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/users/edit?username=]] .. utils.url_encode(target_username) .. [[">
                    <input type="hidden" name="action" value="update">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" value="]] .. utils.html_escape(target_username) .. [[" disabled style="background:rgba(255,255,255,0.03);color:var(--text-muted);">
                    </div>
                    <div class="form-group">
                        <label>Email Address</label>
                        <input type="text" name="email" value="]] .. utils.html_escape(user_data.email or "") .. [[">
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
                    
                    <div class="form-group">
                        <label>Direct Realm Roles (RBAC)</label>
                        <div style="display:grid;grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));gap:8px;margin-top:6px;">
                            ]] .. role_checkboxes .. [[
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Group Memberships (GBAC - Automatic Role Inheritance)</label>
                        <div style="display:grid;grid-template-columns: 1fr;gap:8px;margin-top:6px;">
                            ]] .. (group_checkboxes ~= "" and group_checkboxes or '<span style="font-size:12px;color:var(--text-muted);">No groups created yet</span>') .. [[
                        </div>
                    </div>

                    <div style="margin:20px 0 24px;">
                        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:14px;color:var(--text);">
                            <input type="checkbox" name="enabled" ]] .. enabled_checked .. [[ ]] .. (target_username == "admin" and "disabled" or "") .. [[ style="width:18px;height:18px;">
                            <span>Account Enabled</span>
                        </label>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:auto;"><i class="fa-solid fa-floppy-disk"></i> Save Changes</button>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3>Reset Password</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/users/edit?username=]] .. utils.url_encode(target_username) .. [[">
                    <input type="hidden" name="action" value="reset_password">
                    <div class="form-group">
                        <label>New Password</label>
                        <input type="password" name="newPassword" placeholder="Enter new password" required>
                    </div>
                    <button type="submit" class="btn btn-warning" style="width:100%;"><i class="fa-solid fa-key"></i> Reset Password</button>
                </form>
            </div>
        </div>
    </div>
]]

response:write(utils.render_admin_page("Edit User", "users", admin_user, content))
