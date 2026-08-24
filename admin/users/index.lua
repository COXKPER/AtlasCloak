local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/users", 302)
    return
end

-- Handle Delete User action
local delete_username = request:getParam("delete")
if delete_username and delete_username ~= "" and delete_username ~= "admin" then
    db:delete("user:" .. delete_username)
    db:delete("role:" .. delete_username)
    
    local users_str = db:get("meta:user_list")
    if users_str then
        local users = json.decode(users_str)
        local new_users = {}
        for _, u in ipairs(users) do
            if u ~= delete_username then table.insert(new_users, u) end
        end
        db:put("meta:user_list", json.encode(new_users))
    end
    
    local event = {
        type = "USER_DELETE",
        username = admin_user,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Deleted user: " .. delete_username
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    db:close()
    response:redirect("/admin/users", 302)
    return
end

-- Handle Toggle Enable/Disable User action
local toggle_user = request:getParam("toggle")
if toggle_user and toggle_user ~= "" and toggle_user ~= "admin" then
    local udata_str = db:get("user:" .. toggle_user)
    if udata_str then
        local udata = json.decode(udata_str)
        udata.enabled = not (udata.enabled ~= false)
        db:put("user:" .. toggle_user, json.encode(udata))
        
        local event = {
            type = "USER_UPDATE",
            username = admin_user,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = (udata.enabled and "Enabled" or "Disabled") .. " user: " .. toggle_user
        }
        local events_str = db:get("meta:events")
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put("meta:events", json.encode(events))
    end
    db:close()
    response:redirect("/admin/users", 302)
    return
end

-- Search filter
local search_query = string.lower(request:getParam("search") or "")

local users_str = db:get("meta:user_list")
local user_list = users_str and json.decode(users_str) or { "admin" }

local rows = ""
local count = 0

for _, uname in ipairs(user_list) do
    local udata_str = db:get("user:" .. uname)
    if udata_str then
        local udata = json.decode(udata_str)
        local match = true
        if search_query ~= "" then
            local un = string.lower(udata.username or "")
            local em = string.lower(udata.email or "")
            local fn = string.lower(udata.firstName or "")
            local ln = string.lower(udata.lastName or "")
            if not string.find(un, search_query, 1, true) and 
               not string.find(em, search_query, 1, true) and
               not string.find(fn, search_query, 1, true) and
               not string.find(ln, search_query, 1, true) then
                match = false
            end
        end
        
        if match then
            count = count + 1
            local u_roles = utils.get_user_roles(db, uname)
            local role_badges = ""
            for _, r in ipairs(u_roles) do
                local b_cls = (r == "admin") and "badge-warning" or "badge-info"
                role_badges = role_badges .. '<span class="badge ' .. b_cls .. '" style="margin-right:4px;">' .. utils.html_escape(r) .. '</span>'
            end
            
            local is_enabled = (udata.enabled ~= false)
            local is_locked, _ = utils.check_account_locked(db, uname)
            
            local status_badge = is_enabled and '<span class="badge badge-success">Enabled</span>' or '<span class="badge badge-danger">Disabled</span>'
            if is_locked then
                status_badge = '<span class="badge badge-danger" title="Brute force locked">🔒 Locked</span>'
            end
            
            local toggle_text = is_enabled and "Disable" or "Enable"
            local toggle_cls = is_enabled and "btn-danger" or "btn-success"
            
            local actions = '<a href="/admin/users/edit?username=' .. utils.url_encode(uname) .. '" class="btn btn-sm btn-secondary">Edit</a> '
            if uname ~= "admin" then
                actions = actions .. '<a href="/admin/users?toggle=' .. utils.url_encode(uname) .. '" class="btn btn-sm ' .. toggle_cls .. '">' .. toggle_text .. '</a> '
                actions = actions .. '<a href="/admin/users?delete=' .. utils.url_encode(uname) .. '" class="btn btn-sm btn-danger" onclick="return confirm(\'Delete user ' .. uname .. '?\')">Delete</a>'
            end
            
            local full_name = (udata.firstName or "") .. " " .. (udata.lastName or "")
            if full_name == " " then full_name = "-" end
            local created_str = udata.createdAt and utils.time_ago(udata.createdAt) or "-"
            
            rows = rows .. [[
                <tr>
                    <td><strong>]] .. utils.html_escape(udata.username or "") .. [[</strong></td>
                    <td>]] .. utils.html_escape(udata.email or "-") .. [[</td>
                    <td>]] .. utils.html_escape(full_name) .. [[</td>
                    <td><div style="display:flex;flex-wrap:wrap;gap:2px;">]] .. role_badges .. [[</div></td>
                    <td>]] .. status_badge .. [[</td>
                    <td>]] .. created_str .. [[</td>
                    <td style="text-align:right;">]] .. actions .. [[</td>
                </tr>
            ]]
        end
    end
end

db:close()

if count == 0 then
    rows = '<tr><td colspan="7" class="empty-state"><div class="icon">👥</div><p>No users found</p></td></tr>'
end

local content = [[
    <div class="card">
        <div class="card-header">
            <div style="display:flex;align-items:center;gap:12px;">
                <h3>Users</h3>
                <span class="badge badge-info">]] .. count .. [[ Total</span>
            </div>
            <div style="display:flex;gap:10px;">
                <form method="GET" action="/admin/users" style="display:flex;gap:6px;">
                    <input type="text" name="search" value="]] .. utils.html_escape(search_query) .. [[" placeholder="Search users..." style="padding:6px 12px;font-size:13px;border-radius:8px;background:var(--bg-input);border:1px solid var(--border);color:var(--text);">
                    <button type="submit" class="btn btn-sm btn-secondary">Search</button>
                </form>
                <a href="/admin/users/new" class="btn btn-sm btn-primary">➕ Add User</a>
            </div>
        </div>
        <div style="overflow-x:auto;">
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Name</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th style="text-align:right;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ]] .. rows .. [[
                </tbody>
            </table>
        </div>
    </div>
]]

response:write(utils.render_admin_page("User Management", "users", admin_user, content))
