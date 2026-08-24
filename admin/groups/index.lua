local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/groups", 302)
    return
end

local msg_html = ""

-- Handle Delete Group
local delete_group = request:getParam("delete")
if delete_group and delete_group ~= "" then
    utils.delete_group(db, delete_group)
    local event = {
        type = "GROUP_DELETE",
        username = admin_user,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Deleted group: " .. delete_group
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    db:close()
    response:redirect("/admin/groups", 302)
    return
end

-- Handle Add Group POST
if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local group_name = string.lower(form.group_name or "")
    local group_desc = form.group_description or ""
    
    if group_name == "" or not string.match(group_name, "^[a-z0-9%-_]+$") then
        msg_html = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-triangle-exclamation"></i></span> Group name must contain only lowercase letters, digits, dashes, and underscores.</div>'
    else
        local all_roles = utils.get_roles(db)
        local assigned_roles = {}
        for _, r in ipairs(all_roles) do
            if form["role_" .. r] == "on" or form["role_" .. r] == "true" then
                table.insert(assigned_roles, r)
            end
        end
        if #assigned_roles == 0 then table.insert(assigned_roles, "user") end
        
        utils.save_group(db, group_name, group_desc, assigned_roles)
        
        local event = {
            type = "GROUP_CREATE",
            username = admin_user,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Created group: " .. group_name .. " with roles: " .. table.concat(assigned_roles, ", ")
        }
        local events_str = db:get("meta:events")
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put("meta:events", json.encode(events))
        
        msg_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-check"></i></span> Group <strong>' .. utils.html_escape(group_name) .. '</strong> created!</div>'
    end
end

local groups = utils.get_groups(db)
local users_str = db:get("meta:user_list")
local user_list = users_str and json.decode(users_str) or {}

-- Count members per group
local group_member_counts = {}
for _, g in ipairs(groups) do group_member_counts[g] = 0 end

for _, uname in ipairs(user_list) do
    local u_grps = utils.get_user_groups(db, uname)
    for _, ug in ipairs(u_grps) do
        group_member_counts[ug] = (group_member_counts[ug] or 0) + 1
    end
end

local rows = ""
for _, gname in ipairs(groups) do
    local gdet = utils.get_group_details(db, gname)
    local mem_count = group_member_counts[gname] or 0
    
    local role_badges = ""
    if gdet.roles and #gdet.roles > 0 then
        for _, gr in ipairs(gdet.roles) do
            local b_cls = (gr == "admin") and "badge-warning" or "badge-info"
            role_badges = role_badges .. '<span class="badge ' .. b_cls .. '" style="margin-right:4px;">' .. utils.html_escape(gr) .. '</span>'
        end
    else
        role_badges = '<span style="font-size:12px;color:var(--text-muted);">None</span>'
    end
    
    local actions = '<a href="/admin/groups?delete=' .. utils.url_encode(gname) .. '" class="btn btn-sm btn-danger" onclick="return confirm(\'Delete group ' .. gname .. '?\')"><i class="fa-solid fa-trash"></i> Delete</a>'
    
    rows = rows .. [[
        <tr>
            <td><strong><code><i class="fa-solid fa-layer-group" style="margin-right:6px;color:var(--primary-hover);"></i>]] .. utils.html_escape(gname) .. [[</code></strong></td>
            <td>]] .. utils.html_escape(gdet.description or "-") .. [[</td>
            <td><div style="display:flex;flex-wrap:wrap;gap:2px;">]] .. role_badges .. [[</div></td>
            <td><span class="badge badge-info"><i class="fa-solid fa-users"></i> ]] .. mem_count .. [[ members</span></td>
            <td style="text-align:right;">]] .. actions .. [[</td>
        </tr>
    ]]
end

local all_roles = utils.get_roles(db)
local role_checkboxes = ""
for _, r in ipairs(all_roles) do
    role_checkboxes = role_checkboxes .. [[
        <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:8px;border:1px solid var(--border);">
            <input type="checkbox" name="role_]] .. r .. [[" style="width:16px;height:16px;">
            <span><code>]] .. utils.html_escape(r) .. [[</code></span>
        </label>
    ]]
end

db:close()

if #groups == 0 then
    rows = '<tr><td colspan="5" class="empty-state"><div class="icon"><i class="fa-solid fa-layer-group"></i></div><p>No user groups defined yet</p></td></tr>'
end

local content = msg_html .. [[
    <div style="display:grid;grid-template-columns: 2fr 1fr;gap:20px;">
        <div class="card">
            <div class="card-header">
                <div style="display:flex;align-items:center;gap:12px;">
                    <h3>User Groups & Role Inheritance (GBAC)</h3>
                    <span class="badge badge-info">]] .. #groups .. [[ Groups</span>
                </div>
            </div>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Group Name</th>
                            <th>Description</th>
                            <th>Inherited Roles</th>
                            <th>Members</th>
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
                <h3>➕ Create New Group</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/groups">
                    <div class="form-group">
                        <label>Group Name *</label>
                        <input type="text" name="group_name" placeholder="e.g. devops, finance, engineering" required>
                        <small style="color:var(--text-muted);font-size:11px;">Lowercase letters, numbers, and hyphens.</small>
                    </div>
                    <div class="form-group">
                        <label>Description</label>
                        <textarea name="group_description" rows="2" placeholder="Purpose and department of this group"></textarea>
                    </div>
                    <div class="form-group">
                        <label>Roles Inherited by Members</label>
                        <div style="display:grid;grid-template-columns: 1fr 1fr;gap:8px;margin-top:6px;">
                            ]] .. role_checkboxes .. [[
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:100%;margin-top:8px;"><i class="fa-solid fa-plus"></i> Save Group</button>
                </form>
            </div>
        </div>
    </div>
]]

response:write(utils.render_admin_page("User Groups (GBAC)", "groups", admin_user, content))
