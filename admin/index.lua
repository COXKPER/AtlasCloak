local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local username, session_id = utils.get_session_user(db)
if not username or not utils.is_admin(db, username) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin", 302)
    return
end

-- Stats
local users_str = db:get("meta:user_list")
local users = users_str and json.decode(users_str) or {}
local user_count = #users

local sessions_str = db:get("meta:session_list")
local sessions = sessions_str and json.decode(sessions_str) or {}
local session_count = #sessions

local clients_str = db:get("meta:client_list")
local clients = clients_str and json.decode(clients_str) or { "account", "admin-console" }
local client_count = #clients

local groups = utils.get_groups(db)
local group_count = #groups

local events_str = db:get("meta:events")
local events = events_str and json.decode(events_str) or {}
local event_count = #events

local reg_enabled = utils.is_registration_enabled(db)

-- Recent events table
local event_rows = ""
for i = #events, math.max(1, #events - 7), -1 do
    local ev = events[i]
    local badge_cls = "badge-info"
    if ev.type == "LOGIN" or ev.type == "REGISTER" then badge_cls = "badge-success"
    elseif string.find(ev.type, "ERROR") or string.find(ev.type, "BLOCKED") or string.find(ev.type, "LOCKED") then badge_cls = "badge-danger"
    elseif string.find(ev.type, "UPDATE") or string.find(ev.type, "CONFIG") then badge_cls = "badge-warning"
    end
    
    local time_str = ev.time and utils.time_ago(ev.time) or "-"
    event_rows = event_rows .. [[
        <tr>
            <td><span class="badge ]] .. badge_cls .. [[">]] .. utils.html_escape(ev.type) .. [[</span></td>
            <td><strong>]] .. utils.html_escape(ev.username or "-") .. [[</strong></td>
            <td>]] .. utils.html_escape(ev.detail or "-") .. [[</td>
            <td><code>]] .. utils.html_escape(ev.ip or "-") .. [[</code></td>
            <td style="color:var(--text-muted);font-size:12px;">]] .. time_str .. [[</td>
        </tr>
    ]]
end

if #events == 0 then
    event_rows = '<tr><td colspan="5" class="empty-state"><p>No events recorded yet</p></td></tr>'
end

db:close()

local reg_status_badge = reg_enabled and '<span class="badge badge-success"><i class="fa-solid fa-circle-check"></i> Enabled</span>' or '<span class="badge badge-danger"><i class="fa-solid fa-ban"></i> Disabled</span>'

local content = [[
    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-icon stat-icon-users"><i class="fa-solid fa-users"></i></div>
            <div>
                <div class="stat-value">]] .. user_count .. [[</div>
                <div class="stat-label">Total Users</div>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon stat-icon-sessions"><i class="fa-solid fa-layer-group"></i></div>
            <div>
                <div class="stat-value">]] .. group_count .. [[</div>
                <div class="stat-label">User Groups</div>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon stat-icon-clients"><i class="fa-solid fa-cubes"></i></div>
            <div>
                <div class="stat-value">]] .. client_count .. [[</div>
                <div class="stat-label">OIDC Clients</div>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon stat-icon-events"><i class="fa-solid fa-clock-rotate-left"></i></div>
            <div>
                <div class="stat-value">]] .. event_count .. [[</div>
                <div class="stat-label">Audit Events</div>
            </div>
        </div>
    </div>

    <div style="display:grid;grid-template-columns: 2fr 1fr;gap:20px;">
        <div class="card">
            <div class="card-header">
                <h3><i class="fa-solid fa-list-check" style="margin-right:8px;"></i> Recent Audit Activity</h3>
                <a href="/admin/events" class="btn btn-sm btn-ghost">View All <i class="fa-solid fa-arrow-right"></i></a>
            </div>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Event</th>
                            <th>User</th>
                            <th>Details</th>
                            <th>IP</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        ]] .. event_rows .. [[
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3><i class="fa-solid fa-circle-info" style="margin-right:8px;"></i> Realm Quick Info</h3>
            </div>
            <div class="card-body" style="padding:16px;">
                <div style="display:flex;flex-direction:column;gap:14px;">
                    <div>
                        <div style="font-size:12px;color:var(--text-muted);">Current Realm</div>
                        <div style="font-weight:600;color:var(--text-heading);margin-top:2px;"><i class="fa-solid fa-shield-halved" style="color:var(--primary-hover);margin-right:4px;"></i> master</div>
                    </div>
                    <div>
                        <div style="font-size:12px;color:var(--text-muted);">Self-Registration</div>
                        <div style="margin-top:4px;">]] .. reg_status_badge .. [[</div>
                    </div>
                    <div>
                        <div style="font-size:12px;color:var(--text-muted);">Server Engine</div>
                        <div style="font-weight:500;color:var(--text);margin-top:2px;"><i class="fa-solid fa-server" style="margin-right:4px;"></i> Telamon (Go + Lua)</div>
                    </div>
                    <div style="border-top:1px solid var(--border);padding-top:14px;margin-top:4px;">
                        <a href="/admin/realm-settings" class="btn btn-primary" style="width:100%;font-size:13px;"><i class="fa-solid fa-sliders"></i> Configure Realm Settings</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
]]

response:write(utils.render_admin_page("Dashboard", "dashboard", username, content))
