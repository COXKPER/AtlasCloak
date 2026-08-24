local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/events", 302)
    return
end

-- Clear events action
local action = request:getParam("action")
if action == "clear" then
    db:delete("meta:events")
    db:close()
    response:redirect("/admin/events", 302)
    return
end

local type_filter = request:getParam("type") or ""

local events_str = db:get("meta:events")
local events = events_str and json.decode(events_str) or {}
db:close()

local rows = ""
local count = 0
for i = #events, 1, -1 do
    local ev = events[i]
    if type_filter == "" or ev.type == type_filter then
        count = count + 1
        local badge_cls = "badge-info"
        if ev.type == "LOGIN" or ev.type == "REGISTER" or ev.type == "CONSENT_GRANT" then badge_cls = "badge-success"
        elseif string.find(ev.type, "ERROR") or string.find(ev.type, "DELETE") or string.find(ev.type, "BLOCKED") or string.find(ev.type, "LOCKED") then badge_cls = "badge-danger"
        elseif string.find(ev.type, "UPDATE") or string.find(ev.type, "CONFIG") or string.find(ev.type, "RESET") or string.find(ev.type, "REVOKE") then badge_cls = "badge-warning"
        end
        
        local time_str = ev.time and os.date("%Y-%m-%d %H:%M:%S", ev.time) or "-"
        local rel_time = ev.time and utils.time_ago(ev.time) or ""
        
        rows = rows .. [[
            <tr>
                <td><span class="badge ]] .. badge_cls .. [[">]] .. utils.html_escape(ev.type) .. [[</span></td>
                <td><strong>]] .. utils.html_escape(ev.username or "-") .. [[</strong></td>
                <td>]] .. utils.html_escape(ev.detail or "-") .. [[</td>
                <td><code>]] .. utils.html_escape(ev.ip or "-") .. [[</code></td>
                <td>
                    <div>]] .. time_str .. [[</div>
                    <div style="font-size:11px;color:var(--text-muted);">]] .. rel_time .. [[</div>
                </td>
            </tr>
        ]]
    end
end

if count == 0 then
    rows = '<tr><td colspan="5" class="empty-state"><div class="icon"><i class="fa-solid fa-clock-rotate-left"></i></div><p>No audit events recorded</p></td></tr>'
end

local content = [[
    <div class="card">
        <div class="card-header">
            <div style="display:flex;align-items:center;gap:12px;">
                <h3><i class="fa-solid fa-clock-rotate-left" style="margin-right:6px;"></i> Audit Events Log</h3>
                <span class="badge badge-info">]] .. count .. [[ Events</span>
            </div>
            <div style="display:flex;gap:10px;">
                <form method="GET" action="/admin/events" style="display:flex;gap:6px;">
                    <select name="type" onchange="this.form.submit()" style="padding:6px 12px;font-size:13px;border-radius:8px;background:var(--bg-input);border:1px solid var(--border);color:var(--text);">
                        <option value="">All Event Types</option>
                        <option value="LOGIN" ]] .. (type_filter == "LOGIN" and "selected" or "") .. [[>LOGIN</option>
                        <option value="LOGIN_ERROR" ]] .. (type_filter == "LOGIN_ERROR" and "selected" or "") .. [[>LOGIN_ERROR</option>
                        <option value="REGISTER" ]] .. (type_filter == "REGISTER" and "selected" or "") .. [[>REGISTER</option>
                        <option value="CODE_TO_TOKEN" ]] .. (type_filter == "CODE_TO_TOKEN" and "selected" or "") .. [[>CODE_TO_TOKEN</option>
                        <option value="USER_CREATE" ]] .. (type_filter == "USER_CREATE" and "selected" or "") .. [[>USER_CREATE</option>
                        <option value="USER_UPDATE" ]] .. (type_filter == "USER_UPDATE" and "selected" or "") .. [[>USER_UPDATE</option>
                        <option value="USER_DELETE" ]] .. (type_filter == "USER_DELETE" and "selected" or "") .. [[>USER_DELETE</option>
                        <option value="TOKEN_REVOKE" ]] .. (type_filter == "TOKEN_REVOKE" and "selected" or "") .. [[>TOKEN_REVOKE</option>
                        <option value="REALM_CONFIG_UPDATE" ]] .. (type_filter == "REALM_CONFIG_UPDATE" and "selected" or "") .. [[>REALM_CONFIG_UPDATE</option>
                    </select>
                </form>
                <a href="/admin/events?action=clear" class="btn btn-sm btn-danger" onclick="return confirm('Clear all audit logs?')"><i class="fa-solid fa-trash"></i> Clear Logs</a>
            </div>
        </div>
        <div style="overflow-x:auto;">
            <table>
                <thead>
                    <tr>
                        <th>Event Type</th>
                        <th>User</th>
                        <th>Details</th>
                        <th>IP Address</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    ]] .. rows .. [[
                </tbody>
            </table>
        </div>
    </div>
]]

response:write(utils.render_admin_page("Audit Events", "events", admin_user, content))
