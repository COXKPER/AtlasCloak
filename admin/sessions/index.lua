local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, current_session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=admin-console&redirect_uri=/admin/sessions", 302)
    return
end

-- Action: Revoke single session
local revoke_id = request:getParam("revoke")
if revoke_id and revoke_id ~= "" then
    local sess_user = db:get("session:" .. revoke_id)
    db:delete("session:" .. revoke_id)
    db:delete("session_data:" .. revoke_id)
    
    local sessions_str = db:get("meta:session_list")
    if sessions_str then
        local sessions = json.decode(sessions_str)
        local new_sessions = {}
        for _, sid in ipairs(sessions) do
            if sid ~= revoke_id then table.insert(new_sessions, sid) end
        end
        db:put("meta:session_list", json.encode(new_sessions))
    end
    
    local event = {
        type = "SESSION_REVOKE",
        username = admin_user,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Revoked session: " .. string.sub(revoke_id, 1, 8) .. "... (" .. (sess_user or "unknown") .. ")"
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    db:close()
    response:redirect("/admin/sessions", 302)
    return
end

-- Action: Revoke all other sessions
local revoke_others = request:getParam("revoke_others")
if revoke_others == "true" and current_session_id then
    local sessions_str = db:get("meta:session_list")
    if sessions_str then
        local sessions = json.decode(sessions_str)
        local new_sessions = { current_session_id }
        for _, sid in ipairs(sessions) do
            if sid ~= current_session_id then
                db:delete("session:" .. sid)
                db:delete("session_data:" .. sid)
            end
        end
        db:put("meta:session_list", json.encode(new_sessions))
    end
    
    local event = {
        type = "SESSION_REVOKE_ALL",
        username = admin_user,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Revoked all other active sessions"
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    db:close()
    response:redirect("/admin/sessions", 302)
    return
end

-- Fetch and clean valid sessions
local sessions_str = db:get("meta:session_list")
local session_ids = sessions_str and json.decode(sessions_str) or {}

local valid_sessions = {}
local rows = ""
local count = 0
local other_count = 0

for _, sid in ipairs(session_ids) do
    local s_user = db:get("session:" .. sid)
    if s_user then
        table.insert(valid_sessions, sid)
        count = count + 1
        
        local s_data_str = db:get("session_data:" .. sid)
        local s_data = s_data_str and json.decode(s_data_str) or {}
        local is_current = (sid == current_session_id)
        
        if not is_current then
            other_count = other_count + 1
        end
        
        local status_badge = is_current and '<span class="badge badge-success"><i class="fa-solid fa-circle-check"></i> Current</span>' or '<span class="badge badge-info"><i class="fa-solid fa-signal"></i> Active</span>'
        local action_btn = is_current and '<a href="/admin/logout" class="btn btn-sm btn-danger"><i class="fa-solid fa-right-from-bracket"></i> Sign Out</a>' or '<a href="/admin/sessions?revoke=' .. sid .. '" class="btn btn-sm btn-secondary" onclick="return confirm(\'Revoke session ' .. string.sub(sid, 1, 8) .. '...?\')"><i class="fa-solid fa-ban"></i> Revoke</a>'
        
        local started = s_data.started and utils.time_ago(s_data.started) or "Active"
        local ip = s_data.ip or "Unknown IP"
        
        rows = rows .. [[
            <tr ]] .. (is_current and 'style="background:rgba(99,102,241,0.06);"' or '') .. [[>
                <td><code>]] .. string.sub(sid, 1, 8) .. [[...</code></td>
                <td><strong>]] .. utils.html_escape(s_user) .. [[</strong></td>
                <td><code>]] .. utils.html_escape(ip) .. [[</code></td>
                <td>]] .. started .. [[</td>
                <td>]] .. status_badge .. [[</td>
                <td style="text-align:right;">]] .. action_btn .. [[</td>
            </tr>
        ]]
    end
end

-- Sync cleaned sessions in metadata if some were pruned
if #valid_sessions ~= #session_ids then
    db:put("meta:session_list", json.encode(valid_sessions))
end

db:close()

if count == 0 then
    rows = '<tr><td colspan="6" class="empty-state"><div class="icon"><i class="fa-solid fa-link-slash"></i></div><p>No active user sessions</p></td></tr>'
end

local revoke_all_btn = ""
if other_count > 0 then
    revoke_all_btn = '<a href="/admin/sessions?revoke_others=true" class="btn btn-sm btn-danger" onclick="return confirm(\'Revoke all ' .. other_count .. ' other active sessions?\')"><i class="fa-solid fa-ban"></i> Revoke Other Sessions (' .. other_count .. ')</a>'
end

local content = [[
    <div class="card">
        <div class="card-header">
            <div style="display:flex;align-items:center;gap:12px;">
                <h3>Active User Sessions</h3>
                <span class="badge badge-info">]] .. count .. [[ Total</span>
            </div>
            <div>
                ]] .. revoke_all_btn .. [[
            </div>
        </div>
        <div style="overflow-x:auto;">
            <table>
                <thead>
                    <tr>
                        <th>Session</th>
                        <th>User</th>
                        <th>IP Address</th>
                        <th>Started</th>
                        <th>Status</th>
                        <th style="text-align:right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    ]] .. rows .. [[
                </tbody>
            </table>
        </div>
    </div>
]]

response:write(utils.render_admin_page("Active Sessions", "sessions", admin_user, content))
