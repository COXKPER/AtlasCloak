local utils = dofile("public/lib/utils.lua")

local raw_redirect = request:getParam("post_logout_redirect_uri") or request:getParam("redirect_uri") or "/"
local client_id = request:getParam("client_id")
local db = utils.get_db()

-- K5: Validate post_logout_redirect_uri
local redirect_uri = "/"
if raw_redirect and raw_redirect ~= "" and raw_redirect ~= "/" then
    local uri_ok, _ = utils.validate_redirect_uri(db, client_id or "account", raw_redirect)
    if uri_ok then
        redirect_uri = raw_redirect
    end
end

local username, session_id = utils.get_session_user(db)
if session_id then
    db:delete("session:" .. session_id)
    db:delete("session_data:" .. session_id)
    
    -- Remove from session list
    local sessions_str = db:get("meta:session_list")
    if sessions_str then
        local sessions = json.decode(sessions_str)
        local new_sessions = {}
        for _, sid in ipairs(sessions) do
            if sid ~= session_id then
                table.insert(new_sessions, sid)
            end
        end
        db:put("meta:session_list", json.encode(new_sessions))
    end
    
    if username then
        local event = {
            type = "LOGOUT",
            username = username,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "User logged out"
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
    end
end
db:close()

utils.redirect(redirect_uri, "ATLAS_SESSION=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly")
