local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
local username, session_id = utils.get_session_user(db)
if session_id then
    db:delete("session:" .. session_id)
    db:delete("session_data:" .. session_id)
    
    local sessions_str = db:get("meta:session_list")
    if sessions_str then
        local sessions = json.decode(sessions_str)
        local new_sessions = {}
        for _, sid in ipairs(sessions) do
            if sid ~= session_id then table.insert(new_sessions, sid) end
        end
        db:put("meta:session_list", json.encode(new_sessions))
    end
end
db:close()

utils.redirect("/", "ATLAS_SESSION=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly")
