local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local admin_user, session_id = utils.get_session_user(db)
if not admin_user or not utils.is_admin(db, admin_user) then
    db:close()
    response:setStatus(401)
    response:json({ error = "unauthorized" })
    return
end

local export_data = utils.export_realm_data(db)
db:close()

response:setHeader("Content-Disposition", 'attachment; filename="atlascloak-realm-export.json"')
response:json(export_data)
