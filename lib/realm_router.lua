-- AtlasCloak multi-realm router stub.
-- Route stubs under public/auth/realms/<name>/... relay execution into the
-- shared master implementation. The implementation derives the active realm
-- from the request path (utils.get_realm()), so a single copy of each
-- endpoint serves every realm.

local M = {}

function M.relay(rel_path)
    return dofile("public/auth/realms/master/" .. rel_path .. ".lua")
end

return M
