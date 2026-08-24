local utils = dofile("public/lib/utils.lua")

-- Auto-forward OIDC Authorization requests hitting root '/' to the official OIDC Auth Endpoint
local client_id = request:getParam("client_id")
local response_type = request:getParam("response_type")
local redirect_uri = request:getParam("redirect_uri")

if (client_id and client_id ~= "") or (response_type and response_type ~= "") or (redirect_uri and redirect_uri ~= "") then
    local qs_parts = {}
    local params = {
        "client_id", "redirect_uri", "response_type", "response_mode", 
        "scope", "state", "nonce", "code_challenge", "code_challenge_method"
    }
    for _, p in ipairs(params) do
        local v = request:getParam(p)
        if v and v ~= "" then
            table.insert(qs_parts, p .. "=" .. utils.url_encode(v))
        end
    end
    local target = "/auth/realms/master/protocol/openid-connect/auth"
    if #qs_parts > 0 then
        target = target .. "?" .. table.concat(qs_parts, "&")
    end
    response:redirect(target, 302)
    return
end

local db = utils.get_db()
utils.ensure_admin_exists(db)

-- Check if logged in
local username, _ = utils.get_session_user(db)
db:close()

local login_section = ""
if username then
    login_section = [[
        <div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-circle-check"></i></span> Signed in as <strong>]] .. utils.html_escape(username) .. [[</strong></div>
        <a href="/account" class="btn btn-primary" style="margin-bottom:10px;"><i class="fa-solid fa-user"></i> My Account</a>
        <a href="/admin" class="btn btn-secondary" style="width:100%;"><i class="fa-solid fa-sliders"></i> Admin Console</a>
    ]]
else
    login_section = [[
        <a href="/auth/realms/master/protocol/openid-connect/auth?client_id=account&redirect_uri=/account" class="btn btn-primary" style="margin-bottom:10px;"><i class="fa-solid fa-arrow-right-to-bracket"></i> Sign In</a>
    ]]
end

local content = [[
    ]] .. login_section .. [[
    <div class="divider">or explore</div>
    <div style="display:flex;flex-direction:column;gap:8px;">
        <a href="/auth/realms/master/.well-known/openid-configuration" class="btn btn-secondary">
            <i class="fa-solid fa-file-code" style="color:var(--primary-hover);"></i> OpenID Configuration
        </a>
        <a href="/admin" class="btn btn-secondary">
            <i class="fa-solid fa-sliders" style="color:var(--accent);"></i> Admin Console
        </a>
    </div>
]]

response:write(utils.render_auth_page("AtlasCloak", "Identity & Access Management", content))
