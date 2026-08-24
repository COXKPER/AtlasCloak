local utils = dofile("public/lib/utils.lua")

local client_id = request:getParam("client_id")
local redirect_uri = request:getParam("redirect_uri")
local state = request:getParam("state")
local response_type = request:getParam("response_type")
if not response_type or response_type == "" then response_type = "code" end

local response_mode = request:getParam("response_mode")
if not response_mode or response_mode == "" then response_mode = "query" end

local nonce = request:getParam("nonce")
local scope = request:getParam("scope")
if not scope or scope == "" then scope = "openid profile email" end

local code_challenge = request:getParam("code_challenge")
local code_challenge_method = request:getParam("code_challenge_method")
if not code_challenge_method or code_challenge_method == "" then code_challenge_method = "S256" end

local db = utils.get_db()
utils.ensure_admin_exists(db)

-- K5: Validate redirect_uri strictly against registered client / whitelist
if redirect_uri and redirect_uri ~= "" then
    local uri_ok, uri_err = utils.validate_redirect_uri(db, client_id or "account", redirect_uri)
    if not uri_ok then
        db:close()
        response:setStatus(400)
        local content = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-triangle-exclamation"></i></span> <strong>Invalid Redirect URI:</strong> ' .. utils.html_escape(uri_err or "The redirect_uri is not authorized") .. '</div>' ..
                        '<a href="/" class="btn btn-secondary"><i class="fa-solid fa-house"></i> Return Home</a>'
        response:write(utils.render_auth_page("Invalid Request", "Authorization Error", content))
        return
    end
end

-- Check session cookie
local user, _ = utils.get_session_user(db)

if not user then
    local error_msg = request:getParam("error")
    local alert_html = ""
    if error_msg and error_msg ~= "" then
        if string.find(error_msg, "successful") or string.find(error_msg, "Success") then
            alert_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-check"></i></span> ' .. utils.html_escape(error_msg) .. '</div>'
        else
            alert_html = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-triangle-exclamation"></i></span> ' .. utils.html_escape(error_msg) .. '</div>'
        end
    end

    local action_url = "/auth/realms/master/login-actions/authenticate?client_id=" .. utils.url_encode(client_id or "") .. 
                       "&redirect_uri=" .. utils.url_encode(redirect_uri or "") .. 
                       "&state=" .. utils.url_encode(state or "") .. 
                       "&response_type=" .. utils.url_encode(response_type) .. 
                       "&response_mode=" .. utils.url_encode(response_mode) .. 
                       "&nonce=" .. utils.url_encode(nonce or "") .. 
                       "&scope=" .. utils.url_encode(scope) .. 
                       "&code_challenge=" .. utils.url_encode(code_challenge or "") .. 
                       "&code_challenge_method=" .. utils.url_encode(code_challenge_method or "S256")

    local reg_enabled = utils.is_registration_enabled(db)
    local sec_token = utils.generate_security_token(db, "login")
    db:close()

    local reg_link = ""
    if reg_enabled then
        reg_link = [[
        <div class="footer-links">
            New user? <a href="/auth/realms/master/login-actions/registration?client_id=]] .. utils.url_encode(client_id or "") .. [[&redirect_uri=]] .. utils.url_encode(redirect_uri or "") .. [[&state=]] .. utils.url_encode(state or "") .. [[">Register</a>
        </div>
        ]]
    end

    local content = alert_html .. [[
        <form method="POST" action="]] .. action_url .. [[">
            ]] .. utils.render_security_fields(sec_token) .. [[
            <div class="form-group">
                <label>Username or email</label>
                <input type="text" name="username" placeholder="Enter your username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter your password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-arrow-right-to-bracket"></i> Sign In</button>
        </form>
        ]] .. reg_link

    response:write(utils.render_auth_page("Sign In", "Sign in to your account", content))
    return
end

local prompt = request:getParam("prompt")

-- Check if client requires Consent Screen
if client_id and client_id ~= "" and client_id ~= "account" and client_id ~= "admin-console" then
    local need_consent = false
    if prompt == "consent" then
        need_consent = true
    elseif utils.is_consent_required(db, client_id) and not utils.has_user_consented(db, user, client_id) then
        need_consent = true
    end
    
    if need_consent then
        local cdata_str = db:get("client:" .. client_id)
        local cdata = cdata_str and json.decode(cdata_str) or { name = client_id }
        local client_name = cdata.name or client_id
        
        local sec_token = utils.generate_security_token(db, "consent")
        db:close()
        
        local consent_url = "/auth/realms/master/protocol/openid-connect/consent?client_id=" .. utils.url_encode(client_id) .. 
                            "&redirect_uri=" .. utils.url_encode(redirect_uri or "") .. 
                            "&state=" .. utils.url_encode(state or "") .. 
                            "&response_type=" .. utils.url_encode(response_type) .. 
                            "&response_mode=" .. utils.url_encode(response_mode) .. 
                            "&nonce=" .. utils.url_encode(nonce or "") .. 
                            "&scope=" .. utils.url_encode(scope) .. 
                            "&code_challenge=" .. utils.url_encode(code_challenge or "") .. 
                            "&code_challenge_method=" .. utils.url_encode(code_challenge_method or "")
        
        local content = [[
            <div style="text-align:center;margin-bottom:20px;">
                <div style="font-size:14px;color:var(--text);margin-bottom:8px;">
                    <strong>]] .. utils.html_escape(client_name) .. [[</strong> is requesting access to your account.
                </div>
                <div style="font-size:12px;color:var(--text-muted);">
                    Signed in as <strong>]] .. utils.html_escape(user) .. [[</strong>
                </div>
            </div>
            
            <div style="background:rgba(0,0,0,0.2);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:20px;">
                <div style="font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;">Permissions Requested</div>
                <ul style="padding-left:20px;font-size:13px;color:var(--text);display:flex;flex-direction:column;gap:6px;">
                    <li>Access your basic profile information</li>
                    <li>Verify your identity and email address</li>
                    <li>Read your assigned realm roles</li>
                </ul>
            </div>
            
            <form method="POST" action="]] .. consent_url .. [[">
                ]] .. utils.render_security_fields(sec_token) .. [[
                <div style="display:flex;gap:10px;">
                    <button type="submit" name="decision" value="accept" class="btn btn-primary"><i class="fa-solid fa-check"></i> Grant Access</button>
                    <button type="submit" name="decision" value="deny" class="btn btn-secondary">Deny</button>
                </div>
            </form>
        ]]
        
        response:write(utils.render_auth_page("Authorize Application", "Grant Permissions", content))
        return
    end
end

-- User is authenticated and consented. Process response_type & response_mode
if redirect_uri and redirect_uri ~= "" then
    local params_out = {}
    local roles = utils.get_user_roles(db, user)
    
    -- Handle response_type (code, token, id_token)
    if string.find(response_type, "code") then
        local code = utils.uuid()
        local code_data = {
            username = user,
            client_id = client_id,
            redirect_uri = redirect_uri,
            code_challenge = code_challenge,
            code_challenge_method = code_challenge_method,
            nonce = nonce,
            scope = scope,
            created = os.time()
        }
        db:put("code:" .. code, json.encode(code_data))
        params_out["code"] = code
    end
    
    if string.find(response_type, "token") then
        local access_token, _, lifespan = utils.issue_token(db, user, client_id, scope, roles, false)
        params_out["access_token"] = access_token
        params_out["token_type"] = "Bearer"
        params_out["expires_in"] = tostring(lifespan)
    end
    
    if string.find(response_type, "id_token") then
        local id_token = utils.issue_id_token(db, user, client_id, nonce)
        params_out["id_token"] = id_token
    end
    
    if state and state ~= "" then
        params_out["state"] = state
    end
    
    db:close()

    -- 1. Response Mode: form_post (OAuth 2.0 Form Post Response Mode)
    if response_mode == "form_post" then
        local form_inputs = ""
        for k, v in pairs(params_out) do
            form_inputs = form_inputs .. '<input type="hidden" name="' .. utils.html_escape(k) .. '" value="' .. utils.html_escape(v) .. '"/>\n'
        end
        
        local html_form_post = [[<!DOCTYPE html>
<html>
<head>
    <title>Submit Form</title>
</head>
<body onload="javascript:document.forms[0].submit()">
    <noscript>
        <p>JavaScript is disabled. Click the button below to continue.</p>
    </noscript>
    <form method="post" action="]] .. utils.html_escape(redirect_uri) .. [[">
        ]] .. form_inputs .. [[
        <noscript>
            <input type="submit" value="Continue"/>
        </noscript>
    </form>
</body>
</html>]]
        response:write(html_form_post)
        return
        
    -- 2. Response Mode: fragment (Implicit / Hybrid flows)
    elseif response_mode == "fragment" or (string.find(response_type, "token") and response_mode ~= "query") then
        local frag_parts = {}
        for k, v in pairs(params_out) do
            table.insert(frag_parts, utils.url_encode(k) .. "=" .. utils.url_encode(v))
        end
        local redirect_to = redirect_uri .. "#" .. table.concat(frag_parts, "&")
        response:redirect(redirect_to, 302)
        return
        
    -- 3. Response Mode: query (Standard authorization code flow)
    else
        local query_parts = {}
        for k, v in pairs(params_out) do
            table.insert(query_parts, utils.url_encode(k) .. "=" .. utils.url_encode(v))
        end
        local sep = string.find(redirect_uri, "?") and "&" or "?"
        local redirect_to = redirect_uri .. sep .. table.concat(query_parts, "&")
        response:redirect(redirect_to, 302)
        return
    end
else
    db:close()
    response:redirect("/account", 302)
end
