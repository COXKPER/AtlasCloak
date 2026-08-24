local utils = dofile("public/lib/utils.lua")

if request.method ~= "POST" then
    response:setStatus(405)
    response:write("Method Not Allowed")
    return
end

local client_id = request:getParam("client_id")
local redirect_uri = request:getParam("redirect_uri") or ""
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
local user, _ = utils.get_session_user(db)

if not user then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=" .. utils.url_encode(client_id or "") .. 
                      "&redirect_uri=" .. utils.url_encode(redirect_uri) .. 
                      "&state=" .. utils.url_encode(state or ""), 302)
    return
end

local form = utils.parse_form(request.body)
local ok, err = utils.validate_security_token(db, form, "consent")

if not ok then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=" .. utils.url_encode(client_id or "") .. 
                      "&redirect_uri=" .. utils.url_encode(redirect_uri) .. 
                      "&state=" .. utils.url_encode(state or "") .. 
                      "&error=" .. utils.url_encode(err or "Security token validation failed"), 302)
    return
end

local decision = form.decision or "deny"

if decision == "accept" then
    utils.save_user_consent(db, user, client_id)
    
    local event = {
        type = "CONSENT_GRANT",
        username = user,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "User granted consent for client: " .. (client_id or "")
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    if #events > 100 then
        local trimmed = {}
        for i = #events - 99, #events do table.insert(trimmed, events[i]) end
        events = trimmed
    end
    db:put("meta:events", json.encode(events))
    
    local params_out = {}
    local roles = utils.get_user_roles(db, user)
    
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
    elseif response_mode == "fragment" or (string.find(response_type, "token") and response_mode ~= "query") then
        local frag_parts = {}
        for k, v in pairs(params_out) do
            table.insert(frag_parts, utils.url_encode(k) .. "=" .. utils.url_encode(v))
        end
        local redirect_to = redirect_uri .. "#" .. table.concat(frag_parts, "&")
        response:redirect(redirect_to, 302)
        return
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
    -- Deny path: respect existing query string and URL-encode state (R5)
    local sep = string.find(redirect_uri, "?") and "&" or "?"
    local redirect_to = redirect_uri .. sep .. "error=access_denied&error_description=User+denied+consent"
    if state and state ~= "" then
        redirect_to = redirect_to .. "&state=" .. utils.url_encode(state)
    end
    response:redirect(redirect_to, 302)
    return
end
