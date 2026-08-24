local utils = dofile("public/lib/utils.lua")

if request.method ~= "POST" then
    response:setStatus(405)
    response:json({ error = "method_not_allowed" })
    return
end

local form = utils.parse_form(request.body)
local grant_type = form.grant_type

local db = utils.get_db()
utils.ensure_admin_exists(db)

-- Parse Client Credentials from form or HTTP Basic Authorization header
local client_id = form.client_id
local client_secret = form.client_secret

local auth_hdr = request.headers["authorization"]
if auth_hdr and string.match(auth_hdr, "^[Bb]asic%s+(.+)$") then
    local b64_creds = string.match(auth_hdr, "^[Bb]asic%s+(.+)$")
    local raw_creds = utils.base64_decode(b64_creds)
    local cid, csec = string.match(raw_creds, "([^:]+):?(.*)")
    if cid then
        client_id = cid
        client_secret = csec
    end
end

-- 1. Client Credentials Grant (M2M / Machine-to-Machine)
if grant_type == "client_credentials" then
    if not client_id or client_id == "" then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_client", error_description = "client_id is required" })
        return
    end
    
    local cdata_str = db:get("client:" .. client_id)
    if not cdata_str then
        db:close()
        response:setStatus(401)
        response:json({ error = "invalid_client", error_description = "Client not found" })
        return
    end
    
    local cdata = json.decode(cdata_str)
    if cdata.client_type == "confidential" and cdata.secret ~= client_secret then
        db:close()
        response:setStatus(401)
        response:json({ error = "unauthorized_client", error_description = "Invalid client secret" })
        return
    end
    
    local roles = cdata.roles or { "service-account" }
    local access_token, refresh_token, lifespan = utils.issue_token(db, client_id, client_id, form.scope or "client", roles, true)
    
    local event = {
        type = "CLIENT_LOGIN",
        username = "client:" .. client_id,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Issued token via client_credentials grant"
    }
    local events_str = db:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put("meta:events", json.encode(events))
    
    db:close()
    
    response:json({
        access_token = access_token,
        token_type = "Bearer",
        expires_in = lifespan,
        refresh_token = refresh_token,
        scope = form.scope or "client"
    })
    return

-- 2. Authorization Code Grant
elseif grant_type == "authorization_code" then
    local code = form.code
    
    local code_data_str = db:get("code:" .. (code or ""))
    if not code_data_str then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_grant", error_description = "Invalid or expired authorization code" })
        return
    end
    
    local code_data = json.decode(code_data_str)
    db:delete("code:" .. code) -- Single-use immediate delete
    
    -- K3: Check authorization code expiration (max 60 seconds)
    if code_data.created and (os.time() - code_data.created > 60) then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_grant", error_description = "Authorization code expired" })
        return
    end
    
    -- K3: Verify client_id binding (RFC 6749 §4.1.3 — MUST be sent and equal)
    local req_client_id = client_id or form.client_id
    if code_data.client_id and code_data.client_id ~= "" then
        if not req_client_id or req_client_id == "" or req_client_id ~= code_data.client_id then
            db:close()
            response:setStatus(400)
            response:json({ error = "invalid_grant", error_description = "client_id mismatch" })
            return
        end
    end
    
    -- K3: Verify redirect_uri binding (MUST be sent and identical to authz request)
    if code_data.redirect_uri and code_data.redirect_uri ~= "" then
        if not form.redirect_uri or form.redirect_uri == "" or form.redirect_uri ~= code_data.redirect_uri then
            db:close()
            response:setStatus(400)
            response:json({ error = "invalid_grant", error_description = "redirect_uri mismatch" })
            return
        end
    end
    
    -- PKCE Verification (RFC 7636)
    if code_data.code_challenge and code_data.code_challenge ~= "" then
        local pkce_ok, pkce_err = utils.verify_pkce(form.code_verifier, code_data.code_challenge, code_data.code_challenge_method)
        if not pkce_ok then
            db:close()
            response:setStatus(400)
            response:json({ error = "invalid_grant", error_description = pkce_err or "PKCE verification failed" })
            return
        end
    end
    
    local user_data_str = db:get("user:" .. code_data.username)
    if user_data_str then
        local user_data = json.decode(user_data_str)
        if user_data.enabled == false then
            db:close()
            response:setStatus(400)
            response:json({ error = "invalid_grant", error_description = "Account is disabled" })
            return
        end
    end
    
    local roles = utils.get_user_roles(db, code_data.username)
    local access_token, refresh_token, lifespan = utils.issue_token(db, code_data.username, code_data.client_id, code_data.scope or "openid profile email", roles, false)
    local id_token = utils.issue_id_token(db, code_data.username, code_data.client_id, code_data.nonce)
    
    local event = {
        type = "CODE_TO_TOKEN",
        username = code_data.username,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Issued token via authorization_code grant"
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
    
    db:close()
    
    response:json({
        access_token = access_token,
        token_type = "Bearer",
        id_token = id_token,
        expires_in = lifespan,
        refresh_token = refresh_token,
        scope = code_data.scope or "openid profile email"
    })
    return

-- 3. Resource Owner Password Credentials Grant
elseif grant_type == "password" then
    local username = form.username
    local password = form.password
    
    -- Check account lockout
    local locked, remaining = utils.check_account_locked(db, username or "")
    if locked then
        db:close()
        response:setStatus(423)
        response:json({ error = "locked", error_description = "Account is temporarily locked. Try again in " .. remaining .. " seconds." })
        return
    end
    
    local user_data_str = db:get("user:" .. (username or ""))
    if not user_data_str then
        db:close()
        response:setStatus(401)
        response:json({ error = "invalid_grant", error_description = "Invalid user credentials" })
        return
    end
    
    local user_data = json.decode(user_data_str)
    if user_data.enabled == false then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_grant", error_description = "Account is disabled" })
        return
    end
    
    local pw_ok, needs_rehash = utils.verify_password(password, user_data.password)
    if not pw_ok then
        local just_locked, count, max_f = utils.record_login_failure(db, username, utils.get_client_ip())
        db:close()
        response:setStatus(401)
        response:json({ error = "invalid_grant", error_description = "Invalid user credentials" })
        return
    end
    
    if needs_rehash then
        user_data.password = utils.hash_password(password)
        db:put("user:" .. username, json.encode(user_data))
    end
    
    utils.reset_login_failures(db, username)
    local roles = utils.get_user_roles(db, username)
    local access_token, refresh_token, lifespan = utils.issue_token(db, username, client_id or "default", form.scope or "openid profile email", roles, false)
    
    local event = {
        type = "LOGIN",
        username = username,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "Issued token via password grant"
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
    
    db:close()
    
    response:json({
        access_token = access_token,
        token_type = "Bearer",
        expires_in = lifespan,
        refresh_token = refresh_token,
        scope = form.scope or "openid profile email"
    })
    return

-- 4. Refresh Token Grant
elseif grant_type == "refresh_token" then
    local r_token = form.refresh_token
    local r_data_str = db:get("refresh_token:" .. (r_token or ""))
    if not r_data_str then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_grant", error_description = "Invalid refresh token" })
        return
    end
    
    local r_data = json.decode(r_data_str)
    db:delete("refresh_token:" .. r_token) -- Token Rotation
    
    -- K4: Check refresh token expiry
    if r_data.exp and os.time() > r_data.exp then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_grant", error_description = "Refresh token expired" })
        return
    end
    
    -- K4: Check client binding (MUST be sent and equal)
    local req_client_id = client_id or form.client_id
    if r_data.client_id and r_data.client_id ~= "" then
        if not req_client_id or req_client_id == "" or req_client_id ~= r_data.client_id then
            db:close()
            response:setStatus(400)
            response:json({ error = "invalid_grant", error_description = "client_id mismatch for refresh token" })
            return
        end
    end
    
    local access_token, new_refresh_token, lifespan = utils.issue_token(db, r_data.username, r_data.client_id, "openid profile email", r_data.roles, r_data.is_client)
    db:close()
    
    response:json({
        access_token = access_token,
        token_type = "Bearer",
        expires_in = lifespan,
        refresh_token = new_refresh_token,
        scope = "openid profile email"
    })
    return
end

db:close()
response:setStatus(400)
response:json({ error = "unsupported_grant_type" })
