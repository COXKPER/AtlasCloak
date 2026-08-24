local utils = dofile("public/lib/utils.lua")

local client_id = request:getParam("client_id")
local redirect_uri = request:getParam("redirect_uri")
local state = request:getParam("state")

local db = utils.get_db()
if not utils.is_registration_enabled(db) then
    db:close()
    local content = [[
        <div class="alert alert-error"><span class="alert-icon">✕</span> Registration is currently disabled by the administrator.</div>
        <a href="/auth/realms/master/protocol/openid-connect/auth?client_id=]] .. (client_id or "") .. [[&redirect_uri=]] .. (redirect_uri or "") .. [[&state=]] .. (state or "") .. [[" class="btn btn-primary">Back to Login</a>
    ]]
    response:write(utils.render_auth_page("Registration Disabled", "Self-registration is not available", content))
    return
end

local policy = utils.get_password_policy(db)
db:close()

if request.method == "GET" then
    local error_msg = request:getParam("error")
    local alert_html = ""
    if error_msg and error_msg ~= "" then
        alert_html = '<div class="alert alert-error"><span class="alert-icon">✕</span> ' .. utils.html_escape(error_msg) .. '</div>'
    end

    local db2 = utils.get_db()
    local sec_token = utils.generate_security_token(db2, "register")
    db2:close()

    local action_url = "/auth/realms/master/login-actions/registration?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "")

    local policy_hint = "Min " .. policy.min_length .. " chars"
    if policy.req_upper then policy_hint = policy_hint .. ", uppercase" end
    if policy.req_number then policy_hint = policy_hint .. ", digit" end
    if policy.req_symbol then policy_hint = policy_hint .. ", symbol" end

    local content = alert_html .. [[
        <form method="POST" action="]] .. action_url .. [[">
            ]] .. utils.render_security_fields(sec_token) .. [[
            <div class="row-2">
                <div class="form-group">
                    <label>First Name</label>
                    <input type="text" name="firstName" placeholder="John" required>
                </div>
                <div class="form-group">
                    <label>Last Name</label>
                    <input type="text" name="lastName" placeholder="Doe" required>
                </div>
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="text" name="email" placeholder="john@example.com" required>
            </div>
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Choose a username" required>
            </div>
            <div class="form-group">
                <label>Password <small style="color:var(--text-muted);font-weight:normal;">(]] .. utils.html_escape(policy_hint) .. [[)</small></label>
                <input type="password" name="password" placeholder="Create a password" required>
            </div>
            <button type="submit" class="btn btn-primary">Register</button>
        </form>
        <div class="footer-links">
            Already have an account? <a href="/auth/realms/master/protocol/openid-connect/auth?client_id=]] .. (client_id or "") .. [[&redirect_uri=]] .. (redirect_uri or "") .. [[&state=]] .. (state or "") .. [[">Sign In</a>
        </div>
    ]]

    response:write(utils.render_auth_page("Register", "Create your account", content))
    return
end

if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local username = form.username
    local password = form.password
    local email = form.email
    local firstName = form.firstName
    local lastName = form.lastName

    local db3 = utils.get_db()

    -- 1. Anti-Bot Security Token Validation
    local ok, err_msg = utils.validate_security_token(db3, form, "register")
    if not ok then
        local event = {
            type = "SECURITY_BLOCKED",
            username = username or "anonymous",
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = "Blocked signup: " .. (err_msg or "Invalid security token")
        }
        local events_str = db3:get("meta:events")
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db3:put("meta:events", json.encode(events))
        
        db3:close()
        response:redirect("/auth/realms/master/login-actions/registration?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=" .. utils.url_encode(err_msg or "Security validation failed"), 302)
        return
    end

    -- 2. Validate Fields
    if not username or username == "" or not password or password == "" then
        db3:close()
        response:redirect("/auth/realms/master/login-actions/registration?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=All+fields+are+required", 302)
        return
    end

    -- 3. Validate Password Policy
    local pw_ok, pw_err = utils.validate_password_policy(db3, password)
    if not pw_ok then
        db3:close()
        response:redirect("/auth/realms/master/login-actions/registration?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=" .. utils.url_encode(pw_err), 302)
        return
    end

    -- Re-check if registration is still enabled
    if not utils.is_registration_enabled(db3) then
        db3:close()
        response:setStatus(403)
        response:write("Registration is disabled")
        return
    end

    -- Check if user exists
    if db3:get("user:" .. username) then
        db3:close()
        response:redirect("/auth/realms/master/login-actions/registration?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=Username+already+exists", 302)
        return
    end

    local user_data = {
        username = username,
        password = utils.hash_password(password),
        email = email,
        firstName = firstName,
        lastName = lastName,
        enabled = true,
        createdAt = os.time()
    }

    db3:put("user:" .. username, json.encode(user_data))
    utils.set_user_roles(db3, username, { "user" })

    -- Add to user list
    local user_list_str = db3:get("meta:user_list")
    local user_list = user_list_str and json.decode(user_list_str) or {}
    table.insert(user_list, username)
    db3:put("meta:user_list", json.encode(user_list))

    -- Log event
    local event = {
        type = "REGISTER",
        username = username,
        ip = utils.get_client_ip(),
        time = os.time(),
        detail = "User registered"
    }
    local events_str = db3:get("meta:events")
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db3:put("meta:events", json.encode(events))

    db3:close()

    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=" .. (client_id or "") .. "&redirect_uri=" .. (redirect_uri or "") .. "&state=" .. (state or "") .. "&error=Registration+successful!+Please+sign+in.", 302)
    return
end

response:setStatus(405)
response:write("Method Not Allowed")
