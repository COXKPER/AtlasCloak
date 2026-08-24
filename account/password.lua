local utils = dofile("public/lib/utils.lua")

local db = utils.get_db()
utils.ensure_admin_exists(db)

local username, session_id = utils.get_session_user(db)
if not username then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=account&redirect_uri=/account/password", 302)
    return
end

local user_data_str = db:get("user:" .. username)
local user_data = user_data_str and json.decode(user_data_str) or { username = username }
local policy = utils.get_password_policy(db)

local msg_html = ""
local forced = request:getParam("forced") == "true" or (user_data.must_change_password == true)

if forced then
    msg_html = '<div class="alert alert-warning"><span class="alert-icon"><i class="fa-solid fa-triangle-exclamation"></i></span> <strong>Security Notice:</strong> You are currently using default credentials. Please set a new, secure password.</div>'
end

if request.method == "POST" then
    local form = utils.parse_form(request.body)
    local current_pw = form.currentPassword or ""
    local new_pw = form.newPassword or ""
    local confirm_pw = form.confirmPassword or ""
    
    local pw_ok, _ = utils.verify_password(current_pw, user_data.password)
    if not pw_ok then
        msg_html = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-xmark"></i></span> Current password is incorrect.</div>'
    elseif new_pw ~= confirm_pw then
        msg_html = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-xmark"></i></span> Passwords do not match.</div>'
    else
        local val_ok, val_err = utils.validate_password_policy(db, new_pw)
        if not val_ok then
            msg_html = '<div class="alert alert-error"><span class="alert-icon"><i class="fa-solid fa-xmark"></i></span> ' .. utils.html_escape(val_err) .. '</div>'
        else
            user_data.password = utils.hash_password(new_pw)
            user_data.must_change_password = false
            db:put("user:" .. username, json.encode(user_data))
            
            local event = {
                type = "UPDATE_PASSWORD",
                username = username,
                ip = utils.get_client_ip(),
                time = os.time(),
                detail = "User updated password"
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
            
            msg_html = '<div class="alert alert-success"><span class="alert-icon"><i class="fa-solid fa-circle-check"></i></span> Password updated successfully! Your account is now secured.</div>'
        end
    end
end

db:close()

local policy_items = "<li>Minimum length: " .. policy.min_length .. " characters</li>"
if policy.req_upper then policy_items = policy_items .. "<li>Requires at least one uppercase letter (A-Z)</li>" end
if policy.req_lower then policy_items = policy_items .. "<li>Requires at least one lowercase letter (a-z)</li>" end
if policy.req_number then policy_items = policy_items .. "<li>Requires at least one digit (0-9)</li>" end
if policy.req_symbol then policy_items = policy_items .. "<li>Requires at least one special symbol (!@#$%)</li>" end

local content = msg_html .. [[
    <div style="display:grid;grid-template-columns: 2fr 1fr;gap:20px;">
        <div class="card">
            <div class="card-header">
                <h3><i class="fa-solid fa-key" style="margin-right:6px;"></i> Change Password</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="/account/password">
                    <div class="form-group">
                        <label>Current Password</label>
                        <input type="password" name="currentPassword" placeholder="Enter current password" required autocomplete="current-password">
                    </div>
                    <div class="form-group">
                        <label>New Password</label>
                        <input type="password" name="newPassword" placeholder="Enter new password" required autocomplete="new-password">
                    </div>
                    <div class="form-group">
                        <label>Confirm New Password</label>
                        <input type="password" name="confirmPassword" placeholder="Re-enter new password" required autocomplete="new-password">
                    </div>
                    <div style="margin-top:8px;">
                        <button type="submit" class="btn btn-primary" style="width:auto;"><i class="fa-solid fa-floppy-disk"></i> Update Password</button>
                    </div>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3><i class="fa-solid fa-shield-halved" style="margin-right:6px;"></i> Password Requirements</h3>
            </div>
            <div class="card-body" style="padding:16px;">
                <ul style="padding-left:20px;font-size:13px;color:var(--text-muted);display:flex;flex-direction:column;gap:8px;">
                    ]] .. policy_items .. [[
                </ul>
            </div>
        </div>
    </div>
]]

response:write(utils.render_account_page("Change Password", "password", user_data, content))
