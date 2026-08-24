local M = {}

M.db_path = "./atlascloak.db"
M.version = "2.0.0"

local sha256_mod = dofile("public/lib/sha256.lua")

-- ─── Database ─────────────────────────────────────────────────────────────────

function M.get_db()
    return ldb.create(M.db_path)
end

-- ─── Base64 & Base64URL ───────────────────────────────────────────────────────

local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function M.base64_encode(data)
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b64chars:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

function M.base64url_encode(data)
    local s = M.base64_encode(data)
    s = s:gsub('%+', '-'):gsub('/', '_'):gsub('=', '')
    return s
end

function M.base64_decode(data)
    data = string.gsub(data, '[^'..b64chars..'=]', '')
    local bit_str = ''
    for i = 1, #data do
        local c = string.sub(data, i, i)
        if c == '=' then break end
        local idx = string.find(b64chars, c, 1, true)
        if idx then
            local val = idx - 1
            for b = 5, 0, -1 do
                bit_str = bit_str .. (math.floor(val / (2^b)) % 2)
            end
        end
    end
    local result = {}
    for i = 1, #bit_str - 7, 8 do
        local byte_val = 0
        for b = 0, 7 do
            if string.sub(bit_str, i + b, i + b) == '1' then
                byte_val = byte_val + 2^(7 - b)
            end
        end
        table.insert(result, string.char(byte_val))
    end
    return table.concat(result)
end

function M.base64url_decode(data)
    local pad = (4 - (#data % 4)) % 4
    data = data .. string.rep("=", pad)
    data = data:gsub("%-", "+"):gsub("_", "/")
    return M.base64_decode(data)
end

-- ─── General Helpers ──────────────────────────────────────────────────────────

function M.get_base_url()
    local host = (request and request.host) or "localhost:8081"
    if request and request.headers then
        local fwd_host = request.headers["x-forwarded-host"]
        if fwd_host and fwd_host ~= "" then
            host = fwd_host
        end
    end
    
    local proto = "http"
    if request and request.headers then
        local fwd_proto = request.headers["x-forwarded-proto"]
        if fwd_proto and fwd_proto ~= "" then
            proto = fwd_proto
        end
    end
    if string.find(host, "neoncorp", 1, true) then
        proto = "https"
    end
    return proto .. "://" .. host
end

-- ─── K1: Password Hashing (PBKDF2-HMAC-SHA256 via Go crypto bridge) ─────────

-- Iteration target for NEW hashes. Verify always uses the rounds recorded in
-- the stored string; rehash happens only upward (never downward).
-- 100k ≈ 30-50 ms on commodity server hardware.
M.pbkdf2_rounds = 100000

function M.uuid()
    if crypto and crypto.random_bytes then
        local raw = crypto.random_bytes(16)
        local b = {}
        for i = 1, 16 do b[i] = string.byte(raw, i) end
        b[7] = (b[7] % 16) + 64   -- version nibble -> 4
        b[9] = (b[9] % 64) + 128  -- variant bits -> 10xx
        local hexs = {}
        for i = 1, 16 do hexs[i] = string.format("%02x", b[i]) end
        local s = table.concat(hexs)
        return string.sub(s,1,8).."-"..string.sub(s,9,12).."-"
            ..string.sub(s,13,16).."-"..string.sub(s,17,20).."-"..string.sub(s,21,32)
    end
    -- Fallback (bridge unavailable): PRNG-based UUID v4
    local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function(c)
        local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
        return string.format('%x', v)
    end)
end

function M.hash_password(password)
    if not password or password == "" then return nil end
    local salt = M.uuid():gsub("-", "")
    -- Preferred: real PBKDF2-HMAC-SHA256 via the Go crypto bridge.
    if crypto and crypto.pbkdf2_hex then
        local h = crypto.pbkdf2_hex(password, salt, M.pbkdf2_rounds)
        return "atlas_pbkdf2$" .. M.pbkdf2_rounds .. "$" .. salt .. "$" .. h
    end
    -- Transitional fallback (bridge unavailable): weak iterated concat,
    -- always flagged legacy so it is upgraded on next login.
    local h2 = salt .. password
    for _ = 1, 5 do
        h2 = sha256_mod.sha256_hex(h2 .. salt)
    end
    return "pbkdf2_sha256$5$" .. salt .. "$" .. h2
end

local function djb2_hash(password)
    local h = 5381
    for i = 1, #password do
        h = ((h * 33) + string.byte(password, i)) % 4294967296
    end
    return string.format("%x", h)
end

function M.verify_password(input_password, stored_password)
    if not input_password or not stored_password or stored_password == "" then
        return false, false
    end

    -- 1. Current format: atlas_pbkdf2$rounds$salt$hash (Go PBKDF2-HMAC-SHA256)
    local rounds, salt, hash = string.match(stored_password, "^atlas_pbkdf2%$(%d+)%$([a-zA-Z0-9]+)%$([a-zA-Z0-9]+)$")
    if rounds and salt and hash then
        if not (crypto and crypto.pbkdf2_hex) then return false, false end
        local rounds_num = tonumber(rounds) or M.pbkdf2_rounds
        if crypto.pbkdf2_hex(input_password, salt, rounds_num) == hash then
            -- upgrade-only rehash: never downgrade to fewer rounds
            return true, (rounds_num < M.pbkdf2_rounds)
        end
        return false, false
    end

    -- 2. Transitional format (v1.2.1): pbkdf2_sha256$rounds$salt$hash —
    --    pure-Lua iterated concat, NOT real PBKDF2. Verify then always
    --    flag for upgrade to the Go-backed format.
    local lrounds, lsalt, lhash = string.match(stored_password, "^pbkdf2_sha256%$(%d+)%$([a-zA-Z0-9]+)%$([a-zA-Z0-9]+)$")
    if lrounds and lsalt and lhash then
        local h = lsalt .. input_password
        for _ = 1, (tonumber(lrounds) or 5) do
            h = sha256_mod.sha256_hex(h .. lsalt)
        end
        if h == lhash then
            return true, true
        end
        return false, false
    end

    -- 3. Legacy format: atlas_salt_ static-salt hash
    if stored_password == sha256_mod.sha256_hex("atlas_salt_" .. input_password) then
        return true, true
    end

    -- 4. Legacy format: djb2 hash
    if stored_password == djb2_hash(input_password) then
        return true, true
    end

    return false, false
end

function M.url_decode(str)
    str = string.gsub(str, "+", " ")
    str = string.gsub(str, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    str = string.gsub(str, "\r\n", "\n")
    return str
end

function M.url_encode(str)
    str = string.gsub(str, "([^%w%-%.%_%~ ])", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
    str = string.gsub(str, " ", "+")
    return str
end

function M.html_escape(str)
    if not str then return "" end
    str = string.gsub(str, "&", "&amp;")
    str = string.gsub(str, "<", "&lt;")
    str = string.gsub(str, ">", "&gt;")
    str = string.gsub(str, '"', "&quot;")
    str = string.gsub(str, "'", "&#39;")
    return str
end

function M.parse_form(body)
    local params = {}
    if not body or body == "" then return params end
    for kv in string.gmatch(body, "([^&]+)") do
        local key, val = string.match(kv, "([^=]+)=?(.*)")
        if key then
            params[M.url_decode(key)] = M.url_decode(val)
        end
    end
    return params
end

function M.redirect(url, cookie_str)
    M.apply_security_headers()
    response:setStatus(302)
    response:setHeader("Location", url)
    if cookie_str then
        response:setHeader("Set-Cookie", cookie_str)
        response:setHeader("Cache-Control", "no-store")
    end
end

function M.time_ago(ts)
    local diff = os.time() - ts
    if diff < 60 then return diff .. "s ago" end
    if diff < 3600 then return math.floor(diff / 60) .. "m ago" end
    if diff < 86400 then return math.floor(diff / 3600) .. "h ago" end
    return math.floor(diff / 86400) .. "d ago"
end

-- ─── Redirect URI Whitelist Management ───────────────────────────────────────

function M.is_whitelist_enabled(db)
    local val = db:get(M.rk("setting:whitelist_enabled"))
    if val == nil then return true end
    return val == "true"
end

function M.get_global_whitelist(db)
    local val = db:get(M.rk("setting:global_whitelist"))
    if not val or val == "" then
        return "http://localhost:*\nhttp://127.0.0.1:*\nhttps://oidcdebugger.com/*\nhttps://oauth.pstmn.io/*"
    end
    return val
end

function M.validate_redirect_uri(db, client_id, redirect_uri)
    if not redirect_uri or redirect_uri == "" then
        return false, "Missing redirect_uri"
    end
    
    -- If whitelist enforcement is disabled (Permissive / Testing Mode)
    if not M.is_whitelist_enabled(db) then
        return true, "Whitelist enforcement disabled (Permissive mode)"
    end
    
    -- Internal clients (account, admin-console)
    if client_id == "account" or client_id == "admin-console" then
        if string.sub(redirect_uri, 1, 1) == "/" and not string.find(redirect_uri, "^//") then
            return true
        end
        local host = request.host or "localhost:8081"
        if string.find(redirect_uri, "^https?://" .. host) then
            return true
        end
    end
    
    -- 1. Check Global Whitelist patterns
    local global_patterns = M.get_global_whitelist(db)
    for raw_pat in string.gmatch(global_patterns, "[^\r\n]+") do
        local pattern = string.match(raw_pat, "^%s*(.-)%s*$")
        if pattern and pattern ~= "" then
            if pattern == "*" then return true end
            if pattern == redirect_uri then return true end
            if string.sub(pattern, -1) == "*" then
                local prefix = string.sub(pattern, 1, -2)
                -- Guard: reject wildcard matches that would smuggle an
                -- authority component via "@" userinfo (e.g. evil.com@host)
                if string.sub(redirect_uri, 1, #prefix) == prefix
                    and not string.find(string.sub(redirect_uri, #prefix + 1), "@", 1, true) then
                    return true
                end
            end
        end
    end

    -- 2. Check Client-Specific Registered Redirect URIs
    local cdata_str = db:get(M.rk("client:") .. (client_id or ""))
    if cdata_str then
        local cdata = json.decode(cdata_str)
        local allowed = cdata.redirect_uris or ""  -- fail closed by default

        if allowed == "*" then
            return true
        end

        for pattern in string.gmatch(allowed, "[^\r\n, ]+") do
            if pattern == redirect_uri then
                return true
            end
            if string.sub(pattern, -1) == "*" then
                local prefix = string.sub(pattern, 1, -2)
                if string.sub(redirect_uri, 1, #prefix) == prefix
                    and not string.find(string.sub(redirect_uri, #prefix + 1), "@", 1, true) then
                    return true
                end
            end
        end
    end
    
    return false, "redirect_uri '" .. redirect_uri .. "' is not in the allowed whitelist for client '" .. tostring(client_id) .. "'"
end

-- ─── PKCE (RFC 7636) ─────────────────────────────────────────────────────────

function M.verify_pkce(code_verifier, code_challenge, method)
    if not code_challenge or code_challenge == "" then
        return true
    end
    if not code_verifier or code_verifier == "" then
        return false, "code_verifier is required when code_challenge is present"
    end
    
    local m = method or "S256"
    if m == "S256" then
        local raw_hash = sha256_mod.sha256_raw(code_verifier)
        local computed_challenge = M.base64url_encode(raw_hash)
        if computed_challenge == code_challenge then
            return true
        else
            return false, "PKCE verification failed: computed challenge does not match"
        end
    elseif m == "plain" then
        if code_verifier == code_challenge then
            return true
        else
            return false, "PKCE verification failed: plain verifier does not match"
        end
    else
        return false, "Unsupported code_challenge_method: " .. tostring(m)
    end
end

-- ─── JWT & Token Management ───────────────────────────────────────────────────

function M.get_jwt_secret(db)
    local secret = db:get(M.rk("setting:jwt_secret"))
    if not secret or secret == "" then
        -- T2: 256-bit CSPRNG secret (Go crypto/rand bridge)
        if crypto and crypto.random_hex then
            secret = crypto.random_hex(32)
        else
            secret = M.uuid() .. "-" .. M.uuid()
        end
        db:put(M.rk("setting:jwt_secret"), secret)
    end
    return secret
end

-- T6: issuer origin from config (telamon.base_url), never trust Host header
function M.get_base_url()
    if telamon and telamon.base_url and telamon.base_url ~= "" then
        return telamon.base_url
    end
    return "http://" .. (request.host or "localhost")
end

function M.sign_jwt(payload_table, secret)
    local header = { alg = "HS256", typ = "JWT" }
    local h_encoded = M.base64url_encode(json.encode(header))
    local p_encoded = M.base64url_encode(json.encode(payload_table))
    local msg = h_encoded .. "." .. p_encoded
    local sig_raw = sha256_mod.hmac_sha256_raw(secret, msg)
    local sig_encoded = M.base64url_encode(sig_raw)
    return msg .. "." .. sig_encoded
end

function M.verify_jwt(jwt_str, secret)
    if not jwt_str or jwt_str == "" then return false, nil, "Missing token" end
    local h_enc, p_enc, sig_enc = string.match(jwt_str, "^([^%.]+)%.([^%.]+)%.([^%.]+)$")
    if not h_enc or not p_enc or not sig_enc then
        return false, nil, "Invalid JWT format"
    end
    
    local msg = h_enc .. "." .. p_enc
    local expected_sig = M.base64url_encode(sha256_mod.hmac_sha256_raw(secret, msg))
    if expected_sig ~= sig_enc then
        return false, nil, "Invalid signature"
    end
    
    local payload_str = M.base64url_decode(p_enc)
    local payload = json.decode(payload_str)
    if not payload then
        return false, nil, "Invalid payload JSON"
    end
    
    if payload.exp and os.time() > payload.exp then
        return false, nil, "Token expired"
    end
    
    return true, payload, nil
end

function M.issue_token(db, username_or_client, client_id, scope, roles, is_client)
    local token_format = db:get(M.rk("setting:token_format")) or "jwt"
    local lifespan = tonumber(db:get(M.rk("setting:token_lifespan"))) or 3600
    local exp_time = os.time() + lifespan
    local issuer = M.get_base_url() .. M.realm_url()
    
    local access_token = ""
    local refresh_token = M.uuid()
    
    if token_format == "jwt" then
        local secret = M.get_jwt_secret(db)
        local payload = {
            iss = issuer,
            sub = username_or_client,
            aud = client_id or "account",
            exp = exp_time,
            iat = os.time(),
            jti = M.uuid(),
            typ = "Bearer",
            azp = client_id or "account",
            scope = scope or "openid profile email",
            roles = roles or { "user" },
            is_client = is_client or false
        }
        
        if not is_client then
            local udata_str = db:get(M.rk("user:") .. username_or_client)
            if udata_str then
                local udata = json.decode(udata_str)
                payload.preferred_username = udata.username
                payload.email = udata.email
                payload.given_name = udata.firstName
                payload.family_name = udata.lastName
                payload.name = (udata.firstName or "") .. " " .. (udata.lastName or "")
            end
        end
        
        access_token = M.sign_jwt(payload, secret)
    else
        access_token = M.uuid()
        local token_data = {
            username = username_or_client,
            client_id = client_id,
            roles = roles or { "user" },
            exp = exp_time,
            is_client = is_client or false
        }
        db:put(M.rk("token:") .. access_token, json.encode(token_data))
    end
    
    local r_data = {
        username = username_or_client,
        client_id = client_id,
        roles = roles or { "user" },
        is_client = is_client or false,
        exp = os.time() + (lifespan * 7)
    }
    db:put(M.rk("refresh_token:") .. refresh_token, json.encode(r_data))
    
    return access_token, refresh_token, lifespan
end

function M.issue_id_token(db, username, client_id, nonce)
    local secret = M.get_jwt_secret(db)
    local lifespan = tonumber(db:get(M.rk("setting:token_lifespan"))) or 3600
    local issuer = M.get_base_url() .. M.realm_url()
    
    local payload = {
        iss = issuer,
        sub = username,
        aud = client_id or "account",
        exp = os.time() + lifespan,
        iat = os.time(),
        auth_time = os.time(),
        jti = M.uuid()
    }
    
    if nonce and nonce ~= "" then
        payload.nonce = nonce
    end
    
    local udata_str = db:get(M.rk("user:") .. username)
    if udata_str then
        local udata = json.decode(udata_str)
        payload.preferred_username = udata.username
        payload.email = udata.email or ""
        payload.given_name = udata.firstName or ""
        payload.family_name = udata.lastName or ""
        payload.name = (udata.firstName or "") .. " " .. (udata.lastName or "")
    end
    
    return M.sign_jwt(payload, secret)
end

function M.validate_token(db, token_str)
    if not token_str or token_str == "" then return false, nil, "Missing token" end
    
    if db:get(M.rk("revoked:") .. token_str) then
        return false, nil, "Token has been revoked"
    end
    
    if string.find(token_str, "%.") then
        local secret = M.get_jwt_secret(db)
        local ok, payload, err = M.verify_jwt(token_str, secret)
        if not ok then return false, nil, err end
        if payload.jti and db:get(M.rk("revoked:") .. payload.jti) then
            return false, nil, "Token has been revoked"
        end
        return true, payload, nil
    end
    
    local token_data_str = db:get(M.rk("token:") .. token_str)
    if not token_data_str then
        return false, nil, "Invalid token"
    end
    local token_data = json.decode(token_data_str)
    if os.time() > (token_data.exp or 0) then
        return false, nil, "Token expired"
    end
    return true, token_data, nil
end

function M.revoke_token(db, token_str)
    if not token_str or token_str == "" then return false end
    
    db:delete(M.rk("token:") .. token_str)
    db:delete(M.rk("refresh_token:") .. token_str)
    db:put(M.rk("revoked:") .. token_str, tostring(os.time()))
    
    if string.find(token_str, "%.") then
        local h_enc, p_enc, _ = string.match(token_str, "^([^%.]+)%.([^%.]+)%.([^%.]+)$")
        if p_enc then
            local payload_str = M.base64url_decode(p_enc)
            local payload = json.decode(payload_str)
            if payload and payload.jti then
                db:put(M.rk("revoked:") .. payload.jti, tostring(os.time()))
            end
        end
    end
    return true
end

-- ─── Brute Force Protection & Lockout ────────────────────────────────────────

function M.get_brute_force_config(db)
    local enabled = db:get(M.rk("setting:brute_force_enabled"))
    local max_failures = tonumber(db:get(M.rk("setting:max_login_failures"))) or 5
    local lock_duration = tonumber(db:get(M.rk("setting:lockout_duration"))) or 900
    return {
        enabled = (enabled == nil or enabled == "true"),
        max_failures = max_failures,
        lock_duration = lock_duration
    }
end

function M.check_account_locked(db, username)
    local cfg = M.get_brute_force_config(db)
    if not cfg.enabled then return false, 0 end
    
    local fail_str = db:get(M.rk("fails:") .. username)
    if not fail_str then return false, 0 end
    
    local f_data = json.decode(fail_str)
    if f_data.locked_until and os.time() < f_data.locked_until then
        local remaining = f_data.locked_until - os.time()
        return true, remaining
    end
    
    return false, 0
end

function M.record_login_failure(db, username, ip)
    local cfg = M.get_brute_force_config(db)
    local fail_str = db:get(M.rk("fails:") .. username)
    local f_data = fail_str and json.decode(fail_str) or { count = 0, last_fail = 0 }
    
    if os.time() - (f_data.last_fail or 0) > cfg.lock_duration then
        f_data.count = 0
    end
    
    f_data.count = f_data.count + 1
    f_data.last_fail = os.time()
    
    local just_locked = false
    if cfg.enabled and f_data.count >= cfg.max_failures then
        f_data.locked_until = os.time() + cfg.lock_duration
        just_locked = true
    end
    
    db:put(M.rk("fails:") .. username, json.encode(f_data))
    return just_locked, f_data.count, cfg.max_failures, f_data.locked_until
end

function M.reset_login_failures(db, username)
    db:delete(M.rk("fails:") .. username)
end

function M.unlock_account(db, username)
    db:delete(M.rk("fails:") .. username)
end

-- ─── Password Policy ──────────────────────────────────────────────────────────

function M.get_password_policy(db)
    local min_len = tonumber(db:get(M.rk("setting:pwd_min_length"))) or 6
    local req_upper = (db:get(M.rk("setting:pwd_req_upper")) == "true")
    local req_lower = (db:get(M.rk("setting:pwd_req_lower")) == "true")
    local req_number = (db:get(M.rk("setting:pwd_req_number")) == "true")
    local req_symbol = (db:get(M.rk("setting:pwd_req_symbol")) == "true")
    return {
        min_length = min_len,
        req_upper = req_upper,
        req_lower = req_lower,
        req_number = req_number,
        req_symbol = req_symbol
    }
end

function M.validate_password_policy(db, password)
    local policy = M.get_password_policy(db)
    if not password or #password < policy.min_length then
        return false, "Password must be at least " .. policy.min_length .. " characters long."
    end
    if policy.req_upper and not string.match(password, "[A-Z]") then
        return false, "Password must contain at least one uppercase letter."
    end
    if policy.req_lower and not string.match(password, "[a-z]") then
        return false, "Password must contain at least one lowercase letter."
    end
    if policy.req_number and not string.match(password, "[0-9]") then
        return false, "Password must contain at least one digit (0-9)."
    end
    if policy.req_symbol and not string.match(password, "[^%w%s]") then
        return false, "Password must contain at least one special symbol (!@#$%, etc.)."
    end
    return true, nil
end

-- ─── RBAC & Roles ─────────────────────────────────────────────────────────────

function M.get_roles(db)
    local roles_str = db:get(M.rk("meta:roles_list"))
    local roles = roles_str and json.decode(roles_str) or { "admin", "user" }
    return roles
end

function M.get_role_details(db, role_name)
    local r_str = db:get(M.rk("role_def:") .. role_name)
    if r_str then return json.decode(r_str) end
    return { name = role_name, description = (role_name == "admin" and "Realm Administrator" or "Standard User") }
end

function M.add_role(db, role_name, description)
    local roles = M.get_roles(db)
    local found = false
    for _, r in ipairs(roles) do
        if r == role_name then found = true break end
    end
    if not found then
        table.insert(roles, role_name)
        db:put(M.rk("meta:roles_list"), json.encode(roles))
    end
    db:put(M.rk("role_def:") .. role_name, json.encode({ name = role_name, description = description or "" }))
end

function M.delete_role(db, role_name)
    if role_name == "admin" or role_name == "user" then return false end
    local roles = M.get_roles(db)
    local new_roles = {}
    for _, r in ipairs(roles) do
        if r ~= role_name then table.insert(new_roles, r) end
    end
    db:put(M.rk("meta:roles_list"), json.encode(new_roles))
    db:delete(M.rk("role_def:") .. role_name)
    return true
end

-- ─── User Groups & Group-Based Access Control (GBAC) ──────────────────────────

function M.get_groups(db)
    local grps_str = db:get(M.rk("meta:groups_list"))
    local grps = grps_str and json.decode(grps_str) or {}
    return grps
end

function M.get_group_details(db, group_name)
    local g_str = db:get(M.rk("group_def:") .. group_name)
    if g_str then return json.decode(g_str) end
    return { name = group_name, description = "", roles = {} }
end

function M.save_group(db, group_name, description, roles_table)
    local grps = M.get_groups(db)
    local found = false
    for _, g in ipairs(grps) do
        if g == group_name then found = true break end
    end
    if not found then
        table.insert(grps, group_name)
        db:put(M.rk("meta:groups_list"), json.encode(grps))
    end
    db:put(M.rk("group_def:") .. group_name, json.encode({
        name = group_name,
        description = description or "",
        roles = roles_table or {}
    }))
end

function M.delete_group(db, group_name)
    local grps = M.get_groups(db)
    local new_grps = {}
    for _, g in ipairs(grps) do
        if g ~= group_name then table.insert(new_grps, g) end
    end
    db:put(M.rk("meta:groups_list"), json.encode(new_grps))
    db:delete(M.rk("group_def:") .. group_name)
    return true
end

function M.get_user_groups(db, username)
    local grps_str = db:get(M.rk("user_groups:") .. username)
    if grps_str then return json.decode(grps_str) end
    return {}
end

function M.set_user_groups(db, username, groups_table)
    db:put(M.rk("user_groups:") .. username, json.encode(groups_table or {}))
end

function M.get_user_roles(db, username)
    local direct_roles_str = db:get(M.rk("user_roles:") .. username)
    local direct_roles = direct_roles_str and json.decode(direct_roles_str) or { db:get("role:" .. username) or "user" }
    
    local role_set = {}
    for _, r in ipairs(direct_roles) do role_set[r] = true end
    
    local u_grps = M.get_user_groups(db, username)
    for _, gname in ipairs(u_grps) do
        local gdet = M.get_group_details(db, gname)
        if gdet and gdet.roles then
            for _, gr in ipairs(gdet.roles) do
                role_set[gr] = true
            end
        end
    end
    
    local combined = {}
    for r, _ in pairs(role_set) do table.insert(combined, r) end
    if #combined == 0 then table.insert(combined, "user") end
    return combined
end

function M.set_user_roles(db, username, roles_table)
    db:put(M.rk("user_roles:") .. username, json.encode(roles_table))
    local primary = "user"
    for _, r in ipairs(roles_table) do
        if r == "admin" then primary = "admin" break end
    end
    db:put("role:" .. username, primary)
end

-- ─── Consent Screen ───────────────────────────────────────────────────────────

function M.is_consent_required(db, client_id)
    if not client_id or client_id == "" or client_id == "account" or client_id == "admin-console" then
        return false
    end
    local cdata_str = db:get(M.rk("client:") .. client_id)
    if not cdata_str then
        return true
    end
    local cdata = json.decode(cdata_str)
    if cdata.consent_required == nil then
        return true
    end
    return (cdata.consent_required == true or cdata.consent_required == "true" or cdata.consent_required == "on")
end

--- Scope-aware consent check. Legacy grants stored as plain "true" remain a
--- full grant (backward compatible); new grants store the granted scope list.
function M.has_user_consented(db, username, client_id, requested_scopes)
    local val = db:get(M.rk("consent:") .. username .. ":" .. client_id)
    if not val then return false end
    if val == "true" then return true end -- legacy blanket grant
    local granted = json.decode(val)
    if type(granted) ~= "table" then return false end
    local set = {}
    for _, s in ipairs(granted) do set[s] = true end
    for s in string.gmatch(requested_scopes or "", "%S+") do
        if s ~= "openid" and not set[s] then return false end
    end
    return true
end

function M.save_user_consent(db, username, client_id, scopes)
    local list = {}
    for s in string.gmatch(scopes or "openid profile email", "%S+") do table.insert(list, s) end
    db:put(M.rk("consent:") .. username .. ":" .. client_id, json.encode(list))
end

-- ─── Realm Policies ──────────────────────────────────────────────────────────

M.POLICY_DEFAULTS = {
    pkce_required = false,        -- reject authorization-code flows without PKCE
    mfa_required_all = false,     -- every login must complete TOTP enrollment+challenge
    mfa_required_admins = false,  -- admin console access requires TOTP
    passkeys_enabled = true,      -- WebAuthn/Passkey login + enrollment allowed
    device_flow_enabled = true,   -- RFC 8628 device authorization grant allowed
    consent_default = true,       -- clients without explicit config require consent
}

function M.get_policies(db)
    local p = {}
    for name, def in pairs(M.POLICY_DEFAULTS) do
        local raw = db:get(M.rk("policy:" .. name))
        p[name] = (raw == nil) and def or (raw == "true")
    end
    return p
end

--- Session idle timeout in seconds (0 = disabled).
function M.get_session_idle_timeout(db)
    return tonumber(db:get(M.rk("setting:session_idle_timeout"))) or 0
end

-- ─── Realm Export & Import ────────────────────────────────────────────────────

function M.export_realm_data(db)
    local export = {
        realm = "master",
        displayName = M.get_realm_display_name(db),
        exportedAt = os.time(),
        version = M.version,
        settings = {
            registration_enabled = M.is_registration_enabled(db),
            token_lifespan = tonumber(db:get(M.rk("setting:token_lifespan"))) or 3600,
            token_format = db:get(M.rk("setting:token_format")) or "jwt",
            brute_force_enabled = (db:get(M.rk("setting:brute_force_enabled")) ~= "false"),
            max_login_failures = tonumber(db:get(M.rk("setting:max_login_failures"))) or 5,
            lockout_duration = tonumber(db:get(M.rk("setting:lockout_duration"))) or 900,
            pwd_min_length = tonumber(db:get(M.rk("setting:pwd_min_length"))) or 6,
            pwd_req_upper = (db:get(M.rk("setting:pwd_req_upper")) == "true"),
            pwd_req_lower = (db:get(M.rk("setting:pwd_req_lower")) == "true"),
            pwd_req_number = (db:get(M.rk("setting:pwd_req_number")) == "true"),
            pwd_req_symbol = (db:get(M.rk("setting:pwd_req_symbol")) == "true")
        },
        roles = {},
        groups = {},
        users = {},
        clients = {}
    }
    
    local roles = M.get_roles(db)
    for _, r in ipairs(roles) do
        table.insert(export.roles, M.get_role_details(db, r))
    end
    
    local groups = M.get_groups(db)
    for _, g in ipairs(groups) do
        table.insert(export.groups, M.get_group_details(db, g))
    end
    
    local users_str = db:get(M.rk("meta:user_list"))
    local users = users_str and json.decode(users_str) or {}
    for _, uname in ipairs(users) do
        local udata_str = db:get(M.rk("user:") .. uname)
        if udata_str then
            local udata = json.decode(udata_str)
            udata.roles = M.get_user_roles(db, uname)
            udata.groups = M.get_user_groups(db, uname)
            table.insert(export.users, udata)
        end
    end
    
    local clients_str = db:get(M.rk("meta:client_list"))
    local clients = clients_str and json.decode(clients_str) or { "account", "admin-console" }
    for _, cid in ipairs(clients) do
        local cdata_str = db:get(M.rk("client:") .. cid)
        if cdata_str then
            table.insert(export.clients, json.decode(cdata_str))
        else
            table.insert(export.clients, { client_id = cid, name = cid, client_type = "public", redirect_uris = "/*" })
        end
    end
    
    return export
end

function M.import_realm_data(db, import_data)
    if type(import_data) ~= "table" then return false, "Invalid JSON data structure" end
    
    if import_data.displayName then
        db:put(M.rk("setting:realm_display_name"), import_data.displayName)
    end
    
    if import_data.settings then
        local s = import_data.settings
        if s.registration_enabled ~= nil then db:put(M.rk("setting:registration_enabled"), s.registration_enabled and "true" or "false") end
        if s.token_lifespan then db:put(M.rk("setting:token_lifespan"), tostring(s.token_lifespan)) end
        if s.token_format then db:put(M.rk("setting:token_format"), s.token_format) end
        if s.brute_force_enabled ~= nil then db:put(M.rk("setting:brute_force_enabled"), s.brute_force_enabled and "true" or "false") end
        if s.max_login_failures then db:put(M.rk("setting:max_login_failures"), tostring(s.max_login_failures)) end
        if s.lockout_duration then db:put(M.rk("setting:lockout_duration"), tostring(s.lockout_duration)) end
        if s.pwd_min_length then db:put(M.rk("setting:pwd_min_length"), tostring(s.pwd_min_length)) end
        if s.pwd_req_upper ~= nil then db:put(M.rk("setting:pwd_req_upper"), s.pwd_req_upper and "true" or "false") end
        if s.pwd_req_lower ~= nil then db:put(M.rk("setting:pwd_req_lower"), s.pwd_req_lower and "true" or "false") end
        if s.pwd_req_number ~= nil then db:put(M.rk("setting:pwd_req_number"), s.pwd_req_number and "true" or "false") end
        if s.pwd_req_symbol ~= nil then db:put(M.rk("setting:pwd_req_symbol"), s.pwd_req_symbol and "true" or "false") end
    end
    
    if import_data.roles and type(import_data.roles) == "table" then
        local rlist = {}
        for _, r in ipairs(import_data.roles) do
            local rname = type(r) == "table" and r.name or r
            local rdesc = type(r) == "table" and r.description or ""
            table.insert(rlist, rname)
            db:put(M.rk("role_def:") .. rname, json.encode({ name = rname, description = rdesc }))
        end
        db:put(M.rk("meta:roles_list"), json.encode(rlist))
    end

    if import_data.groups and type(import_data.groups) == "table" then
        local glist = {}
        for _, g in ipairs(import_data.groups) do
            if type(g) == "table" and g.name then
                table.insert(glist, g.name)
                db:put(M.rk("group_def:") .. g.name, json.encode(g))
            end
        end
        db:put(M.rk("meta:groups_list"), json.encode(glist))
    end
    
    if import_data.users and type(import_data.users) == "table" then
        local ulist_str = db:get(M.rk("meta:user_list"))
        local ulist = ulist_str and json.decode(ulist_str) or {}
        local u_set = {}
        for _, u in ipairs(ulist) do u_set[u] = true end
        
        for _, u in ipairs(import_data.users) do
            if u.username then
                db:put(M.rk("user:") .. u.username, json.encode(u))
                if u.roles then M.set_user_roles(db, u.username, u.roles) end
                if u.groups then M.set_user_groups(db, u.username, u.groups) end
                if not u_set[u.username] then
                    table.insert(ulist, u.username)
                    u_set[u.username] = true
                end
            end
        end
        db:put(M.rk("meta:user_list"), json.encode(ulist))
    end
    
    if import_data.clients and type(import_data.clients) == "table" then
        local clist_str = db:get(M.rk("meta:client_list"))
        local clist = clist_str and json.decode(clist_str) or {}
        local c_set = {}
        for _, c in ipairs(clist) do c_set[c] = true end
        
        for _, c in ipairs(import_data.clients) do
            if c.client_id then
                db:put(M.rk("client:") .. c.client_id, json.encode(c))
                if not c_set[c.client_id] then
                    table.insert(clist, c.client_id)
                    c_set[c.client_id] = true
                end
            end
        end
        db:put(M.rk("meta:client_list"), json.encode(clist))
    end
    
    return true, nil
end

-- ─── Session Management ───────────────────────────────────────────────────────

function M.get_session_user(db)
    local cookie_hdr = request.headers["cookie"] or ""
    local session_id = string.match(cookie_hdr, "ATLAS_SESSION=([^;]+)")
    if not session_id then return nil, nil end
    local username = db:get("session:" .. session_id)
    if not username then return nil, nil end

    -- Session idle timeout policy (per-realm, 0 = disabled)
    local idle_timeout = M.get_session_idle_timeout(db)
    if idle_timeout > 0 then
        local sd_str = db:get("session_data:" .. session_id)
        if sd_str then
            local sd = json.decode(sd_str)
            local last = tonumber(sd and sd.last_access) or os.time()
            if os.time() - last > idle_timeout then
                db:delete("session:" .. session_id)
                db:delete("session_data:" .. session_id)
                return nil, nil
            end
            sd.last_access = os.time()
            db:put("session_data:" .. session_id, json.encode(sd))
        end
    end

    return username, session_id
end

function M.is_admin(db, username)
    local roles = M.get_user_roles(db, username)
    for _, r in ipairs(roles) do
        if r == "admin" then return true end
    end
    return false
end

-- ─── K2: Lazy-Once Initialization ──────────────────────────────────────────

function M.ensure_admin_exists(db)
    -- Create the bootstrap admin only when missing. Never silently reset an
    -- existing admin's credentials from Lua pattern matching.
    if not db:get(M.rk("user:admin")) then
        local admin_data = {
            username = "admin",
            email = "admin@atlascloak.local",
            firstName = "Admin",
            lastName = "User",
            enabled = true,
            createdAt = os.time(),
            -- K2: force password change on first login
            must_change_password = true
        }
        admin_data.password = M.hash_password("admin")
        db:put(M.rk("user:admin"), json.encode(admin_data))
        M.set_user_roles(db, "admin", { "admin", "user" })
    end
    
    if db:get(M.rk("meta:initialized")) == "true" then
        return
    end
    
    local user_list_str = db:get(M.rk("meta:user_list"))
    local user_list = user_list_str and json.decode(user_list_str) or {}
    local has_admin = false
    for _, u in ipairs(user_list) do if u == "admin" then has_admin = true break end end
    if not has_admin then table.insert(user_list, "admin") end
    db:put(M.rk("meta:user_list"), json.encode(user_list))
    
    if not db:get(M.rk("meta:roles_list")) then
        db:put(M.rk("meta:roles_list"), json.encode({ "admin", "user", "editor", "viewer" }))
        db:put("role_def:admin", json.encode({ name = "admin", description = "Administrator with full access" }))
        db:put("role_def:user", json.encode({ name = "user", description = "Standard user with account access" }))
        db:put("role_def:editor", json.encode({ name = "editor", description = "Content editor with write access" }))
        db:put("role_def:viewer", json.encode({ name = "viewer", description = "Read-only access role" }))
    end

    if not db:get(M.rk("meta:groups_list")) then
        db:put(M.rk("meta:groups_list"), json.encode({ "administrators", "developers", "staff" }))
        db:put("group_def:administrators", json.encode({ name = "administrators", description = "System Administrators Group", roles = { "admin", "user" } }))
        db:put("group_def:developers", json.encode({ name = "developers", description = "Development & Engineering Team", roles = { "editor", "user" } }))
        db:put("group_def:staff", json.encode({ name = "staff", description = "General Staff Members", roles = { "viewer", "user" } }))
    end

    if not db:get(M.rk("client:account")) then
        db:put(M.rk("client:account"), json.encode({ client_id = "account", name = "Account Console", client_type = "public", redirect_uris = "/account/*", enabled = true }))
    end
    if not db:get(M.rk("client:admin-console")) then
        db:put(M.rk("client:admin-console"), json.encode({ client_id = "admin-console", name = "Admin Console", client_type = "public", redirect_uris = "/admin/*", enabled = true }))
    end
    if not db:get("client:m2m-service") then
        db:put("client:m2m-service", json.encode({ client_id = "m2m-service", name = "M2M Microservice", client_type = "confidential", secret = "secret123", redirect_uris = "/*", enabled = true }))
        local clist_str = db:get(M.rk("meta:client_list"))
        local clist = clist_str and json.decode(clist_str) or { "account", "admin-console" }
        table.insert(clist, "m2m-service")
        db:put(M.rk("meta:client_list"), json.encode(clist))
    end
    if not db:get("client:test-oidc-client") then
        db:put("client:test-oidc-client", json.encode({ client_id = "test-oidc-client", name = "Test OIDC Client", client_type = "public", redirect_uris = "http://localhost:3000/*, https://oidcdebugger.com/*", enabled = true }))
        local clist_str = db:get(M.rk("meta:client_list"))
        local clist = clist_str and json.decode(clist_str) or { "account", "admin-console", "m2m-service" }
        table.insert(clist, "test-oidc-client")
        db:put(M.rk("meta:client_list"), json.encode(clist))
    end
    
    db:put(M.rk("meta:initialized"), "true")
end

-- ─── Settings ─────────────────────────────────────────────────────────────────

function M.is_registration_enabled(db)
    local val = db:get(M.rk("setting:registration_enabled"))
    if val == nil then return true end
    return val == "true"
end

function M.set_registration_enabled(db, enabled)
    db:put(M.rk("setting:registration_enabled"), enabled and "true" or "false")
end

function M.get_realm_display_name(db)
    local should_close = false
    if not db then
        db = M.get_db()
        should_close = true
    end
    local val = db:get(M.rk("setting:realm_display_name"))
    if should_close then
        db:close()
    end
    if not val or val == "" or val == "Master Realm" then
        return "Atlas"
    end
    return val
end

-- ─── Theme, Custom Logo & Background ──────────────────────────────────────────

function M.get_theme_settings(db)
    local should_close = false
    if not db then
        db = M.get_db()
        should_close = true
    end
    local logo = db:get(M.rk("setting:custom_logo"))
    if not logo or logo == "" then
        logo = "/images/default.png"
    end
    local bg_type = db:get(M.rk("setting:bg_type")) or "gradient"
    local bg_value = db:get(M.rk("setting:bg_value"))
    if not bg_value or bg_value == "" then
        if bg_type == "image" then
            bg_value = ""
        else
            bg_value = "linear-gradient(135deg, #090d16 0%, #0f172a 45%, #1e1b4b 100%)"
        end
    end
    if should_close then db:close() end
    return {
        logo = logo,
        bg_type = bg_type,
        bg_value = bg_value
    }
end

function M.validate_logo_url(logo_url)
    if not logo_url or logo_url == "" then
        return true, nil
    end
    local lower = string.lower(logo_url)
    if string.find(lower, "%.gif") or string.find(lower, "image/gif") then
        return false, "GIF format is not supported for custom logo. Please use PNG, SVG, JPG, or WebP."
    end
    return true, nil
end

-- ─── Reverse Proxy & Real Client IP Detection ────────────────────────────────

-- Strict validators — header values are attacker-controlled, so anything that
-- does not parse as a well-formed address is rejected (prevents audit-log
-- injection of junk like "1.2.3.4<script>" through spoofed proxy headers).

local function valid_ipv4(ip)
    if not ip or #ip > 15 then return false end
    local a, b, c, d = string.match(ip, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    for _, octet in ipairs({ a, b, c, d }) do
        if #octet > 3 then return false end
        if #octet > 1 and string.sub(octet, 1, 1) == "0" then return false end
        if tonumber(octet) > 255 then return false end
    end
    return true
end

local function valid_ipv6(ip)
    if not ip or #ip < 2 or #ip > 45 then return false end
    if not string.match(ip, "^[%x:]+$") then return false end
    -- An embedded IPv4 tail (::ffff:192.168.0.1) is allowed.
    local v4_tail = string.match(ip, ":(%d+%.%d+%.%d+%.%d+)$")
    if v4_tail then
        if not valid_ipv4(v4_tail) then return false end
        ip = string.sub(ip, 1, -(#v4_tail + 1))
        if not string.match(ip, ":$") then return false end
    end
    local _, colons = string.gsub(ip, ":", "")
    if colons < 1 or colons > 7 then return false end
    local _, double = string.gsub(ip, "::", "")
    if double > 1 then return false end
    return true
end

local function valid_ip(ip)
    return valid_ipv4(ip) or valid_ipv6(ip)
end

local function strip_port(ip)
    local v4 = string.match(ip, "^([%d%.]+):%d+$")
    if v4 then return v4 end
    local v6 = string.match(ip, "^%[([%w:%%.-]+)%]:%d+$")
    if v6 then return v6 end
    return ip
end

function M.get_client_ip()
    if not request then return "127.0.0.1" end
    local headers = request.headers or {}
    
    -- 1. Cloudflare Connecting IP
    local cf_ip = strip_port(string.match(headers["cf-connecting-ip"] or "", "^%s*(.-)%s*$") or "")
    if valid_ip(cf_ip) then return cf_ip end
    
    -- 2. True-Client-IP header (Akamai, Cloudflare Enterprise)
    local true_ip = strip_port(string.match(headers["true-client-ip"] or "", "^%s*(.-)%s*$") or "")
    if valid_ip(true_ip) then return true_ip end
    
    -- 3. X-Real-IP header (Nginx, Caddy reverse_proxy, Traefik, HAProxy)
    local real_ip = strip_port(string.match(headers["x-real-ip"] or "", "^%s*(.-)%s*$") or "")
    if valid_ip(real_ip) then return real_ip end
    
    -- 4. X-Forwarded-For — leftmost entry is the original client as injected
    --    by Caddy/nginx/Cloudflare when they terminate the client connection.
    local xff = headers["x-forwarded-for"] or ""
    if xff ~= "" then
        for entry in string.gmatch(xff, "[^,]+") do
            local candidate = strip_port(string.match(entry, "^%s*(.-)%s*$") or "")
            if valid_ip(candidate) then return candidate end
        end
    end
    
    -- 5. RFC 7239 Forwarded header (for=...)
    local fwd = headers["forwarded"] or ""
    if fwd ~= "" then
        local raw_for = string.match(fwd, 'for=%[?%"?([^%]";,]+)')
        if raw_for then
            local candidate = strip_port(string.match(raw_for, "^%s*(.-)%s*$") or "")
            if valid_ip(candidate) then return candidate end
        end
    end
    
    -- 6. Fallback to request.remote_addr (strip port)
    local raw_addr = request.remote_addr or "127.0.0.1"
    local stripped = strip_port(raw_addr)
    if valid_ip(stripped) then return stripped end
    
    return raw_addr
end

-- ─── Security Token & Anti-Bot Protection ────────────────────────────────────

function M.generate_security_token(db, action_type)
    local token = M.uuid()
    local payload = {
        action = action_type,
        created = os.time(),
        exp = os.time() + 600,
        ip = M.get_client_ip()
    }
    db:put("sec_token:" .. token, json.encode(payload))
    return token
end

function M.validate_security_token(db, form, expected_action)
    if form.atlas_hp_field and form.atlas_hp_field ~= "" then
        return false, "Bot activity detected (honeypot triggered)"
    end
    
    local token = form.security_token
    if not token or token == "" then
        return false, "Security token is missing"
    end
    
    local token_data_str = db:get("sec_token:" .. token)
    if not token_data_str then
        return false, "Invalid or expired security token"
    end
    
    db:delete("sec_token:" .. token)
    local token_data = json.decode(token_data_str)
    
    if os.time() > (token_data.exp or 0) then
        return false, "Security token expired. Please reload and try again."
    end
    
    if token_data.action ~= expected_action then
        return false, "Security token mismatch"
    end
    
    return true, nil
end

function M.render_security_fields(token)
    return [[
        <input type="hidden" name="security_token" value="]] .. M.html_escape(token) .. [[">
        <div style="display:none;opacity:0;position:absolute;left:-9999px;width:1px;height:1px;" aria-hidden="true">
            <label for="atlas_hp_field">Leave this empty</label>
            <input type="text" name="atlas_hp_field" id="atlas_hp_field" tabindex="-1" autocomplete="off">
        </div>
    ]]
end

-- ─── Self-Update Helpers ─────────────────────────────────────────────────────

function M.compare_versions(a, b)
    local function parts(v)
        local t = {}
        for n in string.gmatch(tostring(v), "%d+") do table.insert(t, tonumber(n)) end
        return t
    end
    local pa, pb = parts(a), parts(b)
    for i = 1, math.max(#pa, #pb) do
        local x = pa[i] or 0
        local y = pb[i] or 0
        if x ~= y then return x < y and -1 or 1 end
    end
    return 0
end

-- Fetches the version marker from lib/utils.lua on the main branch of the
-- upstream repository. Returns version string or nil + error reason.
function M.fetch_remote_version()
    local handle = io.popen("curl -fsSL --max-time 15 https://raw.githubusercontent.com/COXKPER/AtlasCloak/main/lib/utils.lua 2>/dev/null || wget -qT 15 -O - https://raw.githubusercontent.com/COXKPER/AtlasCloak/main/lib/utils.lua 2>/dev/null")
    if not handle then return nil, "cannot spawn curl/wget process" end
    local content = handle:read("*a") or ""
    handle:close()
    if content == "" then return nil, "empty response (network unreachable?)" end
    local version = string.match(content, 'M%.version%s*=%s*"([^"]+)"')
    if not version then return nil, "upstream file has no version marker" end
    return version
end

-- Reads the version marker from the locally installed public/lib/utils.lua
-- without executing any code.
function M.read_local_version_file()
    local file = io.open("public/lib/utils.lua", "r")
    if not file then return nil end
    local content = file:read("*a")
    file:close()
    return string.match(content, 'M%.version%s*=%s*"([^"]+)"')
end

-- ─── Security Headers ────────────────────────────────────────────────────────

--- Apply hardened response headers. Call once per response before writing
--- the body (renderers call it automatically; protocol endpoints must call
--- it explicitly).
function M.apply_security_headers()
    response:setHeader("X-Content-Type-Options", "nosniff")
    response:setHeader("X-Frame-Options", "DENY")
    response:setHeader("Referrer-Policy", "no-referrer")
    response:setHeader("X-XSS-Protection", "0")
    response:setHeader("Cross-Origin-Opener-Policy", "same-origin")
    response:setHeader("Content-Security-Policy",
        "default-src 'self'; " ..
        "script-src 'self' 'unsafe-inline'; " ..
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " ..
        "font-src 'self' https://fonts.gstatic.com; " ..
        "img-src 'self' data:; " ..
        "connect-src 'self'; " ..
        "frame-ancestors 'none'; " ..
        "base-uri 'self'; " ..
        "form-action 'self'")
end

-- ─── Multi-Realm Support ─────────────────────────────────────────────────────

-- Realm resolution: derived from the request path (/auth/realms/<name>/...).
-- The built-in realm "master" keeps UNPREFIXED database keys so existing
-- deployments keep working without any migration. Every other realm gets its
-- keys namespaced with "realm:<name>:".

M.realm_cache = nil

function M.get_realm()
    if M.realm_cache then return M.realm_cache end
    local name = "master"
    if request and request.path then
        name = string.match(request.path, "^/auth/realms/([^/]+)/") or name
    end
    -- Defensive: only sane realm names are accepted.
    if not name:match("^[%w][%w%-_%.]") then name = "master" end
    M.realm_cache = name
    return name
end

--- URL prefix of the active realm's endpoints.
function M.realm_url()
    return "/auth/realms/" .. M.get_realm()
end

--- Key-namespacing helper: returns the DB key for `key` in the current realm.
function M.rk(key)
    local realm = M.get_realm()
    if realm == "master" then return key end
    return "realm:" .. realm .. ":" .. key
end

--- List of registered realms (always includes implicit "master").
function M.get_realms(db)
    local s = db:get("meta:realms_list")
    local list = s and json.decode(s) or {}
    local out = { "master" }
    for _, r in ipairs(list) do
        if r ~= "master" then table.insert(out, r) end
    end
    return out
end

local function realm_exists(db, name)
    if name == "master" then return true end
    for _, r in ipairs(M.get_realms(db)) do
        if r == name then return true end
    end
    return false
end

--- Create a new realm: registers it and generates Telamon route stubs that
--- relay into the shared master implementations (which self-parameterize by
--- request path). Returns ok, err.
function M.create_realm(db, name)
    if type(name) ~= "string" or not name:match("^%w[%w%-_%.]*$") or #name > 48 then
        return false, "Realm name may only contain letters, digits, '-', '_' and '.' (max 48 chars)"
    end
    if realm_exists(db, name) then return false, "Realm already exists" end

    local list = {}
    for _, r in ipairs(M.get_realms(db)) do
        if r ~= "master" then table.insert(list, r) end
    end
    table.insert(list, name)
    db:put("meta:realms_list", json.encode(list))

    -- Bootstrap realm data under its namespace.
    db:put(M.rk("meta:user_list"), json.encode({}))
    db:put(M.rk("meta:roles_list"), json.encode({ "admin", "user", "editor", "viewer" }))
    db:put(M.rk("role_def:admin"), json.encode({ name = "admin", description = "Administrator with full access" }))
    db:put(M.rk("role_def:user"), json.encode({ name = "user", description = "Standard user with account access" }))
    db:put(M.rk("setting:realm_display_name"), name)

    -- Generate route stubs mirroring the master URL layout.
    local endpoints = {
        ["protocol/openid-connect/auth"] = 1,
        ["protocol/openid-connect/token"] = 1,
        ["protocol/openid-connect/token/introspect"] = 1,
        ["protocol/openid-connect/userinfo"] = 1,
        ["protocol/openid-connect/certs"] = 1,
        ["protocol/openid-connect/consent"] = 1,
        ["protocol/openid-connect/logout"] = 1,
        ["protocol/openid-connect/revoke"] = 1,
        ["protocol/openid-connect/device/authorize"] = 1,
        [".well-known/openid-configuration"] = 1,
        ["login-actions/authenticate"] = 1,
        ["login-actions/registration"] = 1,
        ["login-actions/totp"] = 1,
        ["login-actions/webauthn"] = 1,
    }
    for rel, _ in pairs(endpoints) do
        local path = "public/auth/realms/" .. name .. "/" .. rel .. ".lua"
        local dir = string.match(path, "^(.*)/")
        os.execute("mkdir -p '" .. dir .. "'")
        local f = io.open(path, "w")
        if f then
            f:write('return dofile("public/lib/realm_router.lua").relay("' .. rel .. '")\n')
            f:close()
        end
    end

    local event = {
        type = "REALM_CREATE",
        username = "_system",
        ip = M.get_client_ip(),
        time = os.time(),
        detail = "Created realm: " .. name
    }
    local events_str = db:get(M.rk("meta:events"))
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    db:put(M.rk("meta:events"), json.encode(events))
    return true
end

--- Delete a non-master realm: purges all its namespaced data + stubs.
function M.delete_realm(db, name)
    if name == "master" then return false, "The master realm cannot be deleted" end
    -- Defense-in-depth: the name reaches filesystem paths below.
    if type(name) ~= "string" or not name:match("^%w[%w%-_%.]*$") or #name > 48 then
        return false, "Invalid realm name"
    end
    if not realm_exists(db, name) then return false, "Unknown realm" end

    local list = {}
    for _, r in ipairs(M.get_realms(db)) do
        if r ~= "master" and r ~= name then table.insert(list, r) end
    end
    db:put("meta:realms_list", json.encode(list))

    -- Purge namespaced keys referenced through stored lists, then the
    -- singletons. Unknown keys (e.g. stale codes/tokens) simply expire.
    local sweeps = {
        { M.rk("meta:user_list"),   M.rk("user:") },
        { M.rk("meta:client_list"), M.rk("client:") },
        { M.rk("meta:groups_list"), M.rk("group_def:") },
        { M.rk("meta:roles_list"),  M.rk("role_def:") },
    }
    for _, sw in ipairs(sweeps) do
        local s = db:get(M.rk(sw[1]))
        if s then
            for _, item in ipairs(json.decode(s) or {}) do
                db:delete(M.rk(sw[2] .. item))
            end
        end
        db:delete(M.rk(sw[1]))
    end
    db:delete(M.rk("meta:events"))

    -- Remove route stubs.
    os.execute("rm -rf 'public/auth/realms/" .. name .. "'")

    return true
end

-- ─── TOTP / Two-Factor Helpers ───────────────────────────────────────────────

local totp_mod = dofile("public/lib/totp.lua")

M.totp_verify = function(base32_secret, code) return totp_mod.verify(base32_secret, code, 1, 30) end
M.totp_generate_secret = function() return totp_mod.generate_secret(crypto.random_hex, 20) end
M.totp_otpauth_uri = function(issuer, account, secret) return totp_mod.otpauth_uri(issuer, account, secret) end

function M.get_user_totp(db, username)
    local u = db:get(M.rk("user:" .. username))
    if not u then return nil end
    local ud = json.decode(u)
    if ud and ud.totp and ud.totp.enabled and ud.totp.secret then
        return ud.totp
    end
    return nil
end

--- Rebuild the authorization-endpoint URL from a stored login context so a
--- completed MFA/passkey challenge can resume the original OIDC flow.
function M.build_auth_resume_url(ctx)
    ctx = ctx or {}
    local url = M.realm_url() .. "/protocol/openid-connect/auth?client_id=" .. M.url_encode(ctx.client_id or "") ..
        "&redirect_uri=" .. M.url_encode(ctx.redirect_uri or "") ..
        "&state=" .. M.url_encode(ctx.state or "") ..
        "&response_type=" .. M.url_encode(ctx.response_type or "code") ..
        "&response_mode=" .. M.url_encode(ctx.response_mode or "query") ..
        "&nonce=" .. M.url_encode(ctx.nonce or "") ..
        "&scope=" .. M.url_encode(ctx.scope or "openid")
    if ctx.code_challenge and ctx.code_challenge ~= "" then
        url = url .. "&code_challenge=" .. M.url_encode(ctx.code_challenge) ..
            "&code_challenge_method=" .. M.url_encode(ctx.code_challenge_method or "S256")
    end
    return url
end

--- Capture the full OIDC request context from query parameters.
function M.capture_oidc_context()
    return {
        client_id = request:getParam("client_id"),
        redirect_uri = request:getParam("redirect_uri"),
        state = request:getParam("state"),
        response_type = request:getParam("response_type") or "code",
        response_mode = request:getParam("response_mode") or "query",
        nonce = request:getParam("nonce"),
        scope = request:getParam("scope") or "openid",
        code_challenge = request:getParam("code_challenge"),
        code_challenge_method = request:getParam("code_challenge_method") or "S256"
    }
end

--- Store a short-lived pending-MFA grant after a successful password check.
function M.create_pending_mfa(db, username, context)
    local token = crypto.random_hex(24)
    db:put("mfa_pending:" .. token, json.encode({
        username = username,
        context = context or {},
        created = os.time(),
        exp = os.time() + 180
    }))
    return token
end

--- Peek at a pending-MFA grant without consuming it.
function M.get_pending_mfa(db, token)
    local s = token and db:get("mfa_pending:" .. token) or nil
    if not s then return nil end
    local d = json.decode(s)
    if not d or os.time() > (d.exp or 0) then return nil end
    return d
end

--- Patch a pending-MFA grant in place (e.g. attach an enrollment secret).
function M.update_pending_mfa(db, token, patch)
    local d = M.get_pending_mfa(db, token)
    if not d then return false end
    for k, v in pairs(patch) do d[k] = v end
    db:put("mfa_pending:" .. token, json.encode(d))
    return true
end

function M.consume_pending_mfa(db, token)
    local s = token and db:get("mfa_pending:" .. token) or nil
    if not s then return nil, "invalid_or_expired" end
    db:delete("mfa_pending:" .. token)
    local d = json.decode(s)
    if not d or os.time() > (d.exp or 0) then return nil, "expired" end
    return d
end

--- Create a fully authenticated session for `username` (shared by password,
--- TOTP challenge, passkey, and device-flow logins). Returns the session id.
function M.create_session(db, username)
    local session_id = M.uuid()
    local session_data = {
        username = username,
        realm = M.get_realm(),
        ip = M.get_client_ip(),
        started = os.time(),
        last_access = os.time()
    }
    db:put("session:" .. session_id, username)
    db:put("session_data:" .. session_id, json.encode(session_data))

    local sessions_str = db:get("meta:session_list")
    local sessions = sessions_str and json.decode(sessions_str) or {}
    table.insert(sessions, session_id)
    db:put("meta:session_list", json.encode(sessions))

    local event = {
        type = "LOGIN",
        username = username,
        ip = M.get_client_ip(),
        time = os.time(),
        detail = "Login successful"
    }
    local events_str = db:get(M.rk("meta:events"))
    local events = events_str and json.decode(events_str) or {}
    table.insert(events, event)
    if #events > 100 then
        local trimmed = {}
        for i = #events - 99, #events do table.insert(trimmed, events[i]) end
        events = trimmed
    end
    db:put(M.rk("meta:events"), json.encode(events))
    return session_id
end

-- ─── WebAuthn / Passkey Helpers ──────────────────────────────────────────────

local cbor_mod = dofile("public/lib/cbor.lua")

--- Parse WebAuthn authenticatorData binary:
--- rpIdHash(32) flags(1) signCount(4) [attestedCredentialData] ...
function M.parse_authenticator_data(auth_data)
    if type(auth_data) ~= "string" or #auth_data < 37 then return nil, "authenticatorData too short" end
    local rp_id_hash = auth_data:sub(1, 32)
    local flags = auth_data:byte(33)
    local sign_count = 0
    for i = 34, 37 do sign_count = sign_count * 256 + auth_data:byte(i) end
    local parsed = {
        rp_id_hash = rp_id_hash,
        flags = flags,
        up = (flags % 2) == 1,                       -- bit 0: user present
        uv = math.floor(flags / 4) % 2 == 1,         -- bit 2: user verified
        at = math.floor(flags / 64) % 2 == 1,        -- bit 6: attested credential data present
        sign_count = sign_count
    }
    if parsed.at then
        if #auth_data < 55 then return nil, "truncated attested credential data" end
        local aaguid = auth_data:sub(38, 53)
        local cred_len = auth_data:byte(54) * 256 + auth_data:byte(55)
        if #auth_data < 55 + cred_len then return nil, "truncated credential id" end
        local cred_id = auth_data:sub(56, 55 + cred_len)
        local cose_key, next_pos = cbor_mod.decode_at(auth_data, 56 + cred_len)
        if not cose_key then return nil, "bad COSE key: " .. tostring(next_pos) end
        parsed.aaguid_hex = aaguid:gsub(".", function(c) return string.format("%02x", c:byte()) end)
        parsed.cred_id_b64u = M.base64url_encode(cred_id)
        parsed.cose_key = cose_key
        parsed.next_pos = next_pos
    end
    return parsed
end

--- Extract EC P-256 coordinates (x, y as base64url) from a decoded COSE key.
function M.cose_key_to_xy(cose)
    if type(cose) ~= "table" then return nil end
    -- kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256), x=-2, y=-3
    if cose[1] ~= 2 or cose[-1] ~= 1 then return nil end
    local x, y = cose[-2], cose[-3]
    if type(x) ~= "string" or type(y) ~= "string" then return nil end
    return M.base64url_encode(x), M.base64url_encode(y)
end

--- Store a challenge for later verification.
function M.wa_store_challenge(db, challenge, username, context)
    db:put("wa_challenge:" .. challenge, json.encode({
        username = username,
        context = context or {},
        created = os.time(),
        exp = os.time() + 300
    }))
end

--- Split a DER-encoded ECDSA signature (SEQUENCE{r INTEGER, s INTEGER}) into
--- unpadded-base64url r and s components for the Go bridge.
function M.parse_der_signature(der)
    local data = M.base64url_decode(der or "")
    if data:byte(1) ~= 0x30 then return nil, nil end
    local pos = 3 -- skip 0x30 + total length (assumes < 128 bytes)
    if data:byte(pos) ~= 0x02 then return nil, nil end
    local rlen = data:byte(pos + 1)
    local r = data:sub(pos + 2, pos + 1 + rlen)
    pos = pos + 2 + rlen
    if data:byte(pos) ~= 0x02 then return nil, nil end
    local slen = data:byte(pos + 1)
    local s = data:sub(pos + 2, pos + 1 + slen)
    -- Strip a possible leading zero byte used to mark positive integers.
    if #r > 32 then r = r:sub(-32) end
    if #s > 32 then s = s:sub(-32) end
    while #r < 32 do r = "\0" .. r end
    while #s < 32 do s = "\0" .. s end
    return M.base64url_encode(r), M.base64url_encode(s)
end

--- Consume a stored challenge (single use).
function M.wa_consume_challenge(db, challenge)
    if not challenge or challenge == "" then return nil end
    local s = db:get("wa_challenge:" .. challenge)
    if not s then return nil end
    db:delete("wa_challenge:" .. challenge)
    local d = json.decode(s)
    if not d or os.time() > (d.exp or 0) then return nil end
    return d
end

--- Look up a stored passkey credential by raw id (base64url).
function M.wa_get_credential(db, cred_id_b64u)
    local s = db:get("wa_cred:" .. cred_id_b64u)
    return s and json.decode(s) or nil
end

-- ─── Device Flow (RFC 8628) Helpers ──────────────────────────────────────────

local USER_CODE_CHARS = "BCDFGHJKLMNPQRSTVWXZ2456789" -- unambiguous set

function M.device_generate_codes()
    local hex = crypto.random_hex(32)
    local device_code = hex
    local uc = ""
    local seed_hex = crypto.random_hex(8)
    for i = 1, 8 do
        local v = tonumber(seed_hex:sub(i, i), 16) % #USER_CODE_CHARS + 1
        uc = uc .. USER_CODE_CHARS:sub(v, v)
        if i == 4 then uc = uc .. "-" end
    end
    return device_code, uc
end

function M.device_create_grant(db, client_id, scope)
    local device_code, user_code = M.device_generate_codes()
    db:put("dev:" .. device_code, json.encode({
        user_code = user_code,
        client_id = client_id,
        scope = scope or "",
        status = "pending",
        created = os.time(),
        exp = os.time() + 600,
        last_poll = 0
    }))
    db:put("dev_uc:" .. user_code, device_code)
    return device_code, user_code
end


-- ─── CSS Theme ────────────────────────────────────────────────────────────────

M.css = [[
    :root {
        --bg: #0f172a;
        --bg-card: #1e293b;
        --bg-input: #0f172a;
        --border: #334155;
        --border-focus: #6366f1;
        --text: #e2e8f0;
        --text-muted: #94a3b8;
        --text-heading: #f8fafc;
        --primary: #6366f1;
        --primary-hover: #818cf8;
        --primary-glow: rgba(99, 102, 241, 0.3);
        --success: #22c55e;
        --success-bg: rgba(34, 197, 94, 0.1);
        --danger: #ef4444;
        --danger-bg: rgba(239, 68, 68, 0.1);
        --warning: #f59e0b;
        --warning-bg: rgba(245, 158, 11, 0.1);
        --accent: #06b6d4;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: 'Inter', -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: var(--bg);
        color: var(--text);
        min-height: 100vh;
    }
    .auth-wrapper {
        display: flex;
        min-height: 100vh;
        width: 100%;
        align-items: center;
        justify-content: flex-start;
        padding: 2.5rem 2rem 2.5rem 8vw;
        position: relative;
        overflow-x: hidden;
        background-attachment: fixed;
    }
    .auth-container {
        width: 100%;
        max-width: 440px;
        z-index: 10;
        position: relative;
        animation: fadeIn 0.4s ease-out;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .auth-card {
        background: rgba(15, 23, 42, 0.88);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(51, 65, 85, 0.7);
        border-radius: 18px;
        padding: 2.5rem;
        width: 100%;
        box-shadow: 0 25px 60px rgba(0, 0, 0, 0.55), 0 0 30px rgba(99, 102, 241, 0.1);
    }
    .brand {
        text-align: center;
        margin-bottom: 1.75rem;
    }
    .brand-logo-container {
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 14px;
        min-height: 60px;
    }
    .brand-custom-logo {
        max-height: 64px;
        max-width: 190px;
        width: auto;
        height: auto;
        object-fit: contain;
        filter: drop-shadow(0 6px 16px rgba(0, 0, 0, 0.4));
        transition: transform 0.2s ease;
    }
    .brand-custom-logo:hover {
        transform: scale(1.04);
    }
    .brand-icon {
        width: 56px;
        height: 56px;
        margin: 0 auto;
        background: linear-gradient(135deg, var(--primary), var(--accent));
        border-radius: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 26px;
        color: white;
        box-shadow: 0 8px 24px var(--primary-glow);
    }
    .brand h1 {
        font-size: 22px;
        font-weight: 700;
        color: var(--text-heading);
        letter-spacing: -0.5px;
    }
    .brand p {
        font-size: 13px;
        color: var(--text-muted);
        margin-top: 4px;
    }
    .form-group { margin-bottom: 1.25rem; }
    .form-group label {
        display: block;
        font-size: 13px;
        font-weight: 500;
        color: var(--text-muted);
        margin-bottom: 6px;
    }
    .form-group input, .form-group select, .form-group textarea {
        width: 100%;
        padding: 10px 14px;
        background: var(--bg-input);
        border: 1px solid var(--border);
        border-radius: 10px;
        color: var(--text);
        font-size: 14px;
        transition: border-color 0.2s, box-shadow 0.2s;
        outline: none;
    }
    .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
        border-color: var(--border-focus);
        box-shadow: 0 0 0 3px var(--primary-glow);
    }
    .form-group input::placeholder { color: #475569; }
    .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 10px 20px;
        border-radius: 10px;
        font-size: 14px;
        font-weight: 600;
        border: none;
        cursor: pointer;
        transition: all 0.2s;
        text-decoration: none;
    }
    .btn-primary {
        width: 100%;
        background: linear-gradient(135deg, var(--primary), #4f46e5);
        color: white;
        box-shadow: 0 4px 14px var(--primary-glow);
    }
    .btn-primary:hover {
        background: linear-gradient(135deg, var(--primary-hover), #6366f1);
        transform: translateY(-1px);
        box-shadow: 0 6px 20px var(--primary-glow);
    }
    .btn-secondary {
        background: var(--bg-input);
        color: var(--text);
        border: 1px solid var(--border);
    }
    .btn-secondary:hover { background: var(--border); }
    .btn-danger { background: var(--danger); color: white; }
    .btn-danger:hover { background: #dc2626; }
    .btn-warning { background: var(--warning); color: #000; font-weight: 700; }
    .btn-warning:hover { background: #d97706; }
    .btn-success { background: var(--success); color: white; }
    .btn-success:hover { background: #16a34a; }
    .btn-sm { padding: 6px 12px; font-size: 12px; border-radius: 8px; }
    .btn-ghost {
        background: transparent;
        color: var(--text-muted);
        border: none;
        padding: 6px 12px;
    }
    .btn-ghost:hover { color: var(--text); background: rgba(255,255,255,0.05); }
    .alert {
        padding: 12px 16px;
        border-radius: 10px;
        font-size: 13px;
        margin-bottom: 1.25rem;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .alert-error {
        background: var(--danger-bg);
        color: #fca5a5;
        border: 1px solid rgba(239,68,68,0.2);
    }
    .alert-success {
        background: var(--success-bg);
        color: #86efac;
        border: 1px solid rgba(34,197,94,0.2);
    }
    .alert-warning {
        background: var(--warning-bg);
        color: #fcd34d;
        border: 1px solid rgba(245,158,11,0.2);
    }
    .alert-icon { font-size: 16px; flex-shrink: 0; }
    .divider {
        display: flex;
        align-items: center;
        gap: 16px;
        margin: 1.5rem 0;
        color: var(--text-muted);
        font-size: 12px;
    }
    .divider::before, .divider::after {
        content: '';
        flex: 1;
        height: 1px;
        background: var(--border);
    }
    .footer-links {
        text-align: center;
        margin-top: 1.5rem;
        font-size: 13px;
        color: var(--text-muted);
    }
    .footer-links a {
        color: var(--primary-hover);
        text-decoration: none;
        font-weight: 500;
    }
    .footer-links a:hover { text-decoration: underline; }
    .powered {
        text-align: center;
        margin-top: 2rem;
        font-size: 11px;
        color: #475569;
    }
    .powered a { color: #64748b; text-decoration: none; }

    /* ── Admin Layout ──────────────────────────────────────────────────── */
    .admin-layout { display: flex; min-height: 100vh; }
    .sidebar {
        width: 260px;
        background: var(--bg-card);
        border-right: 1px solid var(--border);
        display: flex;
        flex-direction: column;
        position: fixed;
        top: 0; left: 0; bottom: 0;
        z-index: 50;
    }
    .sidebar-brand {
        padding: 20px 24px;
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .sidebar-brand-icon {
        width: 36px; height: 36px;
        background: linear-gradient(135deg, var(--primary), var(--accent));
        border-radius: 10px;
        display: flex; align-items: center; justify-content: center;
        font-size: 18px;
        color: white;
    }
    .sidebar-brand h2 { font-size: 16px; color: var(--text-heading); font-weight: 700; }
    .sidebar-brand small { font-size: 11px; color: var(--text-muted); }
    .sidebar-nav { flex: 1; padding: 12px; overflow-y: auto; }
    .nav-section { margin-bottom: 8px; }
    .nav-section-title {
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        color: #475569;
        padding: 8px 12px 4px;
        font-weight: 600;
    }
    .nav-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 9px 12px;
        border-radius: 8px;
        color: var(--text-muted);
        text-decoration: none;
        font-size: 13px;
        font-weight: 500;
        transition: all 0.15s;
        margin-bottom: 2px;
    }
    .nav-item:hover { background: rgba(255,255,255,0.05); color: var(--text); }
    .nav-item.active {
        background: rgba(99,102,241,0.15);
        color: var(--primary-hover);
    }
    .nav-icon { font-size: 14px; width: 20px; text-align: center; }
    .sidebar-footer {
        padding: 16px;
        border-top: 1px solid var(--border);
    }
    .user-badge {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 8px;
        border-radius: 10px;
        background: rgba(255,255,255,0.03);
    }
    .user-avatar {
        width: 32px; height: 32px;
        border-radius: 8px;
        background: linear-gradient(135deg, var(--primary), var(--accent));
        display: flex; align-items: center; justify-content: center;
        font-size: 14px; font-weight: 700; color: white;
    }
    .user-info { flex: 1; }
    .user-info .name { font-size: 13px; font-weight: 600; color: var(--text); }
    .user-info .role { font-size: 11px; color: var(--text-muted); }
    .main-content {
        flex: 1;
        margin-left: 260px;
        padding: 0;
    }
    .topbar {
        padding: 16px 32px;
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: var(--bg-card);
    }
    .topbar h1 { font-size: 18px; font-weight: 700; color: var(--text-heading); }
    .topbar-actions { display: flex; gap: 8px; align-items: center; }
    .content-area { padding: 32px; }

    /* ── Cards & Tables ────────────────────────────────────────────── */
    .card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        overflow: hidden;
    }
    .card-header {
        padding: 16px 20px;
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .card-header h3 { font-size: 15px; font-weight: 600; color: var(--text-heading); }
    .card-body { padding: 20px; }
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .stat-icon {
        width: 48px; height: 48px;
        border-radius: 12px;
        display: flex; align-items: center; justify-content: center;
        font-size: 20px;
    }
    .stat-icon-users { background: rgba(99,102,241,0.15); color: var(--primary-hover); }
    .stat-icon-sessions { background: rgba(34,197,94,0.15); color: var(--success); }
    .stat-icon-clients { background: rgba(245,158,11,0.15); color: var(--warning); }
    .stat-icon-events { background: rgba(6,182,212,0.15); color: var(--accent); }
    .stat-value { font-size: 28px; font-weight: 700; color: var(--text-heading); }
    .stat-label { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th {
        text-align: left;
        padding: 10px 16px;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: #475569;
        font-weight: 600;
        border-bottom: 1px solid var(--border);
        background: rgba(0,0,0,0.15);
    }
    td {
        padding: 12px 16px;
        font-size: 13px;
        border-bottom: 1px solid rgba(51,65,85,0.5);
        color: var(--text);
    }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 600;
    }
    .badge-success { background: var(--success-bg); color: var(--success); border: 1px solid rgba(34,197,94,0.2); }
    .badge-danger { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }
    .badge-warning { background: var(--warning-bg); color: var(--warning); border: 1px solid rgba(245,158,11,0.2); }
    .badge-info { background: rgba(99,102,241,0.1); color: var(--primary-hover); border: 1px solid rgba(99,102,241,0.2); }

    /* ── Toggle Switch ─────────────────────────────────────────────── */
    .toggle-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(51,65,85,0.5);
    }
    .toggle-row:last-child { border-bottom: none; }
    .toggle-label { font-size: 14px; color: var(--text); }
    .toggle-desc { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
    .toggle {
        position: relative;
        width: 44px; height: 24px;
        cursor: pointer;
    }
    .toggle input { opacity: 0; width: 0; height: 0; }
    .toggle-slider {
        position: absolute;
        top: 0; left: 0; right: 0; bottom: 0;
        background: #475569;
        border-radius: 24px;
        transition: 0.3s;
    }
    .toggle-slider::before {
        content: '';
        position: absolute;
        width: 18px; height: 18px;
        left: 3px; bottom: 3px;
        background: white;
        border-radius: 50%;
        transition: 0.3s;
    }
    .toggle input:checked + .toggle-slider { background: var(--primary); }
    .toggle input:checked + .toggle-slider::before { transform: translateX(20px); }

    /* ── Tabs & Subsections ────────────────────────────────────────── */
    .tab-bar { display: flex; gap: 8px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
    .tab-btn {
        padding: 10px 16px;
        font-size: 13px;
        font-weight: 600;
        color: var(--text-muted);
        border: none;
        background: none;
        cursor: pointer;
        border-bottom: 2px solid transparent;
        text-decoration: none;
    }
    .tab-btn:hover { color: var(--text); }
    .tab-btn.active { color: var(--primary-hover); border-bottom-color: var(--primary); }

    /* ── Misc ──────────────────────────────────────────────────────── */
    .empty-state {
        text-align: center;
        padding: 48px 24px;
        color: var(--text-muted);
    }
    .empty-state .icon { font-size: 40px; margin-bottom: 12px; color: var(--text-muted); }
    .empty-state h3 { color: var(--text); margin-bottom: 4px; font-size: 16px; }
    .empty-state p { font-size: 13px; }
    .tag-row { display: flex; gap: 6px; flex-wrap: wrap; }
    .row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .row-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
    .text-right { text-align: right; }
    code {
        padding: 2px 6px;
        background: rgba(99,102,241,0.1);
        border-radius: 4px;
        font-size: 12px;
        color: var(--primary-hover);
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
    }
    @media (max-width: 768px) {
        .sidebar { display: none; }
        .main-content { margin-left: 0; }
        .stat-grid { grid-template-columns: 1fr 1fr; }
        .row-2, .row-3 { grid-template-columns: 1fr; }
        .auth-wrapper {
            justify-content: center !important;
            align-items: center !important;
            padding: 1.5rem 1rem !important;
        }
        .auth-container {
            max-width: 100% !important;
            margin: 0 auto !important;
        }
        .auth-card {
            padding: 1.75rem 1.25rem !important;
            border-radius: 16px !important;
        }
    }
]]

-- ─── Layout Renderers ─────────────────────────────────────────────────────────

function M.render_auth_page(title, subtitle, content, db)
    M.apply_security_headers()
    local theme = M.get_theme_settings(db)
    local realm_name = M.get_realm_display_name(db)
    local tab_title = realm_name .. " - AtlasCloak"
    if title and title ~= "" and title ~= "AtlasCloak" then
        tab_title = title .. " - " .. realm_name .. " - AtlasCloak"
    end

    local brand_sub = subtitle or (realm_name .. " Identity Provider")

    local bg_style = ""
    if theme.bg_type == "image" and theme.bg_value ~= "" then
        bg_style = "background: url('" .. M.html_escape(theme.bg_value) .. "') center center / cover no-repeat fixed, #0f172a;"
    else
        local bg_val = theme.bg_value
        if not bg_val or bg_val == "" then
            bg_val = "linear-gradient(135deg, #090d16 0%, #0f172a 45%, #1e1b4b 100%)"
        end
        bg_style = "background: " .. bg_val .. ";"
    end

    return [[<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>]] .. M.html_escape(tab_title) .. [[</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/vendor/fontawesome/css/all.min.css">
    <style>]] .. M.css .. [[</style>
</head>
<body>
    <div class="auth-wrapper" style="]] .. bg_style .. [[">
        <div class="auth-container">
            <div class="auth-card">
                <div class="brand">
                    <div class="brand-logo-container">
                        <img src="]] .. M.html_escape(theme.logo) .. [[" alt="Logo" class="brand-custom-logo" onerror="this.style.display='none';var fb=document.getElementById('fallback-brand-icon');if(fb)fb.style.display='flex';">
                        <div id="fallback-brand-icon" class="brand-icon" style="display:none;"><i class="fa-solid fa-shield-halved"></i></div>
                    </div>
                    <h1>]] .. M.html_escape(title) .. [[</h1>
                    <p>]] .. M.html_escape(brand_sub) .. [[</p>
                </div>
                ]] .. content .. [[
            </div>
            <div class="powered">
                This <a href="https://github.com/COXKPER/AtlasCloak" target="_blank" rel="noopener">AtlasCloak</a> is licensed under <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener">GNU AGPLv3</a> • v]] .. M.version .. [[ (]] .. M.html_escape(realm_name) .. [[) on Telamon
            </div>
        </div>
    </div>
</body>
</html>]]
end

function M.render_admin_page(title, active_nav, admin_user, content, db)
    M.apply_security_headers()
    local theme = M.get_theme_settings(db)
    local realm_name = M.get_realm_display_name(db)
    local tab_title = title .. " - " .. realm_name .. " - AtlasCloak Admin"

    local initial = "A"
    if admin_user and #admin_user > 0 then
        initial = string.upper(string.sub(admin_user, 1, 1))
    end

    local function nav_class(name)
        if name == active_nav then return 'nav-item active' end
        return 'nav-item'
    end

    return [[<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>]] .. M.html_escape(tab_title) .. [[</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/vendor/fontawesome/css/all.min.css">
    <style>]] .. M.css .. [[</style>
</head>
<body>
    <div class="admin-layout">
        <aside class="sidebar">
            <div class="sidebar-brand">
                <div class="sidebar-brand-icon">
                    <img src="]] .. M.html_escape(theme.logo) .. [[" style="width:26px;height:26px;object-fit:contain;" onerror="this.style.display='none';var sbi=this.parentElement.querySelector('i');if(sbi)sbi.style.display='inline-block';">
                    <i class="fa-solid fa-shield-halved" style="display:none;"></i>
                </div>
                <div>
                    <h2>AtlasCloak</h2>
                    <small>Admin Console (]] .. M.html_escape(realm_name) .. [[)</small>
                </div>
            </div>
            <nav class="sidebar-nav">
                <div class="nav-section">
                    <div class="nav-section-title">General</div>
                    <a href="/admin" class="]] .. nav_class("dashboard") .. [["><span class="nav-icon"><i class="fa-solid fa-gauge-high"></i></span> Dashboard</a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Manage</div>
                    <a href="/admin/users" class="]] .. nav_class("users") .. [["><span class="nav-icon"><i class="fa-solid fa-users"></i></span> Users</a>
                    <a href="/admin/groups" class="]] .. nav_class("groups") .. [["><span class="nav-icon"><i class="fa-solid fa-layer-group"></i></span> Groups (GBAC)</a>
                    <a href="/admin/roles" class="]] .. nav_class("roles") .. [["><span class="nav-icon"><i class="fa-solid fa-user-shield"></i></span> Roles (RBAC)</a>
                    <a href="/admin/clients" class="]] .. nav_class("clients") .. [["><span class="nav-icon"><i class="fa-solid fa-cubes"></i></span> Clients</a>
                    <a href="/admin/sessions" class="]] .. nav_class("sessions") .. [["><span class="nav-icon"><i class="fa-solid fa-link"></i></span> Sessions</a>
                    <a href="/admin/events" class="]] .. nav_class("events") .. [["><span class="nav-icon"><i class="fa-solid fa-clock-rotate-left"></i></span> Events</a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Configure</div>
                    <a href="/admin/realm-settings" class="]] .. nav_class("realm-settings") .. [["><span class="nav-icon"><i class="fa-solid fa-sliders"></i></span> Realm Settings</a>
                    <a href="/admin/realm-settings?tab=theme" class="]] .. nav_class("theme") .. [["><span class="nav-icon"><i class="fa-solid fa-palette"></i></span> Theme & Branding</a>
                    <a href="/admin/whitelist" class="]] .. nav_class("whitelist") .. [["><span class="nav-icon"><i class="fa-solid fa-list-check"></i></span> URI Whitelist</a>
                    <a href="/admin/realm-settings?tab=updates" class="]] .. nav_class("updates") .. [["><span class="nav-icon"><i class="fa-solid fa-cloud-arrow-up"></i></span> System Updates</a>
                </div>
            </nav>
            <div class="sidebar-footer">
                <div class="user-badge">
                    <div class="user-avatar">]] .. initial .. [[</div>
                    <div class="user-info">
                        <div class="name">]] .. M.html_escape(admin_user or "admin") .. [[</div>
                        <div class="role">Administrator</div>
                    </div>
                </div>
                <a href="/admin/logout" class="btn btn-ghost" style="width:100%;margin-top:8px;font-size:12px;"><i class="fa-solid fa-right-from-bracket"></i> Sign Out</a>
                <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);font-size:11px;color:var(--text-muted);text-align:center;">
                    This <a href="https://github.com/COXKPER/AtlasCloak" target="_blank" style="color:var(--primary-hover);text-decoration:none;">AtlasCloak</a> is licensed under <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" style="color:var(--text-muted);text-decoration:underline;">GNU AGPLv3</a>
                </div>
            </div>
        </aside>
        <div class="main-content">
            <div class="topbar">
                <h1>]] .. M.html_escape(title) .. [[</h1>
                <div class="topbar-actions">
                    <span style="font-size:12px;color:var(--text-muted);"><i class="fa-solid fa-shield"></i> Realm: <strong style="color:var(--text);">master (]] .. M.html_escape(realm_name) .. [[)</strong></span>
                </div>
            </div>
            <div class="content-area">
                ]] .. content .. [[
            </div>
        </div>
    </div>
</body>
</html>]]
end

function M.render_account_page(title, active_nav, user_data, content, db)
    M.apply_security_headers()
    local realm_name = M.get_realm_display_name(db)
    local tab_title = title .. " - " .. realm_name .. " - AtlasCloak Account"

    local initial = "U"
    local username = user_data and user_data.username or "user"
    if username and #username > 0 then
        initial = string.upper(string.sub(username, 1, 1))
    end

    local function nav_class(name)
        if name == active_nav then return 'nav-item active' end
        return 'nav-item'
    end

    local display_name = username
    if user_data and user_data.firstName and user_data.firstName ~= "" then
        display_name = user_data.firstName .. " " .. (user_data.lastName or "")
    end

    local theme = M.get_theme_settings(db)

    return [[<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>]] .. M.html_escape(tab_title) .. [[</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/vendor/fontawesome/css/all.min.css">
    <style>]] .. M.css .. [[</style>
</head>
<body>
    <div class="admin-layout">
        <aside class="sidebar">
            <div class="sidebar-brand">
                <div class="sidebar-brand-icon">
                    <img src="]] .. M.html_escape(theme.logo) .. [[" style="width:26px;height:26px;object-fit:contain;" onerror="this.style.display='none';var sbi=this.parentElement.querySelector('i');if(sbi)sbi.style.display='inline-block';">
                    <i class="fa-solid fa-shield-halved" style="display:none;"></i>
                </div>
                <div>
                    <h2>AtlasCloak</h2>
                    <small>Account Console (]] .. M.html_escape(realm_name) .. [[)</small>
                </div>
            </div>
            <nav class="sidebar-nav">
                <div class="nav-section">
                    <div class="nav-section-title">Account</div>
                    <a href="/account" class="]] .. nav_class("profile") .. [["><span class="nav-icon"><i class="fa-solid fa-user"></i></span> Personal Info</a>
                    <a href="/account/password" class="]] .. nav_class("password") .. [["><span class="nav-icon"><i class="fa-solid fa-key"></i></span> Password</a>
                    <a href="/account/twofactor" class="]] .. nav_class("twofactor") .. [["><span class="nav-icon"><i class="fa-solid fa-mobile-screen"></i></span> Two-Factor (TOTP)</a>
                    <a href="/account/passkeys" class="]] .. nav_class("passkeys") .. [["><span class="nav-icon"><i class="fa-solid fa-fingerprint"></i></span> Passkeys</a>
                    <a href="/account/sessions" class="]] .. nav_class("sessions") .. [["><span class="nav-icon"><i class="fa-solid fa-desktop"></i></span> Device Sessions</a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Navigation</div>
                    <a href="/" class="nav-item"><span class="nav-icon"><i class="fa-solid fa-house"></i></span> Home</a>
                    <a href="/admin" class="nav-item"><span class="nav-icon"><i class="fa-solid fa-sliders"></i></span> Admin Console</a>
                </div>
            </nav>
            <div class="sidebar-footer">
                <div class="user-badge">
                    <div class="user-avatar">]] .. initial .. [[</div>
                    <div class="user-info">
                        <div class="name">]] .. M.html_escape(display_name) .. [[</div>
                        <div class="role">@]] .. M.html_escape(username) .. [[</div>
                    </div>
                </div>
                <a href="/account/logout" class="btn btn-ghost" style="width:100%;margin-top:8px;font-size:12px;"><i class="fa-solid fa-right-from-bracket"></i> Sign Out</a>
                <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);font-size:11px;color:var(--text-muted);text-align:center;">
                    This <a href="https://github.com/COXKPER/AtlasCloak" target="_blank" style="color:var(--primary-hover);text-decoration:none;">AtlasCloak</a> is licensed under <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" style="color:var(--text-muted);text-decoration:underline;">GNU AGPLv3</a>
                </div>
            </div>
        </aside>
        <div class="main-content">
            <div class="topbar">
                <h1>]] .. M.html_escape(title) .. [[</h1>
                <div class="topbar-actions">
                    <span class="badge badge-info"><i class="fa-solid fa-shield"></i> Realm: master (]] .. M.html_escape(realm_name) .. [[)</span>
                </div>
            </div>
            <div class="content-area">
                ]] .. content .. [[
            </div>
        </div>
    </div>
</body>
</html>]]
end

return M
