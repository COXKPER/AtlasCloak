-- AtlasCloak TOTP (RFC 6238) + HOTP (RFC 4226) — pure Lua implementation.
-- Uses HMAC-SHA1 (the default algorithm of Google Authenticator, Aegis,
-- FreeOTP, 1Password, etc.) with base32 secrets (RFC 4648).

local M = {}

-- ─── SHA-1 ───────────────────────────────────────────────────────────────────

-- Bitwise helpers operating on 32-bit values (Lua 5.1-safe, table-driven)
local function tobits(v)
    local t = {}
    for i = 0, 31 do t[i] = v % 2 ; v = (v - (v % 2)) / 2 end
    return t
end
local function frombits(t)
    local v = 0
    for i = 31, 0, -1 do v = v * 2 + t[i] end
    return v
end
local function op_and(a, b)
    local ta, tb = tobits(a), tobits(b)
    local t = {}
    for i = 0, 31 do t[i] = (ta[i] == 1 and tb[i] == 1) and 1 or 0 end
    return frombits(t)
end
local function op_or(a, b)
    local ta, tb = tobits(a), tobits(b)
    local t = {}
    for i = 0, 31 do t[i] = (ta[i] == 1 or tb[i] == 1) and 1 or 0 end
    return frombits(t)
end
local function op_xor(a, b)
    local ta, tb = tobits(a), tobits(b)
    local t = {}
    for i = 0, 31 do t[i] = (ta[i] ~= tb[i]) and 1 or 0 end
    return frombits(t)
end
local function op_not(a)
    local ta = tobits(a)
    local t = {}
    for i = 0, 31 do t[i] = (ta[i] == 1) and 0 or 1 end
    return frombits(t)
end
local function lrotate(v, n)
    n = n % 32
    return op_or((v * (2 ^ n)) % 2 ^ 32, math.floor(v / 2 ^ (32 - n)))
end

local function str2words(msg)
    local words = {}
    for i = 1, #msg, 4 do
        local a, b, c, d = msg:byte(i, i + 3)
        words[#words + 1] = (a or 0) * 2 ^ 24 + (b or 0) * 2 ^ 16 + (c or 0) * 2 ^ 8 + (d or 0)
    end
    return words
end

--- Raw 20-byte SHA-1 digest (binary-safe; HMAC needs the raw inner hash).
function M.sha1_raw(msg)
    local h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    local ml = #msg * 8
    msg = msg .. "\128"
    while #msg % 64 ~= 56 do msg = msg .. "\0" end
    local l1 = math.floor(ml / 2 ^ 32) % 2 ^ 32
    local l0 = ml % 2 ^ 32
    msg = msg .. string.char(
        math.floor(l1 / 2 ^ 24) % 256, math.floor(l1 / 2 ^ 16) % 256, math.floor(l1 / 2 ^ 8) % 256, l1 % 256,
        math.floor(l0 / 2 ^ 24) % 256, math.floor(l0 / 2 ^ 16) % 256, math.floor(l0 / 2 ^ 8) % 256, l0 % 256)

    for chunk_start = 1, #msg, 64 do
        local w = {}
        local cs = chunk_start
        for i = 0, 15 do
            w[i] = msg:byte(cs) * 2 ^ 24 + msg:byte(cs + 1) * 2 ^ 16 + msg:byte(cs + 2) * 2 ^ 8 + msg:byte(cs + 3)
            cs = cs + 4
        end
        for i = 16, 79 do
            w[i] = lrotate(op_xor(op_xor(w[i - 3], w[i - 8]), op_xor(w[i - 14], w[i - 16])), 1)
        end
        local a, b, c, d, e = h0, h1, h2, h3, h4
        for i = 0, 79 do
            local f, k
            if i < 20 then
                f = op_or(op_and(b, c), op_and(op_not(b), d)); k = 0x5A827999
            elseif i < 40 then
                f = op_xor(op_xor(b, c), d); k = 0x6ED9EBA1
            elseif i < 60 then
                f = op_or(op_or(op_and(b, c), op_and(b, d)), op_and(c, d)); k = 0x8F1BBCDC
            else
                f = op_xor(op_xor(b, c), d); k = 0xCA62C1D6
            end
            local temp = (lrotate(a, 5) + f + e + k + w[i]) % 2 ^ 32
            e, d, c, b, a = d, c, lrotate(b, 30), a, temp
        end
        h0 = (h0 + a) % 2 ^ 32
        h1 = (h1 + b) % 2 ^ 32
        h2 = (h2 + c) % 2 ^ 32
        h3 = (h3 + d) % 2 ^ 32
        h4 = (h4 + e) % 2 ^ 32
    end
    return string.char(
        math.floor(h0 / 2 ^ 24) % 256, math.floor(h0 / 2 ^ 16) % 256, math.floor(h0 / 2 ^ 8) % 256, h0 % 256,
        math.floor(h1 / 2 ^ 24) % 256, math.floor(h1 / 2 ^ 16) % 256, math.floor(h1 / 2 ^ 8) % 256, h1 % 256,
        math.floor(h2 / 2 ^ 24) % 256, math.floor(h2 / 2 ^ 16) % 256, math.floor(h2 / 2 ^ 8) % 256, h2 % 256,
        math.floor(h3 / 2 ^ 24) % 256, math.floor(h3 / 2 ^ 16) % 256, math.floor(h3 / 2 ^ 8) % 256, h3 % 256,
        math.floor(h4 / 2 ^ 24) % 256, math.floor(h4 / 2 ^ 16) % 256, math.floor(h4 / 2 ^ 8) % 256, h4 % 256)
end

function M.sha1(msg)
    return (M.sha1_raw(msg):gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

function M.hmac_sha1(key, message)
    if #key > 64 then key = M.sha1_raw(key) end
    while #key < 64 do key = key .. "\0" end
    local o_key_pad, i_key_pad = "", ""
    for i = 1, 64 do
        local k = key:byte(i)
        o_key_pad = o_key_pad .. string.char(op_xor(k, 0x5c))
        i_key_pad = i_key_pad .. string.char(op_xor(k, 0x36))
    end
    return M.sha1(o_key_pad .. M.sha1_raw(i_key_pad .. message))
end

-- ─── Base32 (RFC 4648, no padding on encode) ────────────────────────────────

local B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

function M.base32_decode(data)
    data = data:gsub("[=%s]", ""):upper()
    local bytes, bits = {}, {}
    for i = 1, #data do
        local pos = B32:find(data:sub(i, i), 1, true)
        if not pos then return nil, "invalid base32 character" end
        local v = pos - 1
        for b = 4, 0, -1 do bits[#bits + 1] = math.floor(v / 2 ^ b) % 2 end
    end
    for i = 1, #bits - 7, 8 do
        local byte = 0
        for j = 0, 7 do byte = byte * 2 + bits[i + j] end
        bytes[#bytes + 1] = string.char(byte)
    end
    return table.concat(bytes)
end

function M.base32_encode(data)
    local bits = {}
    for i = 1, #data do
        local b = data:byte(i)
        for j = 7, 0, -1 do bits[#bits + 1] = math.floor(b / 2 ^ j) % 2 end
    end
    while #bits % 5 ~= 0 do bits[#bits + 1] = 0 end
    local out = {}
    for i = 1, #bits, 5 do
        local v = 0
        for j = 0, 4 do v = v * 2 + bits[i + j] end
        out[#out + 1] = B32:sub(v + 1, v + 1)
    end
    return table.concat(out)
end

-- ─── HOTP / TOTP ─────────────────────────────────────────────────────────────

local function hotp(secret_bytes, counter)
    local msg = string.char(
        math.floor(counter / 2 ^ 56) % 256, math.floor(counter / 2 ^ 48) % 256,
        math.floor(counter / 2 ^ 40) % 256, math.floor(counter / 2 ^ 32) % 256,
        math.floor(counter / 2 ^ 24) % 256, math.floor(counter / 2 ^ 16) % 256,
        math.floor(counter / 2 ^ 8) % 256, counter % 256)
    local digest = M.hmac_sha1(secret_bytes, msg)
    local offset = (tonumber(digest:sub(-1), 16) % 16) * 2 + 1
    local bin = tonumber(digest:sub(offset, offset + 7), 16)
    local code = (bin % 2 ^ 31) % 10 ^ 6   -- & 0x7fffffff per RFC 4226 §5.3
    return string.format("%06d", code)
end

--- Verify a TOTP code against a base32 secret with ±window steps (default ±1 ≈ ±30 s).
--- Returns true / false.
function M.verify(base32_secret, code, window, timestep)
    window = window or 1
    timestep = timestep or 30
    if not base32_secret or not code or not code:match("^%d%d%d%d%d%d$") then return false end
    local secret_bytes, err = M.base32_decode(base32_secret)
    if not secret_bytes then return false end
    local counter = math.floor(os.time() / timestep)
    for delta = -window, window do
        if hotp(secret_bytes, counter + delta) == code then return true end
    end
    return false
end

--- Generate a new random base32 secret (n random bytes, default 20).
function M.generate_secret(random_hex_fn, num_bytes)
    num_bytes = num_bytes or 20
    local hex = random_hex_fn(num_bytes)
    local raw = {}
    for i = 1, #hex, 2 do
        raw[#raw + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
    end
    return M.base32_encode(table.concat(raw))
end

--- Build an otpauth:// provisioning URI.
function M.otpauth_uri(issuer, account, base32_secret)
    local label = issuer .. ":" .. account
    return "otpauth://totp/" .. label ..
        "?secret=" .. base32_secret ..
        "&issuer=" .. issuer ..
        "&algorithm=SHA1&digits=6&period=30"
end

-- Test-only exports (harmless; used by offline RFC-vector harness)
M._xor = op_xor
M._and = op_and

return M
