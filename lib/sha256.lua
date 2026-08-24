-- Pure Lua SHA-256 and HMAC-SHA-256 Implementation for Telamon / GopherLua
local M = {}

local MOD = 2^32

local function band(a, b)
    local res = 0
    local p = 1
    for _ = 1, 32 do
        local ra, rb = a % 2, b % 2
        if ra == 1 and rb == 1 then res = res + p end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
        if a == 0 or b == 0 then break end
    end
    return res
end

local function bxor(a, b)
    local res = 0
    local p = 1
    while a > 0 or b > 0 do
        local ra, rb = a % 2, b % 2
        if ra ~= rb then res = res + p end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end
    return res
end

local function bnot(n)
    return (MOD - 1) - n
end

local function rrotate(n, s)
    local p = 2^s
    local low = n % p
    return math.floor(n / p) + low * (2^(32 - s))
end

local function rshift(n, s)
    return math.floor(n / (2^s))
end

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

function M.sha256_raw(msg)
    local H = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    }

    local len = #msg
    local bit_len = len * 8
    local pad_len = (56 - (len + 1) % 64) % 64
    local padded = msg .. "\128" .. string.rep("\0", pad_len)
    
    local high_len = math.floor(bit_len / (2^32))
    local low_len = bit_len % (2^32)
    
    local function num_to_4bytes(n)
        return string.char(
            math.floor(n / 0x1000000) % 0x100,
            math.floor(n / 0x10000) % 0x100,
            math.floor(n / 0x100) % 0x100,
            n % 0x100
        )
    end

    padded = padded .. num_to_4bytes(high_len) .. num_to_4bytes(low_len)

    for i = 1, #padded, 64 do
        local chunk = string.sub(padded, i, i + 63)
        local W = {}
        for j = 1, 16 do
            local p = (j - 1) * 4 + 1
            local b1, b2, b3, b4 = string.byte(chunk, p, p + 3)
            W[j] = b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
        end
        for j = 17, 64 do
            local s0 = bxor(bxor(rrotate(W[j - 15], 7), rrotate(W[j - 15], 18)), rshift(W[j - 15], 3))
            local s1 = bxor(bxor(rrotate(W[j - 2], 17), rrotate(W[j - 2], 19)), rshift(W[j - 2], 10))
            W[j] = (W[j - 16] + s0 + W[j - 7] + s1) % MOD
        end

        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]

        for j = 1, 64 do
            local S1 = bxor(bxor(rrotate(e, 6), rrotate(e, 11)), rrotate(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local temp1 = (h + S1 + ch + K[j] + W[j]) % MOD
            local S0 = bxor(bxor(rrotate(a, 2), rrotate(a, 13)), rrotate(a, 22))
            local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
            local temp2 = (S0 + maj) % MOD

            h = g
            g = f
            f = e
            e = (d + temp1) % MOD
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % MOD
        end

        H[1] = (H[1] + a) % MOD
        H[2] = (H[2] + b) % MOD
        H[3] = (H[3] + c) % MOD
        H[4] = (H[4] + d) % MOD
        H[5] = (H[5] + e) % MOD
        H[6] = (H[6] + f) % MOD
        H[7] = (H[7] + g) % MOD
        H[8] = (H[8] + h) % MOD
    end

    local out = ""
    for j = 1, 8 do
        out = out .. num_to_4bytes(H[j])
    end
    return out
end

function M.sha256_hex(msg)
    local raw = M.sha256_raw(msg)
    local hex = ""
    for i = 1, #raw do
        hex = hex .. string.format("%02x", string.byte(raw, i))
    end
    return hex
end

function M.hmac_sha256_raw(key, msg)
    local block_size = 64
    if #key > block_size then
        key = M.sha256_raw(key)
    end
    if #key < block_size then
        key = key .. string.rep("\0", block_size - #key)
    end

    local o_key_pad = ""
    local i_key_pad = ""
    for i = 1, block_size do
        local b = string.byte(key, i)
        o_key_pad = o_key_pad .. string.char(bxor(b, 0x5c))
        i_key_pad = i_key_pad .. string.char(bxor(b, 0x36))
    end

    return M.sha256_raw(o_key_pad .. M.sha256_raw(i_key_pad .. msg))
end

function M.hmac_sha256_hex(key, msg)
    local raw = M.hmac_sha256_raw(key, msg)
    local hex = ""
    for i = 1, #raw do
        hex = hex .. string.format("%02x", string.byte(raw, i))
    end
    return hex
end

return M
