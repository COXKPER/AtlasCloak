-- AtlasCloak — minimal CBOR decoder (RFC 8949) sufficient for WebAuthn
-- attestationObject / authenticatorData parsing.
-- Supports: unsigned & negative integers, byte strings, text strings,
-- arrays, maps, and tags (tag value skipped, payload returned).

local M = {}

local function decode_head(data, pos)
    local ib = data:byte(pos)
    if not ib then return nil, pos, "unexpected end of data" end
    local mt, ai = math.floor(ib / 32), ib % 32 -- 3 high bits = type, 5 low = info
    return mt, ai, pos + 1
end

local function read_len(data, pos, ai)
    if ai < 24 then return ai, pos end
    local n = 2 ^ (ai - 24)
    if pos + n - 1 > #data then return nil, pos, "truncated length" end
    local v = 0
    for i = 0, n - 1 do v = v * 256 + data:byte(pos + i) end
    return v, pos + n
end

local dec -- forward

local function decode_bytes(data, pos, len)
    if pos + len - 1 > #data then return nil, pos, "truncated byte string" end
    return data:sub(pos, pos + len - 1), pos + len
end

dec = function(data, pos, depth)
    depth = depth or 0
    if depth > 16 then return nil, pos, "nesting too deep" end
    local mt, ai, npos = decode_head(data, pos)
    if not mt then return nil, npos, ai end

    -- Indefinite length is not used by WebAuthn; reject early.
    if ai == 31 then return nil, npos, "indefinite lengths unsupported" end

    if mt == 0 then -- unsigned integer
        local v, p2 = read_len(data, npos, ai)
        if not v then return nil, p2, "bad uint" end
        return v, p2
    elseif mt == 1 then -- negative integer
        local v, p2 = read_len(data, npos, ai)
        if not v then return nil, p2, "bad negint" end
        return -1 - v, p2
    elseif mt == 2 then -- byte string
        local len, p2 = read_len(data, npos, ai)
        if not len then return nil, p2, "bad bstr len" end
        local s, p3 = decode_bytes(data, p2, len)
        if not s then return nil, p3, "truncated bstr" end
        return s, p3
    elseif mt == 3 then -- text string
        local len, p2 = read_len(data, npos, ai)
        if not len then return nil, p2, "bad tstr len" end
        local s, p3 = decode_bytes(data, p2, len)
        if not s then return nil, p3, "truncated tstr" end
        return s, p3
    elseif mt == 4 then -- array
        local len, p2 = read_len(data, npos, ai)
        if not len then return nil, p2, "bad arr len" end
        local arr = {}
        for _ = 1, len do
            local item, p3 = dec(data, p2, depth + 1)
            if item == nil then return nil, p3, "bad array item" end
            arr[#arr + 1] = item
            p2 = p3
        end
        return arr, p2
    elseif mt == 5 then -- map
        local len, p2 = read_len(data, npos, ai)
        if not len then return nil, p2, "bad map len" end
        local map = {}
        for _ = 1, len do
            local k, p3 = dec(data, p2, depth + 1)
            if k == nil then return nil, p3, "bad map key" end
            local v, p4 = dec(data, p3, depth + 1)
            if v == nil then return nil, p4, "bad map value" end
            map[k] = v
            p2 = p4
        end
        return map, p2
    elseif mt == 6 then -- tag — skip tag number, decode payload
        local _, p2 = read_len(data, npos, ai)
        return dec(data, p2, depth + 1)
    elseif mt == 7 then -- simple/float — only false/true needed here
        if ai == 20 then return false, npos end
        if ai == 21 then return true, npos end
        if ai == 22 then return cjson_null_marker or nil, npos end
        return nil, npos, "unsupported simple value"
    end
    return nil, npos, "unreachable"
end

--- Decode the first CBOR value in `data` starting at byte 1.
--- Returns value, next_pos, err.
function M.decode(data)
    if type(data) ~= "string" or #data == 0 then return nil, nil, "empty input" end
    return dec(data, 1)
end

--- Decode starting at a specific byte position (used for embedded structures
--- such as COSE keys inside authenticatorData).
function M.decode_at(data, pos)
    return dec(data, pos)
end

return M
