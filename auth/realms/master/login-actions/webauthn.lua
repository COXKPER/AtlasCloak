local utils = dofile("public/lib/utils.lua")
utils.apply_security_headers()

local db = utils.get_db()
local policies = utils.get_policies(db)

if not policies.passkeys_enabled then
    db:close()
    response:setStatus(404)
    response:write("Passkey authentication is disabled on this realm")
    return
end

-- ── POST: verify an assertion ────────────────────────────────────────────────
if request.method == "POST" then
    local ok_json, assertion = pcall(json.decode, request.body or "")
    if not ok_json or type(assertion) ~= "table" then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_request", error_description = "Malformed assertion" })
        return
    end

    local resp = assertion.response or {}
    local cred_id_b64u = assertion.id or ""
    local cred = utils.wa_get_credential(db, cred_id_b64u)

    if not cred then
        db:close()
        response:setStatus(401)
        response:json({ error = "unknown_credential", error_description = "Passkey not recognized" })
        return
    end

    -- Consume the single-use challenge bound at options time.
    local client_data = resp.clientDataJSON or ""
    local cd_ok, cd = pcall(json.decode, utils.base64url_decode(client_data))
    if not cd_ok or type(cd) ~= "table" then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_request", error_description = "Bad clientDataJSON" })
        return
    end

    local challenge_rec = utils.wa_consume_challenge(db, tostring(cd.challenge))
    if not challenge_rec then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_request", error_description = "Challenge expired or unknown" })
        return
    end

    -- Parse authenticator data and verify rpIdHash + user-present flag.
    local auth_data_bin = utils.base64url_decode(resp.authenticatorData or "")
    local parsed, perr = utils.parse_authenticator_data(auth_data_bin)
    if not parsed then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_request", error_description = perr })
        return
    end
    if not parsed.up then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_request", error_description = "User presence flag missing" })
        return
    end

    local host = (utils.get_base_url():match("^https?://([^/]+)")) or (request.host or "")
    local rp_id = host:match("^[^:]+") or host   -- rpId has no port per WebAuthn spec
    local expected_rpid = crypto.sha256_raw(rp_id)
    if parsed.rp_id_hash ~= expected_rpid then
        db:close()
        response:setStatus(400)
        response:json({ error = "invalid_request", error_description = "rpId mismatch" })
        return
    end

    -- ES256 signature over authenticatorData || SHA256(clientDataJSON).
    local signed = auth_data_bin .. crypto.sha256_raw(utils.base64url_decode(client_data))
    local sig_r, sig_s = utils.parse_der_signature(resp.signature or "")
    local sig_ok = false
    if sig_r and sig_s then
        sig_ok = crypto.p256_verify(signed, sig_r, sig_s, cred.x, cred.y)
    end

    -- Increment signCount (clone detection: must not go backwards).
    local count_ok = true
    if cred.sign_count and parsed.sign_count and parsed.sign_count > 0 then
        count_ok = parsed.sign_count >= cred.sign_count
    end

    if not sig_ok or not count_ok then
        local event = {
            type = "PASSKEY_FAILED",
            username = cred.username,
            ip = utils.get_client_ip(),
            time = os.time(),
            detail = sig_ok and "Sign counter regression detected" or "Invalid passkey signature"
        }
        local events_str = db:get(utils.rk("meta:events"))
        local events = events_str and json.decode(events_str) or {}
        table.insert(events, event)
        db:put(utils.rk("meta:events"), json.encode(events))
        db:close()
        response:setStatus(401)
        response:json({ error = "verification_failed", error_description = "Signature verification failed" })
        return
    end

    -- Update counter.
    cred.sign_count = parsed.sign_count or (cred.sign_count or 0)
    local u_str = db:get(utils.rk("user:") .. cred.username)
    if u_str then
        local ud = json.decode(u_str)
        ud.passkeys = ud.passkeys or {}
        for _, pk in ipairs(ud.passkeys) do
            if pk.cred_id == cred_id_b64u then pk.sign_count = cred.sign_count end
        end
        db:put(utils.rk("user:") .. cred.username, json.encode(ud))
    end

    local session_id = utils.create_session(db, cred.username)
    db:close()

    response:setHeader("Set-Cookie", "ATLAS_SESSION=" .. session_id .. "; Path=/; HttpOnly; SameSite=Lax")
    response:json({
        ok = true,
        redirect = utils.build_auth_resume_url(challenge_rec.context or {})
    })
    return
end

-- ── GET ?options=: PublicKeyCredentialRequestOptions ─────────────────────────
local _opt = request:getParam("options") or ""
if request.method == "GET" and _opt ~= "" then
    local host = (utils.get_base_url():match("^https?://([^/]+)")) or (request.host or "localhost")
    response:json({
        challenge = _opt,
        rpId = (host:match("^[^:]+")) or host,
        allowCredentials = {},
        timeout = 120000,
        userVerification = "preferred"
    })
    return
end

-- ── GET: render passkey login page with fresh challenge ──────────────────────
local challenge = crypto.random_b64url(32)
utils.wa_store_challenge(db, challenge, nil, utils.capture_oidc_context())
local rp_name = utils.get_realm_display_name(db)
db:close()

local html = [[<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Passkey Sign-In</title>
<link rel="stylesheet" href="/vendor/fontawesome/css/all.min.css">
<style>]] .. utils.css .. [[</style>
</head>
<body>
<div class="auth-wrapper">
    <div class="auth-container">
        <div class="auth-card">
            <div class="brand">
                <div class="brand-icon"><i class="fa-solid fa-fingerprint"></i></div>
                <h1>Passkey Sign-In</h1>
                <p>Use your fingerprint, face, or device PIN for ]] .. utils.html_escape(rp_name) .. [[</p>
            </div>
            <div id="status" class="alert alert-info"><span class="alert-icon"><i class="fa-solid fa-circle-info"></i></span> Preparing passkey request…</div>
            <button id="btn" class="btn btn-primary" style="width:100%;" onclick="startLogin()" disabled>
                <i class="fa-solid fa-fingerprint"></i> Sign in with a Passkey
            </button>
            <div class="footer-links">
                <a href="#" onclick="history.back();return false;">Use password instead</a>
            </div>
        </div>
        <div class="powered">AtlasCloak Passkeys · WebAuthn (FIDO2)</div>
    </div>
</div>
<script>
const CHALLENGE = "]] .. challenge .. [[";
function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const b=atob(s);const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer;}
function bufToB64u(buf){const b=new Uint8Array(buf);let s='';for(const x of b)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function startLogin(){
  try{
    document.getElementById('status').innerHTML='<span class="alert-icon"><i class="fa-solid fa-spinner fa-spin"></i></span> Waiting for authenticator…';
    const opts = await fetch(location.pathname+'?options='+encodeURIComponent(CHALLENGE)).then(r=>r.json());
    const cred = await navigator.credentials.get({
      publicKey:{challenge:b64uToBuf(opts.challenge),timeout:120000,userVerification:'preferred',rpId:opts.rpId,
        allowCredentials:(opts.allowCredentials||[]).map(c=>({type:'public-key',id:b64uToBuf(c)}))}
    });
    const res = await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,
      response:{clientDataJSON:bufToB64u(cred.response.clientDataJSON),authenticatorData:bufToB64u(cred.response.authenticatorData),signature:bufToB64u(cred.response.signature),userHandle:cred.response.userHandle?bufToB64u(cred.response.userHandle):null}
    })});
    const out = await res.json();
    if(out.ok && out.redirect){location.href=out.redirect;return;}
    throw new Error(out.error_description||'Login failed');
  }catch(e){
    document.getElementById('status').className='alert alert-error';
    document.getElementById('status').innerHTML='<span class="alert-icon">✕</span> '+e.message;
    document.getElementById('btn').disabled=false;
  }
}
(async()=>{try{
  const opts = await fetch(location.pathname+'?options='+encodeURIComponent(CHALLENGE)).then(r=>r.json());
  window.__opts = opts;
  if(!window.PublicKeyCredential){throw new Error('This browser does not support passkeys');}
  document.getElementById('status').className='alert alert-success';
  document.getElementById('status').innerHTML='<span class="alert-icon"><i class="fa-solid fa-check"></i></span> Ready — touch your authenticator';
  document.getElementById('btn').disabled=false;
}catch(e){document.getElementById('status').className='alert alert-warning';document.getElementById('status').innerHTML='<span class="alert-icon">!</span> '+e.message;}
})();
</script>
</body>
</html>]]

response:write(html)