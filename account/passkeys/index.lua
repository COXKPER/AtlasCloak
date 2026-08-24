local utils = dofile("public/lib/utils.lua")
utils.apply_security_headers()

local db = utils.get_db()
utils.ensure_admin_exists(db)

local username, _ = utils.get_session_user(db)
if not username then
    db:close()
    response:redirect("/auth/realms/master/protocol/openid-connect/auth?client_id=account&redirect_uri=/account/passkeys", 302)
    return
end

if not utils.get_policies(db).passkeys_enabled then
    db:close()
    response:setStatus(404)
    response:write("Passkeys are disabled on this realm")
    return
end

local msg_html = ""


local function load_user(db)
    local s = db:get(utils.rk("user:") .. username)
    return s and json.decode(s) or {}
end

-- ── GET ?options=1 → PublicKeyCredentialCreationOptions ──────────────────────
local _opt = request:getParam("options") or ""
if request.method == "GET" and _opt ~= "" then
    local challenge = crypto.random_b64url(32)
    local ud = load_user(db)
    local existing = {}
    for _, pk in ipairs(ud.passkeys or {}) do table.insert(existing, pk.cred_id) end
    local rp_host = (utils.get_base_url():match("^https?://([^/]+)")) or (request.host or "localhost")
    local rp_id = rp_host:match("^[^:]+") or rp_host   -- WebAuthn rpId excludes the port
    utils.wa_store_challenge(db, challenge, username)
    db:close()

    -- NOTE: an empty Lua table encodes as a JSON object, not an array, so
    -- excludeCredentials is omitted entirely when there are no credentials.
    local payload = {
        challenge = challenge,
        rp = { name = "AtlasCloak (" .. utils.get_realm_display_name(db) .. ")", id = rp_id },
        user = {
            id = utils.base64url_encode(username),
            name = (ud.email and ud.email ~= "" and ud.email) or username,
            displayName = ((ud.firstName or "") .. " " .. (ud.lastName or "")):gsub("^%s+", "")
        },
        pubKeyCredParams = { { type = "public-key", alg = -7 } },
        timeout = 120000,
        authenticatorSelection = { residentKey = "preferred", userVerification = "preferred" },
        attestation = "none"
    }
    if #existing > 0 then payload.excludeCredentials = existing end
    response:json(payload)
    return
end

-- ── Form actions (delete) ─────────────────────────────────────────────────────
if request.method == "POST" and request:getParam("action") ~= "register" then
    local form = utils.parse_form(request.body)
    if form.action == "delete" and form.cred_id then
        local ud = load_user(db)
        local kept = {}
        for _, pk in ipairs(ud.passkeys or {}) do
            if pk.cred_id ~= form.cred_id then table.insert(kept, pk) end
        end
        ud.passkeys = kept
        db:put(utils.rk("user:") .. username, json.encode(ud))
        db:delete(utils.rk("wa_cred:" .. form.cred_id))
        msg_html = '<div class="alert alert-success"><span class="alert-icon">✓</span> Passkey removed.</div>'
    end
end

-- ── Render page ───────────────────────────────────────────────────────────────
local ud = load_user(db)
local rows = ""
for _, pk in ipairs(ud.passkeys or {}) do
    rows = rows .. [[
        <tr>
            <td><i class="fa-solid fa-fingerprint" style="color:var(--accent);margin-right:8px;"></i><code style="font-size:11px;">]] .. utils.html_escape(pk.cred_id:sub(1, 16)) .. [[…</code></td>
            <td>]] .. utils.html_escape(pk.label or "-") .. [[</td>
            <td>
                <form method="POST" action="/account/passkeys" style="display:inline;">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="cred_id" value="]] .. utils.html_escape(pk.cred_id) .. [[">
                    <button type="submit" class="btn btn-sm btn-danger"><i class="fa-solid fa-trash"></i> Remove</button>
                </form>
            </td>
        </tr>
    ]]
end
if rows == "" then
    rows = '<tr><td colspan="3" class="empty-state">No passkeys registered yet</td></tr>'
end
db:close()

local content = msg_html .. [[
    <div class="card">
        <div class="card-header"><h3><i class="fa-solid fa-fingerprint" style="margin-right:8px;"></i> Your Passkeys</h3></div>
        <div class="card-body">
            <p style="font-size:13px;color:var(--text-muted);margin-bottom:14px;">
                Passkeys let you sign in with fingerprint, face, or device PIN — no password needed.
            </p>
            <div style="overflow-x:auto;">
                <table>
                    <thead><tr><th>Credential</th><th>Added</th><th></th></tr></thead>
                    <tbody>]] .. rows .. [[</tbody>
                </table>
            </div>
            <button id="enroll-btn" class="btn btn-primary" style="margin-top:18px;" onclick="enrollPasskey()" disabled>
                <i class="fa-solid fa-plus"></i> Register New Passkey
            </button>
            <div id="status" style="font-size:12px;color:var(--text-muted);margin-top:10px;"></div>
        </div>
    </div>
    <script>
    function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const b=atob(s);const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer;}
    function bufToB64u(buf){const b=new Uint8Array(buf);let s='';for(const x of b)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
    const statusEl=document.getElementById('status');
    async function enrollPasskey(){
      try{
        statusEl.textContent='Waiting for authenticator…';
        const opts=await fetch(location.pathname+'?options=1').then(r=>r.json());
        opts.challenge=b64uToBuf(opts.challenge);
        opts.user.id=b64uToBuf(opts.user.id);
        // defensive: some encoders emit {} instead of [] for empty lists
        let exc = opts.excludeCredentials;
        if (!Array.isArray(exc)) exc = [];
        opts.excludeCredentials = exc.map(c=>({type:'public-key',id:b64uToBuf(c)}));
        const cred=await navigator.credentials.create({publicKey:opts});
        const res=await fetch('/account/passkeys/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
          id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,
          response:{clientDataJSON:bufToB64u(cred.response.clientDataJSON),attestationObject:bufToB64u(cred.response.attestationObject)}
        })});
        const out=await res.json();
        if(out.ok){location.reload();return;}
        throw new Error(out.error||'Registration failed');
      }catch(e){statusEl.textContent='Error: '+e.message;}
    }
    (async()=>{ if(window.PublicKeyCredential){document.getElementById('enroll-btn').disabled=false;} else {statusEl.textContent='This browser does not support passkeys.';} })();
    </script>
]]
response:write(utils.render_account_page("Passkeys", "passkeys", ud, content))