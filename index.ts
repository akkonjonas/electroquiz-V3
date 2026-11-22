// @ts-nocheck
/* Electro Quiz · API (Supabase Edge Function "api")
   - Cuentas con huella digital (WebAuthn / passkeys) + código de activación de un solo uso.
   - Guarda el progreso de cada alumno en la base de datos.
   Secretos necesarios (Supabase > Edge Functions > Secrets):
     ADMIN_KEY  clave del panel de administrador (la elegís vos)
     RP_ID      dominio de tu página, sin https:// (ej.: miusuario.github.io)
     ORIGIN     dirección completa de tu página, sin barra final (ej.: https://miusuario.github.io)
*/

/* ================= utilidades ================= */
const enc = new TextEncoder();
const b64u = (buf) => { const b = new Uint8Array(buf); let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64u = (s) => { s = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const bin = atob(s); const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o; };
const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
const hex = (u8) => [...u8].map(x => x.toString(16).padStart(2, "0")).join("");
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const safeEq = (a, b) => { a = String(a); b = String(b); let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/* ---- CBOR mínimo (lo que necesita WebAuthn) ---- */
function cbor(u8, off = 0) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const type = u8[off] >> 5, info = u8[off] & 31; off++;
  let n = info;
  if (info === 24) { n = u8[off]; off += 1; }
  else if (info === 25) { n = dv.getUint16(off); off += 2; }
  else if (info === 26) { n = dv.getUint32(off); off += 4; }
  else if (info === 27) { n = Number(dv.getBigUint64(off)); off += 8; }
  else if (info > 27) throw new Error("cbor");
  if (type === 0) return [n, off];
  if (type === 1) return [-1 - n, off];
  if (type === 2) return [u8.slice(off, off + n), off + n];
  if (type === 3) return [new TextDecoder().decode(u8.slice(off, off + n)), off + n];
  if (type === 4) { const a = []; for (let i = 0; i < n; i++) { const [v, o] = cbor(u8, off); a.push(v); off = o; } return [a, off]; }
  if (type === 5) { const m = new Map(); for (let i = 0; i < n; i++) { const [k, o1] = cbor(u8, off); const [v, o2] = cbor(u8, o1); m.set(k, v); off = o2; } return [m, off]; }
  if (type === 7) return [info === 20 ? false : info === 21 ? true : null, off];
  throw new Error("cbor tipo");
}

/* ---- WebAuthn: verificación ---- */
function parseClientData(b64, type, challenge, origin) {
  const raw = unb64u(b64);
  const cd = JSON.parse(new TextDecoder().decode(raw));
  if (cd.type !== type) throw new Error("tipo inválido");
  if (cd.challenge !== challenge) throw new Error("desafío inválido");
  if (cd.origin !== origin) throw new Error("origen inválido");
  return raw;
}
async function checkAuthData(ad, rpId, needAttested) {
  if (ad.length < 37) throw new Error("authData corta");
  if (!eq(ad.slice(0, 32), await sha256(rpId))) throw new Error("dominio inválido");
  const flags = ad[32];
  if (!(flags & 0x01)) throw new Error("falta presencia");
  if (!(flags & 0x04)) throw new Error("falta verificación de huella");
  if (needAttested && !(flags & 0x40)) throw new Error("sin credencial");
  const counter = new DataView(ad.buffer, ad.byteOffset + 33, 4).getUint32(0);
  return { flags, counter };
}
async function verifyRegistration(cred, challenge, rpId, origin) {
  parseClientData(cred.response.clientDataJSON, "webauthn.create", challenge, origin);
  const [att] = cbor(unb64u(cred.response.attestationObject));
  const ad = att.get("authData");
  const { counter } = await checkAuthData(ad, rpId, true);
  let p = 37 + 16;
  const idLen = (ad[p] << 8) | ad[p + 1]; p += 2;
  const credId = ad.slice(p, p + idLen); p += idLen;
  const [cose] = cbor(ad, p);
  const kty = cose.get(1), alg = cose.get(3);
  let jwk;
  if (kty === 2 && alg === -7) jwk = { kty: "EC", crv: "P-256", x: b64u(cose.get(-2)), y: b64u(cose.get(-3)) };
  else if (kty === 3 && alg === -257) jwk = { kty: "RSA", n: b64u(cose.get(-1)), e: b64u(cose.get(-2)), alg: "RS256" };
  else throw new Error("algoritmo no soportado");
  if (b64u(credId) !== cred.id) throw new Error("id inconsistente");
  return { id: b64u(credId), jwk, alg, counter };
}
function derToRaw(der, size = 32) {
  let o = 2; if (der[1] & 0x80) o = 2 + (der[1] & 0x7f);
  const rd = () => { o++; let l = der[o++]; let v = der.slice(o, o + l); o += l; while (v.length > size && v[0] === 0) v = v.slice(1); const out = new Uint8Array(size); out.set(v, size - v.length); return out; };
  const r = rd(), s = rd(); const out = new Uint8Array(size * 2); out.set(r, 0); out.set(s, size); return out;
}
async function verifyAssertion(cred, stored, challenge, rpId, origin) {
  const cdRaw = parseClientData(cred.response.clientDataJSON, "webauthn.get", challenge, origin);
  const ad = unb64u(cred.response.authenticatorData);
  const { counter } = await checkAuthData(ad, rpId, false);
  const signed = new Uint8Array([...ad, ...(await sha256(cdRaw))]);
  const sig = unb64u(cred.response.signature);
  let ok;
  if (stored.alg === -7) {
    const key = await crypto.subtle.importKey("jwk", stored.public_key, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(sig), signed);
  } else {
    const key = await crypto.subtle.importKey("jwk", stored.public_key, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, signed);
  }
  if (!ok) throw new Error("firma inválida");
  const old = Number(stored.counter);
  if ((counter !== 0 || old !== 0) && counter <= old) throw new Error("contador inválido (posible copia)");
  return counter;
}

/* ================= lógica ================= */
const ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const newCode = () => { const r = rnd(8); let s = ""; for (const x of r) s += ALPHA[x % 32]; return s; };
const showCode = (c) => c.slice(0, 4) + "-" + c.slice(4);
const normCode = (c) => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const hashCode = (c) => sha256("code:" + normCode(c)).then(hex);
const validName = (n) => typeof n === "string" && /^[\p{L}\p{N} ._-]{2,20}$/u.test(n.trim());
const nameKey = (n) => n.trim().replace(/\s+/g, " ").toLowerCase();
const cleanName = (n) => n.trim().replace(/\s+/g, " ");
class Fail extends Error { constructor(msg, status = 400) { super(msg); this.status = status; } }

async function newSession(q, userId) {
  const token = b64u(rnd(32));
  await q("insert into sessions(token_hash,user_id,expires_at) values($1,$2,now()+interval '30 days')", [hex(await sha256("tok:" + token)), userId]);
  await q("delete from sessions where expires_at < now()");
  return token;
}
async function userFromToken(q, token) {
  if (!token) throw new Fail("Sesión no válida", 401);
  const r = await q("select u.id,u.name from sessions s join users u on u.id=s.user_id where s.token_hash=$1 and s.expires_at>now()", [hex(await sha256("tok:" + token))]);
  if (!r.length) throw new Fail("Sesión vencida. Volvé a entrar con tu huella.", 401);
  return r[0];
}
function scoreOf(data) {
  const L = (data && data.levels) || {}; let pts = 0, st = 0, done = 0;
  for (const k in L) { const v = L[k] || {}; pts += +v.score || 0; st += +v.stars || 0; if ((+v.pct || 0) >= 70 && k !== "F" && !/^U/.test(k)) done++; }
  return { pts, st, done };
}

export async function handle(body, q, env) {
  const RP_ID = env.RP_ID, ORIGIN = env.ORIGIN;
  const a = body.action;

  /* ---------- registro ---------- */
  if (a === "reg_begin") {
    if (!validName(body.name)) throw new Fail("Escribí un nombre de 2 a 20 letras o números.");
    const name = cleanName(body.name);
    const ch = normCode(body.code);
    if (ch.length !== 8) throw new Fail("El código tiene 8 letras y números.");
    const h = await hashCode(ch);
    const c = (await q("select * from codes where code_hash=$1", [h]))[0];
    if (!c || c.used_at || new Date(c.expires_at) < new Date()) throw new Fail("Código inválido o ya usado. Pedile uno nuevo al profesor.");
    let userId;
    if (c.for_user) {
      const u = (await q("select id,name from users where id=$1", [c.for_user]))[0];
      if (!u || nameKey(u.name) !== nameKey(name)) throw new Fail("Este código es para otra cuenta.");
      userId = u.id;
    } else {
      if ((await q("select 1 from users where name_key=$1", [nameKey(name)])).length) throw new Fail("Ese nombre ya está en uso. Elegí otro.");
      userId = crypto.randomUUID();
    }
    const challenge = b64u(rnd(32));
    const cid = (await q("insert into challenges(kind,challenge,payload) values('reg',$1,$2::jsonb) returning id", [challenge, JSON.stringify({ name, userId, code_hash: h })]))[0].id;
    await q("delete from challenges where expires_at < now()");
    return { cid, options: {
      challenge, rp: { name: "Electro Quiz", id: RP_ID },
      user: { id: b64u(enc.encode(userId)), name, displayName: name },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred" },
      attestation: "none", timeout: 120000 } };
  }
  if (a === "reg_finish") {
    const ch = (await q("delete from challenges where id=$1 and kind='reg' and expires_at>now() returning *", [body.cid]))[0];
    if (!ch) throw new Fail("Se venció el intento. Probá de nuevo.");
    const { name, userId, code_hash } = ch.payload;
    let info;
    try { info = await verifyRegistration(body.credential, ch.challenge, RP_ID, ORIGIN); } catch (e) { throw new Fail("No se pudo verificar la huella: " + e.message); }
    // 1) consumir el código (un solo uso, de forma atómica)
    const used = await q("update codes set used_at=now(), used_by=$2 where code_hash=$1 and used_at is null and expires_at>now() returning for_user", [code_hash, userId]);
    if (!used.length) throw new Fail("Ese código ya fue usado.");
    // 2) crear usuario o reiniciar el existente
    if (used[0].for_user) {
      await q("delete from credentials where user_id=$1", [userId]);
      await q("delete from sessions where user_id=$1", [userId]);
    } else {
      const ins = await q("insert into users(id,name,name_key) values($1,$2,$3) on conflict do nothing returning id", [userId, name, nameKey(name)]);
      if (!ins.length) { await q("update codes set used_at=null, used_by=null where code_hash=$1", [code_hash]); throw new Fail("Ese nombre ya está en uso. Elegí otro."); }
    }
    await q("insert into credentials(id,user_id,public_key,alg,counter) values($1,$2,$3::jsonb,$4,$5)", [info.id, userId, JSON.stringify(info.jwk), info.alg, info.counter]);
    return { token: await newSession(q, userId), name };
  }

  /* ---------- ingreso con huella ---------- */
  if (a === "login_begin") {
    if (!validName(body.name)) throw new Fail("Escribí tu nombre.");
    const u = (await q("select id,name from users where name_key=$1", [nameKey(body.name)]))[0];
    if (!u) throw new Fail("No existe esa cuenta. Si sos nuevo, tocá «Crear cuenta».");
    const creds = await q("select id from credentials where user_id=$1", [u.id]);
    if (!creds.length) throw new Fail("Tu cuenta está esperando un código nuevo. Pedíselo al profesor y tocá «Crear cuenta».");
    const challenge = b64u(rnd(32));
    const cid = (await q("insert into challenges(kind,challenge,payload) values('login',$1,$2::jsonb) returning id", [challenge, JSON.stringify({ userId: u.id })]))[0].id;
    return { cid, options: { challenge, rpId: RP_ID, timeout: 120000, userVerification: "required",
      allowCredentials: creds.map(c => ({ type: "public-key", id: c.id, transports: ["internal"] })) } };
  }
  if (a === "login_finish") {
    const ch = (await q("delete from challenges where id=$1 and kind='login' and expires_at>now() returning *", [body.cid]))[0];
    if (!ch) throw new Fail("Se venció el intento. Probá de nuevo.");
    const stored = (await q("select * from credentials where id=$1 and user_id=$2", [body.credential && body.credential.id, ch.payload.userId]))[0];
    if (!stored) throw new Fail("Esta huella no está registrada en tu cuenta.", 401);
    let counter;
    try { counter = await verifyAssertion(body.credential, stored, ch.challenge, RP_ID, ORIGIN); } catch (e) { throw new Fail("No se pudo verificar la huella: " + e.message, 401); }
    await q("update credentials set counter=$2 where id=$1", [stored.id, counter]);
    const u = (await q("select name from users where id=$1", [ch.payload.userId]))[0];
    return { token: await newSession(q, ch.payload.userId), name: u.name };
  }

  /* ---------- progreso ---------- */
  if (a === "load") {
    const u = await userFromToken(q, body.token);
    const r = (await q("select data,updated_at from progress where user_id=$1", [u.id]))[0];
    return { name: u.name, data: r ? r.data : null, updated_at: r ? r.updated_at : null };
  }
  if (a === "save") {
    const u = await userFromToken(q, body.token);
    const s = JSON.stringify(body.data || {});
    if (s.length > 300000) throw new Fail("Datos demasiado grandes.");
    await q("insert into progress(user_id,data,updated_at) values($1,$2::jsonb,now()) on conflict (user_id) do update set data=excluded.data, updated_at=now()", [u.id, s]);
    return { ok: true };
  }
  if (a === "ranking") {
    await userFromToken(q, body.token);
    const rows = await q("select u.name, p.data from users u join progress p on p.user_id=u.id");
    return { ranking: rows.map(r => ({ n: r.name, ...scoreOf(r.data) })).sort((x, y) => y.pts - x.pts || y.st - x.st || x.n.localeCompare(y.n)) };
  }
  if (a === "logout") {
    if (body.token) await q("delete from sessions where token_hash=$1", [hex(await sha256("tok:" + body.token))]);
    return { ok: true };
  }

  /* ---------- administrador ---------- */
  if (a && a.startsWith("admin_")) {
    if (!env.ADMIN_KEY || !safeEq(body.key || "", env.ADMIN_KEY)) { await sleep(1200); throw new Fail("Clave de administrador incorrecta.", 403); }
    if (a === "admin_create_code") {
      const code = newCode();
      await q("insert into codes(code_hash,label) values($1,$2)", [await hashCode(code), String(body.label || "").slice(0, 60)]);
      return { code: showCode(code) };
    }
    if (a === "admin_list") {
      const users = await q("select u.id,u.name,u.created_at,(select count(*) from credentials c where c.user_id=u.id)::int as devices, p.updated_at, p.data from users u left join progress p on p.user_id=u.id order by u.created_at desc");
      const codes = await q("select label,created_at,expires_at,used_at,for_user from codes order by created_at desc limit 100");
      return { users: users.map(u => ({ id: u.id, name: u.name, created_at: u.created_at, devices: u.devices, updated_at: u.updated_at, ...scoreOf(u.data) })), codes };
    }
    if (a === "admin_reset") {
      const u = (await q("select id,name from users where id=$1", [body.user_id]))[0];
      if (!u) throw new Fail("Usuario inexistente.");
      await q("delete from credentials where user_id=$1", [u.id]);
      await q("delete from sessions where user_id=$1", [u.id]);
      const code = newCode();
      await q("insert into codes(code_hash,label,for_user) values($1,$2,$3)", [await hashCode(code), "Reinicio de " + u.name, u.id]);
      return { code: showCode(code), name: u.name };
    }
    if (a === "admin_delete_user") {
      await q("delete from users where id=$1", [body.user_id]);
      return { ok: true };
    }
  }
  throw new Fail("Acción desconocida.", 404);
}

/* ================= servidor (Supabase) ================= */
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type, authorization, apikey, x-client-info", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...CORS, "content-type": "application/json" } });

if (typeof Deno !== "undefined" && Deno.serve) {
  let sql = null;
  const q = async (text, params = []) => {
    if (!sql) { const { default: postgres } = await import("npm:postgres@3.4.4"); sql = postgres(Deno.env.get("SUPABASE_DB_URL"), { max: 3, prepare: false }); }
    return await sql.unsafe(text, params);
  };
  Deno.serve(async (req) => {
    if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
    try {
      const body = await req.json();
      const env = { RP_ID: Deno.env.get("RP_ID"), ORIGIN: Deno.env.get("ORIGIN"), ADMIN_KEY: Deno.env.get("ADMIN_KEY") };
      return json(await handle(body, q, env));
    } catch (e) {
      if (e instanceof Fail) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: "Error del servidor." }, 500);
    }
  });
}
