/* Radar de Fornecedores - UM ÚNICO ARQUIVO (servidor com login + site)
   Requer Node 18+. Sem dependências.
   Uso:  node radar.js
   O site inteiro está no final deste arquivo (variável APP_HTML).          */
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const criarML = require("./ml.js");

const PORT = parseInt(process.env.PORT || "3000", 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const STRICT_IP = process.env.STRICT_IP === "1";
const ONE_ACCOUNT_PER_IP = process.env.ONE_ACCOUNT_PER_IP === "1";
const IDLE_MIN = parseInt(process.env.IDLE_MIN || "30", 10);
const SESSION_DAYS = 7;

fs.mkdirSync(DATA_DIR, { recursive: true });
const ml = criarML(DATA_DIR);

let db = { users: {}, sessions: {}, suppliers: [], nextSupplierId: 1 };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, "utf8"))); } catch (_) {}
function saveDb() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

function hashPass(pass) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pass, salt, 64);
  return salt.toString("hex") + ":" + h.toString("hex");
}
function checkPass(pass, stored) {
  try {
    const [s, h] = stored.split(":");
    const calc = crypto.scryptSync(pass, Buffer.from(s, "hex"), 64);
    const real = Buffer.from(h, "hex");
    return calc.length === real.length && crypto.timingSafeEqual(calc, real);
  } catch (_) { return false; }
}

if (!Object.values(db.users).some(u => u.admin)) {
  const name = (process.env.ADMIN_USER || "admin").toLowerCase();
  const pass = process.env.ADMIN_PASS || crypto.randomBytes(6).toString("base64url");
  db.users[name] = { user: name, pass: hashPass(pass), admin: true, active: true, expiresAt: null, ip: null, lastSeen: 0, created: Date.now() };
  saveDb();
  console.log("\n=== ADMIN CRIADO ===\nUsuário: " + name + "\nSenha:   " + pass + "\n(troque a senha depois no painel; esta mensagem só aparece uma vez)\n");
}

function clientIp(req) {
  let ip = req.socket.remoteAddress || "";
  if (TRUST_PROXY) {
    const xff = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (xff) ip = xff;
  }
  return ip.replace(/^::ffff:/, "");
}
function send(res, code, body, headers) {
  const h = Object.assign({
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"
  }, headers || {});
  if (typeof body === "object" && !Buffer.isBuffer(body)) { h["Content-Type"] = "application/json; charset=utf-8"; body = JSON.stringify(body); }
  else if (!h["Content-Type"]) h["Content-Type"] = "text/html; charset=utf-8";
  res.writeHead(code, h); res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > 100000) { reject(new Error("grande")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch (_) { reject(new Error("json")); } });
    req.on("error", reject);
  });
}
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || "").split(";").forEach(p => {
    const i = p.indexOf("="); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
const idleMs = IDLE_MIN * 60000;
function expired(u) { return u.expiresAt && Date.now() > u.expiresAt; }

const fails = new Map();
function tooMany(ip) {
  const f = fails.get(ip); if (!f) return false;
  if (Date.now() - f.t > 15 * 60000) { fails.delete(ip); return false; }
  return f.n >= 8;
}
function addFail(ip) {
  const f = fails.get(ip);
  if (!f || Date.now() - f.t > 15 * 60000) fails.set(ip, { n: 1, t: Date.now() }); else f.n++;
}

function getSession(req) {
  const sid = parseCookies(req).sid; if (!sid) return null;
  const s = db.sessions[sid]; if (!s) return null;
  const u = db.users[s.user];
  const ip = clientIp(req);
  if (!u || !u.active || expired(u) || Date.now() > s.exp || s.ip !== ip) {
    delete db.sessions[sid]; saveDb(); return null;
  }
  u.lastSeen = Date.now();
  return { sid, user: u };
}
function cookieHeader(req, sid, maxAge) {
  const secure = (req.headers["x-forwarded-proto"] === "https" || process.env.COOKIE_SECURE === "1") ? "; Secure" : "";
  return "sid=" + sid + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + maxAge + secure;
}
function activeElsewhere(u, ip) {
  return u.ip && u.ip !== ip && Date.now() - (u.lastSeen || 0) < idleMs;
}

const LOGIN_PAGE = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entrar - Radar de Fornecedores</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101827;color:#e8edf7;font:16px system-ui,Segoe UI,Arial,sans-serif;padding:16px}
form{background:#18233a;border:1px solid #2b3a57;border-radius:14px;padding:28px;width:100%;max-width:360px}
h1{font-size:20px;margin:0 0 4px}p{margin:0 0 18px;color:#9fb0cc;font-size:14px}
label{display:block;font-size:13px;color:#9fb0cc;margin:12px 0 4px}
input{width:100%;padding:11px;border-radius:8px;border:1px solid #2b3a57;background:#101827;color:inherit;font-size:16px}
button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:16px;font-weight:600;cursor:pointer}
button:disabled{opacity:.6}#msg{margin-top:12px;color:#ff8a8a;font-size:14px;min-height:20px}
</style></head><body><form id="f"><h1>Radar de Fornecedores</h1><p>Acesso exclusivo para assinantes.</p>
<label for="u">Usuário</label><input id="u" autocomplete="username" required>
<label for="p">Senha</label><input id="p" type="password" autocomplete="current-password" required>
<button id="b">Entrar</button><div id="msg" role="alert"></div></form>
<script>
document.getElementById("f").addEventListener("submit",async e=>{
 e.preventDefault();const b=document.getElementById("b"),m=document.getElementById("msg");b.disabled=true;m.textContent="";
 try{const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:document.getElementById("u").value,pass:document.getElementById("p").value})});
 const j=await r.json().catch(()=>({}));if(r.ok)location.replace("/");else m.textContent=j.error||"Erro ao entrar.";}
 catch(_){m.textContent="Sem conexão com o servidor.";}b.disabled=false;});
</script></body></html>`;

const KINDS = ["marketplace", "importer", "wholesale", "agent", "polo", "tool", "guide"];
function cleanSupplier(b) {
  const s = (v, n) => String(v == null ? "" : v).trim().slice(0, n);
  const name = s(b.name, 80), niche = s(b.niche, 120), desc = s(b.desc, 400), city = s(b.city, 80);
  const region = b.region === "brasil" ? "brasil" : "china";
  const kind = KINDS.includes(b.kind) ? b.kind : "wholesale";
  let url = s(b.url, 300);
  if (url) { try { const u = new URL(url); if (!/^https?:$/.test(u.protocol)) url = ""; else url = u.href; } catch (_) { url = ""; } }
  if (!name) return null;
  return [name, region, kind, niche, desc, url, city];
}

async function handle(req, res) {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const ip = clientIp(req);

  if (req.method === "GET" && p === "/") {
    const s = getSession(req);
    if (!s) return send(res, 200, LOGIN_PAGE);
    return send(res, 200, APP_HTML);
  }
  if (!p.startsWith("/api/")) return send(res, 404, "Não encontrado", { "Content-Type": "text/plain; charset=utf-8" });

  if (req.method !== "GET") {
    const origin = req.headers.origin;
    if (origin) { try { if (new URL(origin).host !== req.headers.host) return send(res, 403, { error: "Origem inválida." }); } catch (_) { return send(res, 403, { error: "Origem inválida." }); } }
    if (!String(req.headers["content-type"] || "").startsWith("application/json") && req.method !== "DELETE") return send(res, 415, { error: "Use JSON." });
  }

  if (req.method === "POST" && p === "/api/login") {
    if (tooMany(ip)) return send(res, 429, { error: "Muitas tentativas. Aguarde 15 minutos." });
    let b; try { b = await readBody(req); } catch (_) { return send(res, 400, { error: "Requisição inválida." }); }
    const name = String(b.user || "").trim().toLowerCase();
    const u = db.users[name];
    if (!u || !checkPass(String(b.pass || ""), u.pass)) { addFail(ip); return send(res, 401, { error: "Usuário ou senha incorretos." }); }
    if (!u.active) return send(res, 403, { error: "Conta desativada. Fale com o suporte." });
    if (expired(u)) return send(res, 403, { error: "Seu acesso expirou. Renove com o suporte." });
    if (!u.admin) {
      if (STRICT_IP && u.ip && u.ip !== ip) return send(res, 403, { error: "Esta conta está liberada para outro IP. Peça ao suporte para liberar." });
      if (activeElsewhere(u, ip)) return send(res, 403, { error: "Esta conta está em uso em outro IP. Aguarde " + IDLE_MIN + " min sem uso ou peça ao suporte para liberar." });
      if (ONE_ACCOUNT_PER_IP) {
        const other = Object.values(db.users).find(x => !x.admin && x.user !== u.user && x.ip === ip && Date.now() - (x.lastSeen || 0) < idleMs);
        if (other) return send(res, 403, { error: "Já existe outra conta ativa neste IP." });
      }
    }
    Object.keys(db.sessions).forEach(k => { if (db.sessions[k].user === u.user) delete db.sessions[k]; });
    const sid = crypto.randomBytes(32).toString("hex");
    db.sessions[sid] = { user: u.user, ip, exp: Date.now() + SESSION_DAYS * 86400000 };
    u.ip = ip; u.lastSeen = Date.now(); saveDb();
    fails.delete(ip);
    return send(res, 200, { ok: true }, { "Set-Cookie": cookieHeader(req, sid, SESSION_DAYS * 86400) });
  }

  const s = getSession(req);
  if (!s) return send(res, 401, { error: "Sessão expirada. Entre novamente." });
  const me = s.user;

  if (await ml.handle(req, res, p, url, send)) return;

  if (req.method === "POST" && p === "/api/logout") {
    delete db.sessions[s.sid]; saveDb();
    return send(res, 200, { ok: true }, { "Set-Cookie": cookieHeader(req, "", 0) });
  }
  if (req.method === "GET" && p === "/api/me") {
    return send(res, 200, { user: me.user, admin: !!me.admin, expiresAt: me.expiresAt });
  }
  if (req.method === "POST" && p === "/api/password") {
    let b; try { b = await readBody(req); } catch (_) { return send(res, 400, { error: "Requisição inválida." }); }
    if (!checkPass(String(b.old || ""), me.pass)) return send(res, 403, { error: "Senha atual incorreta." });
    const pw = String(b.pw || "");
    if (pw.length < 6 || pw.length > 100) return send(res, 400, { error: "Senha nova: mínimo 6 caracteres." });
    me.pass = hashPass(pw); saveDb();
    return send(res, 200, { ok: true });
  }
  if (req.method === "GET" && p === "/api/suppliers") {
    return send(res, 200, db.suppliers.map(x => ({ id: x.id, row: x.row })));
  }

  if (!me.admin) return send(res, 403, { error: "Apenas o administrador." });

  if (req.method === "GET" && p === "/api/admin/users") {
    return send(res, 200, Object.values(db.users).map(u => ({
      user: u.user, admin: !!u.admin, active: !!u.active, expiresAt: u.expiresAt, ip: u.ip, lastSeen: u.lastSeen, created: u.created
    })));
  }
  if (req.method === "POST" && p === "/api/admin/users") {
    let b; try { b = await readBody(req); } catch (_) { return send(res, 400, { error: "Requisição inválida." }); }
    const name = String(b.user || "").trim().toLowerCase();
    const pass = String(b.pass || "");
    if (!/^[a-z0-9_.-]{3,32}$/.test(name)) return send(res, 400, { error: "Usuário: 3 a 32 letras, números, ponto, hífen ou _." });
    if (pass.length < 6 || pass.length > 100) return send(res, 400, { error: "Senha: mínimo 6 caracteres." });
    if (db.users[name]) return send(res, 409, { error: "Esse usuário já existe." });
    const days = Math.max(0, Math.min(3650, parseInt(b.days, 10) || 0));
    db.users[name] = { user: name, pass: hashPass(pass), admin: !!b.admin, active: true, expiresAt: days ? Date.now() + days * 86400000 : null, ip: null, lastSeen: 0, created: Date.now() };
    saveDb(); return send(res, 200, { ok: true });
  }
  let m = p.match(/^\/api\/admin\/users\/([a-z0-9_.-]+)$/);
  if (m) {
    const u = db.users[m[1]];
    if (!u) return send(res, 404, { error: "Usuário não encontrado." });
    if (req.method === "DELETE") {
      if (u.user === me.user) return send(res, 400, { error: "Você não pode excluir a si mesmo." });
      delete db.users[u.user];
      Object.keys(db.sessions).forEach(k => { if (db.sessions[k].user === u.user) delete db.sessions[k]; });
      saveDb(); return send(res, 200, { ok: true });
    }
    if (req.method === "PATCH") {
      let b; try { b = await readBody(req); } catch (_) { return send(res, 400, { error: "Requisição inválida." }); }
      if (typeof b.active === "boolean") {
        if (u.user === me.user && !b.active) return send(res, 400, { error: "Você não pode desativar a si mesmo." });
        u.active = b.active;
        if (!b.active) Object.keys(db.sessions).forEach(k => { if (db.sessions[k].user === u.user) delete db.sessions[k]; });
      }
      if (b.addDays != null) {
        const d = Math.max(-3650, Math.min(3650, parseInt(b.addDays, 10) || 0));
        const base = (u.expiresAt && u.expiresAt > Date.now()) ? u.expiresAt : Date.now();
        u.expiresAt = base + d * 86400000;
      }
      if (b.noExpiry === true) u.expiresAt = null;
      if (b.resetIp === true) { u.ip = null; u.lastSeen = 0; Object.keys(db.sessions).forEach(k => { if (db.sessions[k].user === u.user) delete db.sessions[k]; }); }
      if (b.pass != null) {
        const pw = String(b.pass);
        if (pw.length < 6 || pw.length > 100) return send(res, 400, { error: "Senha: mínimo 6 caracteres." });
        u.pass = hashPass(pw);
        if (u.user !== me.user) Object.keys(db.sessions).forEach(k => { if (db.sessions[k].user === u.user) delete db.sessions[k]; });
      }
      saveDb(); return send(res, 200, { ok: true });
    }
  }
  if (req.method === "POST" && p === "/api/admin/suppliers") {
    let b; try { b = await readBody(req); } catch (_) { return send(res, 400, { error: "Requisição inválida." }); }
    const row = cleanSupplier(b);
    if (!row) return send(res, 400, { error: "Informe pelo menos o nome." });
    if (db.suppliers.length >= 2000) return send(res, 400, { error: "Limite de fornecedores atingido." });
    const item = { id: db.nextSupplierId++, row };
    db.suppliers.push(item); saveDb();
    return send(res, 200, item);
  }
  m = p.match(/^\/api\/admin\/suppliers\/(\d+)$/);
  if (m && req.method === "DELETE") {
    const id = parseInt(m[1], 10);
    const n = db.suppliers.length;
    db.suppliers = db.suppliers.filter(x => x.id !== id);
    if (db.suppliers.length === n) return send(res, 404, { error: "Não encontrado." });
    saveDb(); return send(res, 200, { ok: true });
  }
  return send(res, 404, { error: "Rota não encontrada." });
}

http.createServer((req, res) => {
  handle(req, res).catch(err => { console.error(err); try { send(res, 500, { error: "Erro interno." }); } catch (_) {} });
}).listen(PORT, () => console.log("Radar rodando em http://localhost:" + PORT));

/* ===================== SITE (HTML) ===================== */
const APP_HTML = String.raw`<!DOCTYPE html>
<html lang="pt-BR" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#101827">
<title>Radar de Fornecedores | Atacado e Importação</title>
<style>
:root{--bg:#0b1120;--panel:#141e30;--panel2:#101827;--line:#29364b;--text:#edf3fc;--muted:#aab8cc;--accent:#2563eb;--link:#93c5fd;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--tag:#1d3453;--tagtext:#c7ddff}
html[data-theme="light"]{--bg:#f4f6fb;--panel:#ffffff;--panel2:#eef2f9;--line:#d5dcea;--text:#16202f;--muted:#566377;--accent:#2563eb;--link:#1d4ed8;--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--tag:#e3ecfb;--tagtext:#1e3a8a}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Arial,sans-serif}
.container{width:min(1200px,94%);margin:auto}
header{padding:22px 0 14px;background:var(--panel2);border-bottom:1px solid var(--line)}
.head{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start}
h1{margin:0 0 4px;font-size:clamp(24px,4vw,34px)}
h2{margin:0 0 10px;font-size:20px}
h3{margin:14px 0 6px;font-size:16px}
.muted{color:var(--muted)}
.small{font-size:13px}
.notice{padding:12px 15px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);color:var(--muted);margin:16px 0}
.notice.warn{border-color:var(--warn)}
.notice.bad{border-color:var(--bad)}
.notice.ok{border-color:var(--ok)}
nav.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-top:14px}
nav.tabs button{background:var(--panel);color:var(--text);border:1px solid var(--line);font-weight:normal}
nav.tabs button[aria-selected="true"]{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:bold}
.fxbar{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin:16px 0;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
.fxbar label{display:flex;flex-direction:column;font-size:12px;color:var(--muted);gap:3px}
.fxbar input{width:110px;min-height:38px}
input,select,button,textarea{min-height:44px;border-radius:9px;border:1px solid var(--line);padding:10px 12px;font:inherit;color:inherit}
input,select,textarea{width:100%;background:var(--panel);color:var(--text)}
textarea{min-height:110px;resize:vertical}
button{cursor:pointer;background:var(--accent);color:#fff;border-color:var(--accent);font-weight:bold}
button.ghost{background:var(--panel);border-color:var(--line);color:var(--text);font-weight:normal}
button.ghost.on{border-color:var(--ok);color:var(--ok)}
button.danger{background:transparent;border-color:var(--bad);color:var(--bad)}
button.sm{min-height:34px;padding:4px 10px;font-size:13px}
button:hover,.link:hover{opacity:.85}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,a:focus-visible{outline:2px solid var(--link);outline-offset:2px}
.filters{display:grid;grid-template-columns:2fr 1fr 1fr 1fr 1fr;gap:10px;margin:14px 0}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 12px}
.chip{min-height:32px;padding:3px 12px;font-size:13px;border-radius:999px;background:var(--panel);color:var(--text);border:1px solid var(--line);font-weight:normal}
.chip[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);color:#fff}
.summary{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:10px 0;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;padding-bottom:30px}
.card{display:flex;flex-direction:column;min-width:0;padding:16px;background:var(--panel);border:1px solid var(--line);border-radius:13px}
.card.fav{border-color:var(--warn)}
.card h3{margin:10px 0 4px;font-size:18px}
.niche{color:var(--tagtext);font-size:13px;margin:0 0 6px}
.desc{color:var(--muted);margin:0 0 10px;font-size:14px}
.tags{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.tag{font-size:12px;color:var(--tagtext);background:var(--tag);padding:3px 8px;border-radius:6px}
.st{font-size:12px;padding:3px 8px;border-radius:6px;border:1px solid var(--line);color:var(--muted)}
.st-contatado,.st-cotacao,.st-amostra{color:var(--warn);border-color:var(--warn)}
.st-aprovado{color:var(--ok);border-color:var(--ok)}
.st-descartado{color:var(--bad);border-color:var(--bad)}
.stars{color:var(--warn);letter-spacing:1px;font-size:14px}
.links{display:flex;flex-wrap:wrap;gap:8px 12px;margin-top:auto;padding-top:12px;align-items:center}
.link{color:var(--link);text-decoration:none;font-size:14px}
.link:hover{text-decoration:underline}
.empty{grid-column:1/-1;padding:28px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:12px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:16px;margin-bottom:16px}
.form{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.form label{display:flex;flex-direction:column;font-size:13px;color:var(--muted);gap:4px}
.form .wide{grid-column:span 2}
.form .full{grid-column:1/-1}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
td.num,th.num{text-align:right;white-space:nowrap}
tr.total td{font-weight:bold;border-top:2px solid var(--line)}
tr.best td{color:var(--ok);font-weight:bold}
.tablewrap{overflow-x:auto}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
ul.clean{margin:6px 0;padding-left:20px}
ul.clean li{margin:4px 0}
.check{display:flex;gap:10px;align-items:flex-start;margin:6px 0}
.check input{width:20px;min-height:20px;margin-top:3px;flex:none}
.big{font-size:22px;font-weight:bold}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:10px 0}
.kpi{border:1px solid var(--line);border-radius:10px;padding:10px;background:var(--panel2)}
.kpi span{display:block;font-size:12px;color:var(--muted)}
dialog{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:14px;width:min(640px,94vw);padding:18px;max-height:90vh;overflow:auto}
dialog::backdrop{background:rgba(0,0,0,.6)}
.toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);background:var(--panel);border:1px solid var(--line);padding:10px 16px;border-radius:10px;z-index:99;box-shadow:0 4px 18px rgba(0,0,0,.4)}
.badge{font-size:12px;padding:3px 8px;border-radius:6px;border:1px solid var(--line);color:var(--muted)}
.badge.overdue{color:var(--bad);border-color:var(--bad)}
.badge.today,.badge.soon{color:var(--warn);border-color:var(--warn)}
.ctline{font-size:14px;margin:2px 0;overflow-wrap:anywhere}
.ctline b{color:var(--muted);font-weight:normal}
.counter{font-size:13px;color:var(--muted);margin:4px 0 8px}
.counter.over{color:var(--bad);font-weight:bold}
.neg{color:var(--bad)}
.pos{color:var(--ok)}
.linkrow{display:flex;gap:8px 16px;flex-wrap:wrap}
footer{border-top:1px solid var(--line);padding:22px 0;color:var(--muted);margin-top:20px}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.filters{grid-template-columns:1fr 1fr}.filters input{grid-column:1/-1}.form{grid-template-columns:repeat(2,minmax(0,1fr))}.two{grid-template-columns:1fr}}
@media(max-width:540px){.grid,.filters,.form{grid-template-columns:1fr}.filters input{grid-column:auto}.form .wide{grid-column:auto}}
@media print{nav.tabs,.fxbar,.filters,.row,.chips,button,.toast{display:none!important}body{background:#fff;color:#000}.card,.panel{break-inside:avoid;border-color:#999}.grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<header>
  <div class="container">
    <div class="head">
      <div>
        <h1>🌎 Radar de Fornecedores</h1>
        <p class="muted" style="margin:0">Atacado, importadoras, fábricas e sourcing para quem revende barato em volume. Com calculadoras, checklist e controle das suas negociações.</p>
      </div>
      <div class="row" style="margin:0">
        <button id="themeBtn" class="ghost sm" type="button">☀ Tema</button>
        <button id="printBtn" class="ghost sm" type="button">🖨 Imprimir</button>
      </div>
    </div>
    <nav class="tabs" id="tabs" role="tablist" aria-label="Seções"></nav>
  </div>
</header>

<main class="container">
  <noscript><div class="notice bad">Este site precisa de JavaScript para funcionar.</div></noscript>

  <div class="fxbar" aria-label="Câmbio">
    <label>Dólar (US$ 1 = R$)<input id="fx_usd" inputmode="decimal" value="5,50"></label>
    <label>Yuan (¥ 1 = R$)<input id="fx_cny" inputmode="decimal" value="0,77"></label>
    <button id="fxFetch" class="ghost" type="button">↻ Buscar cotação atual</button>
    <span id="fxInfo" class="muted small">Valores de exemplo: ajuste ou clique para buscar a cotação do dia.</span>
  </div>

  <!-- ============ FORNECEDORES ============ -->
  <section id="tab-suppliers" role="tabpanel">
    <div class="notice">
      <strong>Importante:</strong> lista de pontos de partida, não de recomendação. Preços, pedido mínimo e reputação mudam e precisam ser confirmados com cada empresa.
      Onde não há site oficial confirmado, o botão <em>Pesquisar</em> abre uma busca no Google em vez de um link que poderia estar errado.
      Use <strong>Detalhes</strong> em cada card para marcar o status da negociação, dar nota e anotar contatos.
    </div>
    <section class="filters" aria-label="Filtros">
      <input id="search" type="search" autocomplete="off" placeholder="Buscar produto, empresa ou categoria (atalho: /)" aria-label="Buscar">
      <select id="region" autocomplete="off" aria-label="Região">
        <option value="all">Todas as regiões</option>
        <option value="china">China / internacional</option>
        <option value="brasil">Brasil</option>
      </select>
      <select id="kind" autocomplete="off" aria-label="Tipo"></select>
      <select id="statusSel" autocomplete="off" aria-label="Status da negociação"></select>
      <select id="sort" autocomplete="off" aria-label="Ordenar">
        <option value="default">Ordem padrão</option>
        <option value="az">Nome A–Z</option>
        <option value="rating">Melhor nota primeiro</option>
        <option value="fav">Favoritos primeiro</option>
      </select>
    </section>
    <div class="chips" id="chips" aria-label="Nichos"></div>
    <div class="row">
      <button id="onlyFav" class="ghost" type="button">★ Só favoritos</button>
      <button id="csv" class="ghost" type="button">⬇ Baixar lista (CSV)</button>
      <button id="clear" type="button">Limpar filtros</button>
    </div>
    <div class="summary">
      <span id="count" aria-live="polite">Carregando...</span>
      <span>Confira sempre o custo final (frete + impostos) antes de comprar.</span>
    </div>
    <section id="results" class="grid" aria-label="Lista de fornecedores"></section>
  </section>

  <!-- ============ TENDÊNCIAS ML ============ -->
  <section id="tab-trends" role="tabpanel" hidden>
    <style>
      .tr-hero {
        background: linear-gradient(135deg, #1e40af 0%, #7c3aed 100%);
        border-radius: 16px;
        padding: 24px 28px;
        color: #fff;
        margin-bottom: 20px;
      }
      .tr-hero h2 { margin: 0 0 6px; font-size: 24px; color: #fff; }
      .tr-hero p { margin: 0; opacity: .9; font-size: 14px; }

      .tr-section {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 20px;
        margin-bottom: 18px;
      }
      .tr-section h3 { margin: 0 0 4px; font-size: 17px; }
      .tr-section .tr-sub { color: var(--muted); font-size: 13px; margin: 0 0 16px; }

      .tr-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
        gap: 12px;
      }
      .tr-card {
        background: var(--bg);
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 14px;
        display: flex;
        flex-direction: column;
        gap: 8px;
        transition: transform .15s, box-shadow .15s, border-color .15s;
      }
      .tr-card:hover {
        transform: translateY(-3px);
        border-color: #6366f1;
        box-shadow: 0 8px 20px rgba(99,102,241,.15);
      }
      .tr-termo {
        font-size: 13px;
        font-weight: 600;
        color: #f59e0b;
        background: rgba(245,158,11,.1);
        padding: 4px 8px;
        border-radius: 6px;
        display: inline-block;
        align-self: flex-start;
      }
      .tr-card h4 {
        margin: 0;
        font-size: 15px;
        font-weight: 600;
        line-height: 1.35;
        color: var(--text);
        display: -webkit-box;
        -webkit-line-clamp: 3;
        -webkit-box-orient: vertical;
        overflow: hidden;
      }
      .tr-preco {
        font-size: 18px;
        font-weight: bold;
        color: #22c55e;
      }
      .tr-meta {
        font-size: 11px;
        color: var(--muted);
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }
      .tr-meta span {
        background: var(--panel);
        padding: 2px 8px;
        border-radius: 6px;
      }
      .tr-links {
        display: flex;
        gap: 8px;
        margin-top: auto;
        padding-top: 6px;
        border-top: 1px solid var(--line);
      }
      .tr-links a {
        font-size: 12px;
        text-decoration: none;
        color: #6366f1;
        padding: 4px 8px;
        border-radius: 6px;
        background: rgba(99,102,241,.1);
        transition: background .15s;
      }
      .tr-links a:hover { background: rgba(99,102,241,.25); }
      .tr-links a.tr-ali { color: #f59e0b; background: rgba(245,158,11,.1); }
      .tr-links a.tr-ali:hover { background: rgba(245,158,11,.25); }
      .tr-links a.tr-1688 { color: #ef4444; background: rgba(239,68,68,.1); }
      .tr-links a.tr-1688:hover { background: rgba(239,68,68,.25); }

      .tr-foto {
        width: 100%;
        height: 140px;
        object-fit: contain;
        background: #fff;
        border-radius: 8px;
      }

      .tr-loading {
        padding: 30px;
        text-align: center;
        color: var(--muted);
      }
      .tr-loading::after {
        content: "";
        display: inline-block;
        width: 12px;
        height: 12px;
        margin-left: 8px;
        border: 2px solid #6366f1;
        border-top-color: transparent;
        border-radius: 50%;
        animation: tr-spin .8s linear infinite;
        vertical-align: middle;
      }
      @keyframes tr-spin { to { transform: rotate(360deg); } }
    </style>

    <div class="tr-hero">
      <h2>📈 Tendências do Mercado Livre</h2>
      <p>Dados oficiais da API do ML. Escolha o que importar <strong>antes</strong> de comprar o lote.</p>
    </div>

    <div class="tr-section">
      <h3>🔥 Buscas em alta esta semana</h3>
      <p class="tr-sub">Termos que mais cresceram nas últimas 2 semanas, com o produto mais vendido de cada um.</p>
      <button id="tr_load" type="button">Carregar tendências</button>
      <div id="tr_list" class="tr-grid" style="margin-top:16px"></div>
    </div>

    <div class="tr-section">
      <h3>🏆 Mais vendidos por categoria</h3>
      <p class="tr-sub">Os 20 produtos que mais vendem na categoria escolhida, com preço atual e link do fornecedor.</p>
      <div class="row" style="margin-bottom:16px">
        <select id="tr_cat" style="max-width:420px;flex:1">
          <option value="">Carregando categorias...</option>
        </select>
        <button id="tr_loadCat" type="button">Ver mais vendidos</button>
      </div>
      <div id="tr_catList" class="tr-grid"></div>
    </div>

    <div class="tr-section" style="border-color:var(--warn)">
      <h3>💡 Como usar</h3>
      <p style="margin:0;color:var(--muted);font-size:14px;line-height:1.6">
        Se um termo aparece aqui <em>e</em> você acha o mesmo produto barato no <strong>Alibaba</strong> ou <strong>1688</strong>,
        é um forte candidato. Antes de comprar, confirme o custo final na aba <strong>Custo de importação</strong> e o preço de venda
        na aba <strong>Mercado Livre</strong>.
      </p>
    </div>
  </section>

  <!-- ============ CONTATOS ============ -->
  <section id="tab-contacts" role="tabpanel" hidden>
    <h2>📇 Agenda de importadores e contatos</h2>
    <div class="notice small">Área para guardar contatos de importadores, fábricas, agentes, fretes e despachantes, com lembrete de retorno. Fica salva neste navegador e neste aparelho. Para levar os contatos de um aparelho para outro (por exemplo, entre você e sua esposa), use <strong>Exportar</strong> em um e <strong>Importar</strong> no outro: os contatos são mesclados, sem apagar os que já existem.</div>
    <div class="panel">
      <h3 id="ct_formTitle" style="margin-top:0">Novo contato</h3>
      <div class="form">
        <label class="wide">Nome do contato<input id="ct_name" autocomplete="off" placeholder="Ex.: Li Wei / João"></label>
        <label class="wide">Empresa<input id="ct_company" autocomplete="off" placeholder="Ex.: Shenzhen XYZ Ltd / Importadora ABC"></label>
        <label>Tipo<select id="ct_type"></select></label>
        <label>País / cidade<input id="ct_place" autocomplete="off" placeholder="Ex.: Yiwu, China"></label>
        <label>WhatsApp / telefone<input id="ct_phone" inputmode="tel" autocomplete="off" placeholder="(11) 90000-0000 ou +86 ..."></label>
        <label>E-mail<input id="ct_email" type="email" autocomplete="off"></label>
        <label>WeChat / outro<input id="ct_wechat" autocomplete="off"></label>
        <label class="wide">Site / link da loja<input id="ct_site" autocomplete="off" placeholder="https://..."></label>
        <label class="wide">Produtos que vende<input id="ct_products" autocomplete="off" placeholder="Ex.: fones, carregadores, brinquedos"></label>
        <label>Pedido mínimo (MOQ)<input id="ct_moq" autocomplete="off"></label>
        <label>Prazo de entrega<input id="ct_lead" autocomplete="off"></label>
        <label>Responsável<input id="ct_owner" list="ct_owners" autocomplete="off" placeholder="Ex.: Esposa"></label>
        <datalist id="ct_owners"></datalist>
        <label>Status<select id="ct_status"></select></label>
        <label>Próximo contato<input id="ct_next" type="date"></label>
        <label>Nota<select id="ct_rating"></select></label>
        <label class="full">Anotações<textarea id="ct_notes" rows="3" placeholder="Preços combinados, qualidade, como foi o atendimento..."></textarea></label>
        <div class="full row" style="margin:0">
          <button id="ct_save" type="button">Salvar contato</button>
          <button id="ct_cancel" class="ghost" type="button" hidden>Cancelar edição</button>
        </div>
      </div>
    </div>
    <section class="filters" aria-label="Filtros de contatos">
      <input id="ct_q" type="search" autocomplete="off" placeholder="Buscar nome, empresa, produto, anotação..." aria-label="Buscar contatos">
      <select id="ct_ftype" autocomplete="off" aria-label="Tipo"></select>
      <select id="ct_fowner" autocomplete="off" aria-label="Responsável"></select>
      <select id="ct_fstatus" autocomplete="off" aria-label="Status"></select>
      <select id="ct_sort" autocomplete="off" aria-label="Ordenar">
        <option value="due">Retorno mais próximo primeiro</option>
        <option value="az">Nome A–Z</option>
        <option value="new">Mais recentes</option>
        <option value="rating">Melhor nota</option>
      </select>
    </section>
    <div class="row">
      <button id="ct_dueBtn" class="ghost" type="button">⏰ Só retornos de hoje ou atrasados</button>
      <button id="ct_csv" class="ghost" type="button">⬇ Baixar CSV</button>
      <button id="ct_exp" class="ghost" type="button">⬇ Exportar contatos (JSON)</button>
      <button id="ct_imp" class="ghost" type="button">⬆ Importar contatos (JSON)</button>
      <input id="ct_impFile" type="file" accept="application/json,.json" hidden>
    </div>
    <div class="summary"><span id="ct_count" aria-live="polite"></span><span>Retornos atrasados aparecem em vermelho.</span></div>
    <section id="ct_list" class="grid" aria-label="Lista de contatos"></section>
  </section>

  <!-- ============ MERCADO LIVRE ============ -->
  <section id="tab-ml" role="tabpanel" hidden>
    <h2>🛒 Vender no Mercado Livre</h2>
    <div class="notice warn small">As tarifas do Mercado Livre variam por categoria e mudaram em 2026. Fontes consultadas indicam comissão em faixas (cerca de 11% a 14% no Clássico e 15% a 18% no Premium) e, desde março de 2026, no Full abaixo de R$ 79 o custo fixo foi trocado por um custo operacional variável por peso e dimensões. Os campos abaixo vêm com <strong>valores de referência editáveis</strong>: confirme os seus em “Custos de vender” ou no simulador de custos da sua conta antes de definir o preço.</div>
    <div class="panel">
      <div class="form" data-calc="ml">
        <label>Custo do produto já nacionalizado (R$/un)<input id="ml_cost" inputmode="decimal" autocomplete="off" value="25,00"></label>
        <label>Embalagem e outros custos (R$/un)<input id="ml_pack" inputmode="decimal" autocomplete="off" value="1,50"></label>
        <label>Tipo de anúncio
          <select id="ml_type" autocomplete="off">
            <option value="classico">Clássico</option>
            <option value="premium">Premium</option>
            <option value="custom">Personalizado</option>
          </select>
        </label>
        <label>Comissão do Mercado Livre (%)<input id="ml_comm" inputmode="decimal" autocomplete="off" value="12"></label>
        <label>Custo fixo / operacional (R$/un)<input id="ml_fixed" inputmode="decimal" autocomplete="off" value="6,50"></label>
        <label>Cobrado abaixo de (R$)<input id="ml_thr" inputmode="decimal" autocomplete="off" value="79"></label>
        <label>Frete que você paga (R$/un)<input id="ml_ship" inputmode="decimal" autocomplete="off" value="0"></label>
        <label>Imposto sobre a venda (%)<input id="ml_tax" inputmode="decimal" autocomplete="off" value="6"></label>
        <label>Anúncios / Product Ads (% do preço)<input id="ml_ads" inputmode="decimal" autocomplete="off" value="0"></label>
        <label>Margem desejada (%)<input id="ml_margin" inputmode="decimal" autocomplete="off" value="20"></label>
        <label>Seu preço no ML (R$, opcional)<input id="ml_price" inputmode="decimal" autocomplete="off" value=""></label>
        <label>Vendas por mês (un, opcional)<input id="ml_qty" inputmode="numeric" autocomplete="off" value="100"></label>
        <div class="full row" style="margin:0">
          <button id="ml_fromCost" class="ghost sm" type="button">↩ Pegar custo/un da aba Custo de importação</button>
          <span class="small muted">O custo fixo só entra quando o preço fica abaixo do limite. Acima dele, informe o frete que você paga (o frete grátis costuma ser obrigatório).</span>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="kpis" id="mlKpis"></div>
      <div class="two">
        <div>
          <h3 style="margin-top:0">Para onde vai o dinheiro de cada venda</h3>
          <div class="tablewrap"><table id="mlBreak"></table></div>
        </div>
        <div>
          <h3 style="margin-top:0">Preço de venda por margem</h3>
          <div class="tablewrap"><table id="mlTable"></table></div>
        </div>
      </div>
    </div>

    <div class="two">
      <div class="panel">
        <h3 style="margin-top:0">Gerador de título (limite de 60 caracteres)</h3>
        <div class="form" id="titleForm" style="grid-template-columns:1fr 1fr">
          <label>Produto<input id="t_prod" autocomplete="off" placeholder="Fone de ouvido bluetooth"></label>
          <label>Marca<input id="t_brand" autocomplete="off" placeholder="Sua marca / genérica"></label>
          <label>Modelo<input id="t_model" autocomplete="off" placeholder="TWS i12"></label>
          <label>Característica 1<input id="t_f1" autocomplete="off" placeholder="Sem fio"></label>
          <label>Característica 2<input id="t_f2" autocomplete="off" placeholder="Com microfone"></label>
          <label>Cor / tamanho<input id="t_color" autocomplete="off" placeholder="Preto"></label>
          <label>Kit / quantidade<input id="t_qty" autocomplete="off" placeholder="Kit 2 unidades"></label>
        </div>
        <h3>Título completo</h3>
        <input id="t_full" readonly aria-label="Título completo">
        <div id="t_cnt1" class="counter"></div>
        <h3>Versão que cabe em 60 caracteres</h3>
        <input id="t_fit" readonly aria-label="Título curto">
        <div id="t_cnt2" class="counter"></div>
        <div class="row"><button id="t_copy" class="ghost sm" type="button">Copiar título que cabe</button></div>
      </div>
      <div class="panel">
        <h3 style="margin-top:0">Gerador de descrição (texto simples)</h3>
        <div class="form" style="grid-template-columns:1fr">
          <label>Características / benefícios (um por linha)<textarea id="d_bul" rows="4" autocomplete="off" placeholder="Bateria de até 5 horas&#10;Conexão estável&#10;Estojo carregador"></textarea></label>
          <label>O que vem na caixa (um por linha)<textarea id="d_box" rows="3" autocomplete="off" placeholder="1 fone&#10;1 cabo USB&#10;Manual"></textarea></label>
          <label>Garantia / prazo de envio<input id="d_war" autocomplete="off" placeholder="Garantia de 90 dias. Postagem em até 24 h"></label>
        </div>
        <textarea id="d_out" rows="9" aria-label="Descrição gerada" style="margin-top:10px"></textarea>
        <div class="row" style="margin-top:8px"><button id="d_copy" class="ghost sm" type="button">Copiar descrição</button></div>
        <div class="small muted">A descrição do Mercado Livre é só texto, sem formatação. Não escreva telefone, link ou e-mail no anúncio.</div>
      </div>
    </div>

    <div class="panel">
      <h3 style="margin-top:0">Pesquisar o produto antes de comprar o lote</h3>
      <input id="r_q" autocomplete="off" placeholder="Digite o produto (ex.: carregador turbo tipo C)" aria-label="Produto a pesquisar">
      <div id="r_links" class="linkrow" style="margin-top:10px"></div>
      <div class="small muted" style="margin-top:8px">Olhe o preço dos concorrentes, a quantidade vendida, a reputação dos vendedores e se já existe anúncio em catálogo. Se já tem muitos vendedores iguais, a disputa é por preço.</div>
    </div>

    <div class="two">
      <div class="panel">
        <h3 style="margin-top:0">Checklist do anúncio <span class="muted small">(salvo no navegador)</span></h3>
        <div id="mlCheck"></div>
        <button id="mlCheckReset" class="ghost sm" type="button">Desmarcar tudo</button>
      </div>
      <div class="panel">
        <h3 style="margin-top:0">Dicas para vender mais e perder menos</h3>
        <ul class="clean" id="mlTips"></ul>
      </div>
    </div>
  </section>

  <!-- ============ MEUS PRODUTOS ============ -->
  <section id="tab-products" role="tabpanel" hidden>
    <h2>📦 Meus produtos</h2>
    <div class="notice small">Controle dos produtos que você revende: custo, preço no Mercado Livre, estoque e vendas por mês. O lucro usa as taxas configuradas na aba Mercado Livre (comissão, custo fixo, frete, imposto e anúncios).</div>
    <div class="panel">
      <div class="form" id="prForm">
        <label class="wide">Produto<input id="pr_name" autocomplete="off" placeholder="Ex.: Fone TWS i12"></label>
        <label class="wide">Fornecedor<input id="pr_sup" autocomplete="off" placeholder="Ex.: Fábrica X / Importadora Y"></label>
        <label>Custo nacionalizado (R$/un)<input id="pr_cost" inputmode="decimal" autocomplete="off"></label>
        <label>Preço no ML (R$)<input id="pr_price" inputmode="decimal" autocomplete="off"></label>
        <label>Estoque (un)<input id="pr_stock" inputmode="numeric" autocomplete="off"></label>
        <label>Vendas por mês (un)<input id="pr_sales" inputmode="numeric" autocomplete="off"></label>
        <div class="full row" style="margin:0"><button id="pr_add" type="button">+ Adicionar produto</button></div>
      </div>
    </div>
    <div class="panel">
      <div class="kpis" id="prKpis"></div>
      <div class="tablewrap"><table id="prTable"></table></div>
    </div>
  </section>

  <!-- ============ CUSTO ============ -->
  <section id="tab-cost" role="tabpanel" hidden>
    <h2>Calculadora de custo de importação</h2>
    <div class="notice warn small">Estimativa para planejamento. As alíquotas abaixo são <strong>editáveis e de exemplo</strong>: o imposto real depende da NCM, do regime (Remessa Conforme ou importação formal), do estado e de taxas do despachante. Confirme com seu despachante ou contador. Em maio/2026 (Portaria MF 1.342/2026) o II de até US$ 50 passou a 0% e a dedução subiu para US$ 30, mas isso vale só para pessoa física; pessoa jurídica segue com 60% de II mais ICMS.</div>
    <div class="panel">
      <div class="form" data-calc="cost">
        <label class="wide">Regime / modelo
          <select id="c_mode">
            <option value="remessa_pj">Remessa Conforme — pessoa jurídica (II 60%)</option>
            <option value="remessa_pf">Remessa Conforme — pessoa física (II 60% − US$ 30)</option>
            <option value="formal">Importação formal (exemplo de alíquotas)</option>
            <option value="custom">Personalizado</option>
          </select>
        </label>
        <label>Preço unitário (US$)<input id="c_price" inputmode="decimal" value="3,50"></label>
        <label>Quantidade<input id="c_qty" inputmode="numeric" value="500"></label>
        <label>Frete internacional total (US$)<input id="c_freight" inputmode="decimal" value="350"></label>
        <label>Seguro (% da mercadoria)<input id="c_ins" inputmode="decimal" value="0"></label>
        <label>Imposto de importação (%)<input id="c_ii" inputmode="decimal" value="60"></label>
        <label>Dedução do II (US$)<input id="c_ded" inputmode="decimal" value="0"></label>
        <label>IPI (%)<input id="c_ipi" inputmode="decimal" value="0"></label>
        <label>PIS (%)<input id="c_pis" inputmode="decimal" value="0"></label>
        <label>COFINS (%)<input id="c_cofins" inputmode="decimal" value="0"></label>
        <label>ICMS (%)<input id="c_icms" inputmode="decimal" value="17"></label>
        <label>Outras despesas (R$ total)<input id="c_other" inputmode="decimal" value="0"></label>
        <label>Preço de revenda (R$/un, opcional)<input id="c_resale" inputmode="decimal" value=""></label>
        <div class="full small muted">Outras despesas: despachante, armazenagem, taxas, frete nacional, etc. O ICMS é calculado “por dentro” (a base inclui o próprio ICMS).</div>
      </div>
    </div>
    <div class="panel">
      <div class="kpis" id="costKpis"></div>
      <div class="row"><button id="c_toML" class="ghost sm" type="button">→ Usar este custo por unidade na aba Mercado Livre</button></div>
      <div class="tablewrap"><table id="costTable"></table></div>
    </div>
  </section>

  <!-- ============ PREÇO ============ -->
  <section id="tab-price" role="tabpanel" hidden>
    <h2>Calculadora de preço de revenda e margem</h2>
    <div class="notice small">Margem é calculada sobre o preço de venda (lucro ÷ preço). Markup é calculado sobre o custo. Taxas, imposto sobre venda e anúncios entram como % do preço.</div>
    <div class="panel">
      <div class="form" data-calc="price">
        <label>Custo unitário (R$)<input id="p_cost" inputmode="decimal" value="25,00"></label>
        <label>Custos fixos por unidade (R$)<input id="p_fixed" inputmode="decimal" value="1,50"></label>
        <label>Margem desejada (%)<input id="p_margin" inputmode="decimal" value="30"></label>
        <label>Taxa de marketplace/cartão (%)<input id="p_fee" inputmode="decimal" value="14"></label>
        <label>Imposto sobre a venda (%)<input id="p_tax" inputmode="decimal" value="6"></label>
        <label>Anúncios/comissões (%)<input id="p_ads" inputmode="decimal" value="0"></label>
        <label>Seu preço de venda (R$, opcional)<input id="p_price" inputmode="decimal" value=""></label>
      </div>
    </div>
    <div class="panel">
      <div class="kpis" id="priceKpis"></div>
      <h3>Preço sugerido por margem</h3>
      <div class="tablewrap"><table id="priceTable"></table></div>
    </div>
  </section>

  <!-- ============ COTAÇÕES ============ -->
  <section id="tab-quotes" role="tabpanel" hidden>
    <h2>Comparador de cotações</h2>
    <div class="notice small">Registre as cotações que receber e veja qual sai mais barata por unidade, já em reais. O acréscimo de impostos é uma estimativa única aplicada a todas; use a aba de custo para o cálculo detalhado.</div>
    <div class="panel">
      <div class="form" id="quoteForm">
        <label class="wide">Fornecedor<input id="q_sup" placeholder="Ex.: Fábrica X (Alibaba)"></label>
        <label class="wide">Produto<input id="q_prod" placeholder="Ex.: Fone Bluetooth TWS"></label>
        <label>Moeda
          <select id="q_cur"><option value="USD">US$ (dólar)</option><option value="CNY">¥ (yuan)</option><option value="BRL">R$ (real)</option></select>
        </label>
        <label>Preço unitário<input id="q_price" inputmode="decimal"></label>
        <label>Quantidade<input id="q_qty" inputmode="numeric"></label>
        <label>MOQ<input id="q_moq" inputmode="numeric"></label>
        <label>Frete total (mesma moeda)<input id="q_freight" inputmode="decimal" value="0"></label>
        <label>Prazo (dias)<input id="q_days" inputmode="numeric"></label>
        <label>Acréscimo estimado de impostos (%)<input id="q_tax" inputmode="decimal" value="0"></label>
        <div class="full row" style="margin:0"><button id="q_add" type="button">+ Adicionar cotação</button><button id="q_clear" class="danger" type="button">Apagar todas</button></div>
      </div>
    </div>
    <div class="panel"><div class="tablewrap"><table id="quoteTable"></table></div></div>
  </section>

  <!-- ============ CNPJ ============ -->
  <section id="tab-cnpj" role="tabpanel" hidden>
    <h2>Verificar CNPJ do fornecedor brasileiro</h2>
    <div class="notice small">Validação feita no seu navegador (dígitos verificadores) e consulta pública via BrasilAPI quando disponível. Se a consulta falhar, use os links oficiais abaixo. Sempre peça o CNPJ por escrito e confirme se o nome na nota fiscal e na conta de pagamento é o mesmo da empresa.</div>
    <div class="panel">
      <div class="row">
        <input id="cnpjInput" placeholder="00.000.000/0000-00" inputmode="numeric" style="max-width:320px" aria-label="CNPJ">
        <button id="cnpjGo" type="button">Validar e consultar</button>
      </div>
      <div id="cnpjOut" aria-live="polite"></div>
      <div class="row small" id="cnpjLinks" hidden>
        <a class="link" id="cnpjLinkA" target="_blank" rel="noopener noreferrer">Ver no CNPJá ↗</a>
        <a class="link" href="https://solucoes.receita.fazenda.gov.br/Servicos/cnpjreva/Cnpjreva_Solicitacao.asp" target="_blank" rel="noopener noreferrer">Consulta oficial da Receita Federal ↗</a>
        <a class="link" id="cnpjLinkG" target="_blank" rel="noopener noreferrer">Pesquisar no Google ↗</a>
      </div>
    </div>
    <div class="panel">
      <h3 style="margin-top:0">Sinais de alerta em empresa brasileira</h3>
      <ul class="clean">
        <li>Situação cadastral diferente de “ATIVA” (inapta, suspensa, baixada).</li>
        <li>Empresa aberta há poucos meses prometendo preços muito abaixo do mercado.</li>
        <li>Atividade (CNAE) que não tem a ver com o produto que ela vende.</li>
        <li>Pedem pagamento em conta de pessoa física ou de outra empresa.</li>
        <li>Recusam emitir nota fiscal ou dar endereço físico.</li>
      </ul>
    </div>
  </section>

  <!-- ============ MENSAGENS ============ -->
  <section id="tab-messages" role="tabpanel" hidden>
    <h2>Modelos de mensagem para fornecedores</h2>
    <div class="notice small">Preencha os campos e copie a mensagem pronta. Em inglês para Alibaba/China, em português para atacadistas brasileiros.</div>
    <div class="panel">
      <div class="form" id="msgForm">
        <label>Fornecedor<input id="m_sup" placeholder="Nome da empresa/contato"></label>
        <label>Produto<input id="m_prod" placeholder="Ex.: Fone Bluetooth TWS"></label>
        <label>Quantidade desejada<input id="m_qty" placeholder="Ex.: 500"></label>
        <label>Preço alvo (opcional)<input id="m_target" placeholder="Ex.: US$ 3.00"></label>
        <label>Seu nome<input id="m_me" placeholder="Seu nome"></label>
        <label>Sua empresa / CNPJ<input id="m_co" placeholder="Empresa — CNPJ"></label>
        <label class="wide">Modelo
          <select id="m_tpl"></select>
        </label>
      </div>
    </div>
    <div class="panel">
      <textarea id="m_out" rows="14" aria-label="Mensagem gerada"></textarea>
      <div class="row" style="margin-top:10px">
        <button id="m_copy" type="button">Copiar mensagem</button>
        <a id="m_wa" class="link" target="_blank" rel="noopener noreferrer">Abrir no WhatsApp ↗</a>
      </div>
    </div>
  </section>

  <!-- ============ GUIA ============ -->
  <section id="tab-guide" role="tabpanel" hidden>
    <h2>Guia do importador revendedor</h2>
    <div class="two">
      <div class="panel">
        <h3 style="margin-top:0">Passo a passo</h3>
        <ol class="clean" id="steps"></ol>
      </div>
      <div class="panel">
        <h3 style="margin-top:0">Checklist antes de fechar o pedido <span class="muted small">(salvo no navegador)</span></h3>
        <div id="gcheck"></div>
        <button id="gcheckReset" class="ghost sm" type="button">Desmarcar tudo</button>
      </div>
    </div>
    <div class="two">
      <div class="panel">
        <h3 style="margin-top:0">9 sinais de golpe em fornecedores na China</h3>
        <ul class="clean" id="flags"></ul>
      </div>
      <div class="panel">
        <h3 style="margin-top:0">Erros que corroem a margem</h3>
        <ul class="clean" id="mistakes"></ul>
      </div>
    </div>
    <div class="panel">
      <h3 style="margin-top:0">Dicas práticas</h3>
      <ul class="clean" id="tips"></ul>
    </div>
    <div class="panel">
      <h3 style="margin-top:0">Glossário</h3>
      <input id="glossSearch" type="search" placeholder="Buscar termo (MOQ, FOB, NCM...)" aria-label="Buscar no glossário">
      <dl id="gloss" style="margin-top:10px"></dl>
    </div>
    <div class="panel">
      <h3 style="margin-top:0">Fontes consultadas</h3>
      <ul class="clean small" id="sources"></ul>
    </div>
  </section>

  <!-- ============ MEUS DADOS ============ -->
  <section id="tab-data" role="tabpanel" hidden>
    <h2>Meus dados e backup</h2>
    <div class="notice small">Tudo (favoritos, status, notas, cotações, checklist) fica salvo só neste navegador. Se limpar os dados do site ou trocar de aparelho, você perde. Baixe um backup de vez em quando.</div>
    <div class="panel">
      <div class="kpis" id="dataKpis"></div>
      <div class="row">
        <button id="expJson" type="button">⬇ Baixar backup (JSON)</button>
        <button id="impBtn" class="ghost" type="button">⬆ Restaurar backup</button>
        <input id="impFile" type="file" accept="application/json,.json" hidden>
        <button id="resetAll" class="danger" type="button">Apagar todos os meus dados</button>
      </div>
    </div>
  </section>
</main>

<dialog id="dlg" aria-label="Detalhes do fornecedor"></dialog>
<div id="toast" class="toast" hidden role="status"></div>

<footer>
  <div class="container">Radar de Fornecedores · Dados de pesquisa pública; confirme tudo diretamente com a empresa antes de pagar. Não é aconselhamento jurídico, fiscal ou financeiro.</div>
</footer>

<script>
"use strict";

/* ===================== DADOS ===================== */
const DATA = [
  ["1688","china","marketplace","Fábrica, utilidades, acessórios, variedades","Atacado doméstico do grupo Alibaba. Preço de fábrica, site em chinês; na prática exige agente de compras.","https://www.1688.com/","Plataforma"],
  ["Alibaba","china","marketplace","Fabricantes, OEM, marca própria, grandes pedidos","Diretório internacional de fabricantes. Use Trade Assurance e valide cada vendedor.","https://www.alibaba.com/","Plataforma"],
  ["Made-in-China","china","marketplace","Equipamentos, ferramentas, indústria, casa","Plataforma B2B para pesquisar fábricas e pedir cotações a várias empresas.","https://www.made-in-china.com/","Plataforma"],
  ["Global Sources","china","marketplace","Eletrônicos, presentes, casa e consumo","Diretório B2B com fornecedores verificados, forte em eletrônicos.","https://www.globalsources.com/","Plataforma"],
  ["Yiwugo","china","marketplace","Utilidades, presentes, acessórios, bijuterias","Plataforma ligada ao mercado atacadista de Yiwu.","https://www.yiwugo.com/","Yiwu"],
  ["Chinagoods","china","marketplace","Variedades, mercadorias de consumo","Portal comercial associado ao mercado de Yiwu.","https://www.chinagoods.com/","Yiwu"],
  ["DHgate","china","marketplace","Lotes pequenos, acessórios, variedades","Marketplace com muitos vendedores; confira reputação, avaliações e MOQ.","https://www.dhgate.com/","Plataforma"],
  ["HKTDC Sourcing","china","marketplace","Exportadores asiáticos, diversos","Diretório de fornecedores e produtos da Hong Kong Trade Development Council.","https://sourcing.hktdc.com/","Hong Kong"],
  ["EC21","china","marketplace","Industrial e consumo","Marketplace internacional de empresas e ofertas.","https://www.ec21.com/","Plataforma"],
  ["TradeKey","china","marketplace","B2B geral","Diretório de compradores e vendedores; use como fonte extra de cotações.","https://www.tradekey.com/","Plataforma"],
  ["Tomee (ex-Chinavasion)","china","marketplace","Eletrônicos e gadgets no atacado","Citado em guias brasileiros como fornecedor chinês que vende no atacado para o mundo.","","Plataforma"],
  ["AliExpress (modo atacado)","china","marketplace","Teste de produto, pequenos lotes","Bom para testar produto antes de comprar volume; preço é de varejo, não de escala.","https://www.aliexpress.com/","Plataforma"],
  ["Banggood","china","marketplace","Eletrônicos, gadgets, acessórios","Citado em guias de fornecedores chineses; útil para pesquisa e amostras.","https://www.banggood.com/","Plataforma"],
  ["Canton Fair","china","marketplace","Feira de fabricantes e exportadores","Maior feira comercial da China; pesquise expositores por categoria.","https://www.cantonfair.org.cn/","Guangzhou"],
  ["Yiwu International Trade City","china","polo","Pequenas mercadorias, presentes, brinquedos","O principal mercado atacadista de variedades da China. Normalmente acessado via agente em Yiwu.","","Yiwu"],
  ["Huaqiangbei (Shenzhen)","china","polo","Eletrônicos e componentes","Região de Shenzhen com milhares de lojas de eletrônicos e componentes. Muito usada por quem importa gadgets.","","Shenzhen"],
  ["JingSourcing","china","agent","Busca de fabricantes, inspeção","Agente de sourcing. Peça orçamento detalhado (comissão, inspeção, logística).","https://www.jingsourcing.com/","China"],
  ["LeelineSourcing","china","agent","Compra, consolidação, logística","Serviços de sourcing e apoio a compras internacionais; compare taxas.","https://leelinesourcing.com/","China"],
  ["Yiwu Agent","china","agent","Compra assistida em Yiwu","Compra assistida e consolidação. Confirme taxas, inspeção e envio.","https://yiwuagent.com/","Yiwu"],
  ["Chilat","china","agent","Agente para 1688 e fornecedores verificados","Plataforma de apoio a compras no 1688 e consolidação de cargas.","https://www.chilat.com/","China"],
  ["Sourcify","china","agent","Fabricação e sourcing sob encomenda","Serviço de apoio à fabricação e ao sourcing.","https://sourcify.com/","China"],
  ["QIMA","china","agent","Inspeção, auditoria e testes","Inspeção de qualidade e auditoria de fábrica antes do embarque.","https://www.qima.com/","Serviço"],
  ["SGS","china","agent","Inspeção e certificação","Inspeção, testes e certificação conforme o serviço contratado.","https://www.sgs.com/","Serviço"],
  ["Bureau Veritas","china","agent","Inspeção e conformidade","Serviços de inspeção, qualidade e conformidade.","https://www.bureauveritas.com/","Serviço"],
  ["JoomPro","brasil","agent","Atacado B2B, produtos chineses e locais","Plataforma B2B com fornecedores chineses e locais e serviços de importação.","https://joom.pro/pt-br","Online"],
  ["China Gate","brasil","agent","Importação direta, container compartilhado","Assessoria para importar da China, busca de fornecedores e logística.","https://chinagate.com.br/","Brasil"],
  ["China Link","brasil","agent","Consultoria de importação","Consulte serviços, taxas e modelo de operação diretamente.","https://chinalinktrading.com/","Brasil"],
  ["Dual Imports","brasil","agent","Importação e logística","Citada em discussões de importadores; confirme domínio e empresa antes de contratar.","https://dualimports.com.br/","Brasil"],
  ["Guelcos","brasil","agent","Consultoria de importação da China","Consultoria que publica guias sobre sites da China, impostos e MOQ.","https://guelcos.com.br/","Brasil"],
  ["Vitrine Global","brasil","importer","Importados B2B, importação sob demanda","Compra no atacado para empresas; consulte o pedido mínimo.","https://www.vitrineglobalimport.com.br/","Brasil"],
  ["IT Blue","brasil","importer","Eletrônicos, acessórios, ferramentas, utilidades","Importadora e distribuidora B2B para revenda.","https://www.itblue.com.br/","Brasil"],
  ["GB Importadora","brasil","importer","Importados para revenda","Da sua lista original; confirme catálogo e condições.","","Brasil"],
  ["C&A Importados","brasil","importer","Importados para revenda","Da sua lista original; confirme catálogo e condições.","","Brasil"],
  ["Casa Cristalina","brasil","importer","Utilidades e importados","Da sua lista original; confirme catálogo e condições.","","Brasil"],
  ["Y888 Importadora","brasil","importer","Importados para revenda","Da sua lista original; confirme catálogo e condições.","","Brasil"],
  ["M&M Martins Distribuidora","brasil","wholesale","Distribuição para lojistas","Da sua lista original; confirme catálogo e condições.","","Brasil"],
  ["Brundum","brasil","importer","Gadgets, eletrodomésticos, utilidades importadas","Divulga distribuição de importados para lojistas.","https://brundum.com.br/","Brasil"],
  ["Official Distribuidora","brasil","wholesale","Perfumes e cosméticos","Da sua lista original; confirme linhas e cadastro de revendedor.","","Brasil"],
  ["Matheus Alimentos","brasil","wholesale","Importados a granel (alimentos)","Da sua lista original; confirme validade, rótulo e registro.","","Brasil"],
  ["Tomate Mega Atacadista","brasil","importer","Telefonia, utilidades, ferramentas, informática, games e brinquedos","Mega atacadista de eletrônicos e importados, venda a lojistas; unidades em São Paulo e Curitiba.","","São Paulo / Curitiba"],
  ["25 de Março Atacado (importadora)","brasil","importer","Brinquedos, eletrônicos, acessórios, utilidades","Apresenta-se como importadora e distribuidora para lojistas.","https://25demarcoatacadoo.com.br/quem-somos","São Paulo"],
  ["25 de Março Online","brasil","wholesale","Eletrônicos e acessórios para revenda","Ofertas no atacado e varejo; verifique quantidade mínima.","https://www.25demarcoonline.com.br/","São Paulo"],
  ["PLB Importadora","brasil","importer","Produtos de alto giro","Citada em guia de fornecedores da 25 de Março para lojistas e distribuidores.","","São Paulo"],
  ["Braswu","brasil","importer","Importados para revenda","Citada em guia de fornecedores da 25 de Março.","","São Paulo"],
  ["Distribuidora Mega Mix","brasil","wholesale","Variedades para revenda","Citada em guia de fornecedores da 25 de Março.","","São Paulo"],
  ["GJS Atacado","brasil","wholesale","Atacado para lojistas","Citado em guia de fornecedores da 25 de Março.","","São Paulo"],
  ["Atacado Brasão","brasil","wholesale","Atacado para lojistas","Citado em guia de fornecedores da 25 de Março.","","São Paulo"],
  ["Sunday Acessórios","brasil","wholesale","Acessórios","Citado em guia de fornecedores da 25 de Março.","","São Paulo"],
  ["H'MASTON","brasil","wholesale","Moda e acessórios","Citado em guia de fornecedores da 25 de Março.","","São Paulo"],
  ["25 Cases Atacado & Varejo","brasil","importer","Utilidades, eletrônicos, itens populares","Importadora com variedade para atacado, segundo guia de fornecedores.","","São Paulo"],
  ["Michael & Jessica","brasil","wholesale","Moda feminina, perfumes importados, cosméticos, acessórios","Mix variado para revenda, segundo guia da Melhor Envio.","","São Paulo"],
  ["Mundo dos Fios","brasil","wholesale","Tricôs e malhas","Atende lojistas de todo o Brasil; nicho de moda.","","São Paulo"],
  ["Mix Mil","brasil","wholesale","Ponta de estoque multimarcas, infantil","Distribuidora de ponta de estoque do Brás, entrega para todo o Brasil.","","Brás, SP"],
  ["Trimix","brasil","wholesale","Roupas (atacado e varejo)","Três lojas físicas no centro de São Paulo, segundo o Shopify Brasil.","","São Paulo"],
  ["Liviana Atacado","brasil","wholesale","Moda","Citada em lista de roupas no atacado.","","Brasil"],
  ["Moda Online (marketplace)","brasil","marketplace","Confecções direto da fábrica","Marketplace que conecta lojistas e confecções, vários fornecedores em um carrinho.","","Online"],
  ["Delrô Atacado","brasil","wholesale","Moda para revenda","Nicho de moda, não de variedades.","https://www.delroatacado.com/","Brasil"],
  ["Mirão Distribuidora","brasil","wholesale","Acessórios e dispositivos elétricos e eletrônicos","Citada em guias de fornecedores de eletrônicos para revenda.","https://www.mirao.com.br/","Brasil"],
  ["HD Store","brasil","wholesale","Hardware, periféricos, redes, segurança eletrônica, gamer","Informática e acessórios; confirme se atende CNPJ no atacado.","https://www.hdstore.com.br/","Brasil"],
  ["Distribuidora Importline","brasil","importer","Eletrônicos importados","Citada em guia de fornecedores de eletrônicos; confirme pedido mínimo.","https://www.distribuidoraimportline.com.br/","Brasil"],
  ["Inova Atacadista","brasil","wholesale","Eletrônicos e gadgets","Citada por lançamentos frequentes; confirme condições para CNPJ.","https://www.inovaatacado.com.br/","Brasil"],
  ["Maxtill Atacado de Eletrônicos","brasil","wholesale","Eletrônicos no atacado, Brás","Atacado de eletrônicos no Brás, com grande variedade de itens.","https://www.maxtill.com.br/","Brás, SP"],
  ["Koba Atacado","brasil","wholesale","Pequenos e médios lojistas","Foco em atendimento personalizado a lojistas menores.","https://www.kobaatacado.com.br/","Brasil"],
  ["Ibyte Atacado","brasil","wholesale","Tecnologia para revendedores","Linha ampla de produtos de tecnologia voltada a revenda.","http://ibyteatacado.com.br","Brasil"],
  ["Portal Brás","brasil","wholesale","Moda e acessórios, vários nichos","Citado em lista de fornecedores para revenda, com foco em moda.","https://www.portalbras.com.br/","Brás, SP"],
  ["Yakao","brasil","wholesale","Mais de 45 categorias: tecnologia, brinquedos, cama/mesa/banho, telefonia","Variedade grande de nichos para revenda; confirme mínimos.","https://www.yakao.com.br/","Brasil"],
  ["Bim Distribuidora","brasil","wholesale","Perfumes e cosméticos","Distribuidora para revenda de perfumaria e cosméticos.","https://www.bimdistribuidora.com.br/","Brasil"],
  ["H9 Distribuidora","brasil","wholesale","Suplementos","Distribuidora de suplementos; exige atenção a registro e rotulagem.","http://www.h9distribuidora.com.br/wp/#home","Brasil"],
  ["Revenda de Cosméticos","brasil","wholesale","Cosméticos","Citado em lista de fornecedores de cosméticos para revenda.","https://www.revendadecosmeticos.com.br/","Brasil"],
  ["Hayamax","brasil","wholesale","Eletrônicos, áudio, instrumentos, acessórios","Distribuidora para revendedores; consulte cadastro B2B.","https://hayamax.com.br/","Brasil"],
  ["Oderço","brasil","wholesale","Informática, eletrônicos, acessórios","Distribuidora de tecnologia para canais de revenda.","https://www.oderco.com.br/","Brasil"],
  ["All Nations","brasil","wholesale","Informática e tecnologia","Distribuição para revendedores.","https://www.allnations.com.br/","Brasil"],
  ["Agis","brasil","wholesale","Informática, hardware","Distribuidora B2B de tecnologia.","https://www.agis.com.br/","Brasil"],
  ["SND","brasil","wholesale","Informática, componentes","Distribuidora de tecnologia para o mercado empresarial.","https://snd.com.br/","Brasil"],
  ["Ingram Micro Brasil","brasil","wholesale","Tecnologia e soluções empresariais","Distribuição B2B com condições para parceiros.","https://br.ingrammicro.com/","Brasil"],
  ["Golden Distribuidora","brasil","wholesale","Informática e eletrônicos","Distribuição para revenda, conhecida pela rapidez no atendimento.","https://goldendistribuidora.com.br/","Brasil"],
  ["Martins Atacado","brasil","wholesale","Mercearia, utilidades, higiene","Atacadista e distribuidor nacional para comerciantes.","https://www.martinsatacado.com.br/","Uberlândia, MG"],
  ["Tambasa Atacadistas","brasil","wholesale","Utilidades, ferramentas, casa","Atacado de várias categorias para abastecer lojas.","https://www.tambasa.com/","Brasil"],
  ["Arcom","brasil","wholesale","Distribuição para comércio","Distribuidora nacional com atendimento comercial.","https://www.arcom.com.br/","Brasil"],
  ["Gimba","brasil","wholesale","Papelaria e escritório","Materiais para empresas; compare preço por volume.","https://www.gimba.com.br/","Brasil"],
  ["Rua 25 de Março (SP)","brasil","polo","Variedades, importados, eletrônicos, brinquedos","Maior polo de comércio popular do país; galerias com boxes por nicho. Saia com 2–3 contatos por categoria.","","São Paulo"],
  ["Brás (SP)","brasil","polo","Confecção e moda","Maior polo de moda atacadista; muitos vendedores são fabricantes.","","São Paulo"],
  ["Feira da Madrugada (Brás)","brasil","polo","Moda, acessórios e eletrônicos populares","Feira atacadista no Brás; tem também portal online de eletrônicos para revenda.","https://www.feiradamadrugadasp.com.br/eletronicos-no-atacado-para-revenda/","Brás, SP"],
  ["Santa Efigênia (SP)","brasil","polo","Eletrônicos e componentes","Conhecida pelos eletrônicos; teste os equipamentos antes de comprar.","","São Paulo"],
  ["Galeria Pagé (Brás)","brasil","polo","Variedades e importados","Galeria no Brás, a poucos minutos da 25 de Março.","","São Paulo"],
  ["Bom Retiro (SP)","brasil","polo","Confecção e moda","Polo tradicional de confecção em São Paulo, com muitos fabricantes.","","São Paulo"],
  ["Rua 44 (Goiânia)","brasil","polo","Moda e confecção","Um dos maiores polos de moda atacadista do Centro-Oeste.","","Goiânia, GO"],
  ["Toritama (PE)","brasil","polo","Jeans e confecção","Polo de jeans do Agreste pernambucano, com compra direto de fabricantes.","","Toritama, PE"],
  ["Ciudad del Este (Paraguai)","brasil","polo","Eletrônicos, perfumes, importados","Atenção: compra de fora do país tem limite de cota e regras de importação. Revender sem regularizar pode virar problema fiscal. Informe-se antes.","","Paraguai"],
  ["ImportYeti","china","tool","Achar a fábrica de um concorrente","Base gratuita de registros de embarques dos EUA. Dica de importadores: pesquise o produto ou a marca de um concorrente e veja de quais fornecedores ele compra.","https://www.importyeti.com/","Ferramenta"],
  ["Comex Stat (MDIC)","brasil","tool","Estatísticas oficiais de importação por NCM","Veja quanto o Brasil importa de cada produto, de onde e a que preço médio. Útil para validar demanda e preço.","https://comexstat.mdic.gov.br/","Ferramenta"],
  ["Portal Único Siscomex","brasil","tool","Importação formal, habilitação RADAR","Portal oficial do comércio exterior para quem vai importar como empresa.","https://portalunico.siscomex.gov.br/","Ferramenta"],
  ["Receita Federal","brasil","tool","Regras de Remessa Conforme, tributos e consulta de CNPJ","Fonte oficial para alíquotas, regimes de importação e situação cadastral.","https://www.gov.br/receitafederal/pt-br","Ferramenta"],
  ["Anatel","brasil","tool","Homologação de eletrônicos e telecom","Produtos que emitem sinal (Bluetooth, Wi-Fi, celulares) precisam de homologação.","https://www.gov.br/anatel/pt-br","Ferramenta"],
  ["Inmetro","brasil","tool","Certificação compulsória de produtos","Verifique se o produto exige certificação antes de importar para revender.","https://www.gov.br/inmetro/pt-br","Ferramenta"],
  ["Reclame Aqui","brasil","tool","Reputação de empresas brasileiras","Pesquise o nome e o CNPJ do fornecedor antes de pagar.","https://www.reclameaqui.com.br/","Ferramenta"],
  ["Mercado Livre Tendências","brasil","tool","Descobrir o que está em alta no ML","Página oficial com buscas e categorias em crescimento. Boa para escolher produto antes de importar.","https://tendencias.mercadolivre.com.br/","Ferramenta"],
  ["Central de vendedores do Mercado Livre","brasil","tool","Tarifas, regras e simulador de custos","Fonte oficial para confirmar comissão, custo fixo ou operacional, frete e regras de anúncio.","https://vendedores.mercadolivre.com.br/","Ferramenta"],
  ["Google Trends","brasil","tool","Ver se a procura pelo produto sobe ou cai","Compare termos no Brasil e veja a sazonalidade antes de comprar um lote.","https://trends.google.com.br/","Ferramenta"],
  ["Nubimetrics","brasil","tool","Análise de mercado no Mercado Livre","Ferramenta paga de inteligência para vendedores do Mercado Livre; confira planos e se vale para o seu tamanho.","https://www.nubimetrics.com/","Ferramenta"],
  ["Bling","brasil","tool","ERP: estoque, nota fiscal e integração com ML","Sistema de gestão usado por vendedores de marketplace para emitir nota e controlar estoque. Confirme planos e integração.","https://www.bling.com.br/","Ferramenta"],
  ["CNPJá","brasil","tool","Consulta de dados públicos de CNPJ","Mostra situação, data de abertura, atividades e sócios de uma empresa.","https://cnpja.com/","Ferramenta"],
  ["Guia: fornecedores da 25 de Março (Tray)","brasil","guide","Lista de fornecedores e dicas","Artigo com fornecedores e dicas para escolher parceiros na 25 de Março.","https://tray.com.br/escola/fornecedores-25-de-marco/","Leitura"],
  ["Guia: 15 fornecedores da 25 de Março (E-commerce na Prática)","brasil","guide","Fornecedores por nicho, com endereços","Lista por nicho com endereços e dicas de escolha.","https://ecommercenapratica.com/blog/fornecedores-25-de-marco/","Leitura"],
  ["Guia: fornecedores de eletrônicos (Tray)","brasil","guide","12 opções de eletrônicos para revenda","Lista de distribuidoras de eletrônicos e tecnologia para lojistas.","https://tray.com.br/escola/fornecedores-de-eletronicos/","Leitura"],
  ["Guia: fornecedores para revenda (JivoChat)","brasil","guide","15 opções por nicho","Lista de fornecedores de moda, cosméticos, tecnologia e mais.","https://www.jivochat.com.br/blog/vendas/fornecedores-de-produtos-para-revenda.html","Leitura"],
  ["Guia: fornecedores da China (Tray)","china","guide","Sites e fornecedores da China","Artigo com plataformas para comprar no atacado da China.","https://tray.com.br/escola/fornecedores-da-china/","Leitura"],
  ["Guia: sites da China (Guelcos)","china","guide","Qual site usar para cada objetivo","Compara Alibaba, 1688, Made-in-China, Global Sources, impostos e mínimos.","https://guelcos.com.br/conteudo/empresa-de-importacao/sites-da-china","Leitura"],
  ["Guia: onde comprar produtos da China (ToExceed)","china","guide","Plataformas, MOQ e agentes","Explica diferenças entre Alibaba e 1688, MOQ e produtos para revender.","https://toexceed.com.br/blog/2026/09/12/produtos-da-china-onde-comprar-para-importar-e-revender-no-brasil/","Leitura"],
  ["Guia: como evitar golpes no Alibaba (Epic Sourcing)","china","guide","9 sinais de alerta e verificações","Checklist de verificação antes de pagar um fornecedor.","https://www.epicsourcing.co/post/how-to-avoid-alibaba-scams-red-flags-us-importers","Leitura"]
];

const REGION_NAMES = { china: "China / internacional", brasil: "Brasil" };
const KIND_NAMES = {
  marketplace: "Plataforma B2B",
  importer: "Importadora",
  wholesale: "Distribuidora / atacado",
  agent: "Agente / assessoria",
  polo: "Polo / mercado físico",
  tool: "Ferramenta",
  guide: "Guia de referência"
};
const STATUS = [
  ["novo", "Novo"], ["contatado", "Contatado"], ["cotacao", "Cotação recebida"],
  ["amostra", "Amostra pedida"], ["aprovado", "Aprovado"], ["descartado", "Descartado"]
];
const NICHES = [
  ["eletronicos", "Eletrônicos", /eletr|celular|telefon|áudio|audio|gadget|inform|tecnolog|games|hardware|componentes/i],
  ["moda", "Moda", /moda|roupa|malha|tricô|confec|vestu|jeans|lingerie/i],
  ["brinquedos", "Brinquedos", /brinqued/i],
  ["cosmeticos", "Cosméticos e perfumes", /cosm|perfum|beleza|maquiagem/i],
  ["utilidades", "Utilidades e casa", /utilidade|casa|ferrament|variedade|cama/i],
  ["acessorios", "Acessórios", /acess|bijuter|semijoia/i],
  ["papelaria", "Papelaria", /papelaria|escritório/i],
  ["alimentos", "Alimentos", /aliment|mercearia/i]
];
const SUP_CHECKS = [
  "CNPJ / registro da empresa verificado e ativo",
  "Pedido mínimo e tabela de preços recebidos por escrito",
  "Amostra paga recebida e testada",
  "Pagamento protegido, contrato ou nota fiscal",
  "Reputação pesquisada (avaliações, Reclame Aqui)",
  "Custo final (frete + impostos) calculado"
];

const items = DATA.map((r, i) => {
  const hay = r[3] + " " + r[4];
  return {
    id: String(i), name: r[0], region: r[1], kind: r[2], niche: r[3], desc: r[4], url: r[5], city: r[6],
    niches: NICHES.filter(n => n[2].test(hay)).map(n => n[0])
  };
});

/* ===================== ESTADO ===================== */
const KEY = "radar-v2";
function defaults() {
  return { fav: {}, status: {}, rating: {}, notes: {}, contact: {}, last: {}, checks: {}, quotes: [], gcheck: {}, contacts: [], products: [], ml: {}, mlcheck: {}, settings: { usd: 5.5, cny: 0.77, theme: "dark" } };
}
let state = defaults();
(function loadState() {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) mergeState(JSON.parse(raw));
    else {
      const old = JSON.parse(localStorage.getItem("radar-favs") || "[]");
      if (Array.isArray(old)) old.forEach(id => { state.fav[String(id)] = true; });
    }
  } catch (_) {}
})();
function mergeState(s) {
  if (!s || typeof s !== "object") return false;
  const d = defaults();
  ["fav", "status", "rating", "notes", "contact", "last", "checks", "gcheck", "ml", "mlcheck"].forEach(k => {
    state[k] = (s[k] && typeof s[k] === "object" && !Array.isArray(s[k])) ? s[k] : d[k];
  });
  state.quotes = Array.isArray(s.quotes) ? s.quotes.filter(q => q && typeof q === "object").slice(0, 500) : [];
  state.contacts = Array.isArray(s.contacts) ? s.contacts.filter(c => c && typeof c === "object" && c.id).slice(0, 5000) : [];
  state.products = Array.isArray(s.products) ? s.products.filter(c => c && typeof c === "object" && c.id).slice(0, 2000) : [];
  state.settings = Object.assign(d.settings, (s.settings && typeof s.settings === "object") ? s.settings : {});
  return true;
}
function save() { try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (_) {} }

/* ===================== UTIL ===================== */
const $ = id => document.getElementById(id);
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) {
    if (c == null || c === false) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}
function parseNum(v) {
  let s = String(v == null ? "" : v).trim().replace(/[^\d.,-]/g, "");
  if (s.includes(",")) s = s.replace(/\./g, "").replace(",", ".");
  const n = parseFloat(s);
  return isFinite(n) ? n : 0;
}
const brl = new Intl.NumberFormat("pt-BR", { style: "currency", currency: "BRL" });
const usdF = new Intl.NumberFormat("pt-BR", { style: "currency", currency: "USD" });
const fmt = n => isFinite(n) ? brl.format(n) : "—";
const pct = n => isFinite(n) ? n.toLocaleString("pt-BR", { maximumFractionDigits: 1 }) + "%" : "—";
function numStr(n, d) { return Number(n).toLocaleString("pt-BR", { minimumFractionDigits: d, maximumFractionDigits: d }); }
function safeUrl(v) {
  try { const u = new URL(v); if (u.protocol === "https:" || u.protocol === "http:") return u.href; } catch (_) {}
  return null;
}
function googleUrl(item) {
  const extra = item.kind === "guide" ? "" : (item.region === "brasil" ? " atacado CNPJ" : " wholesale");
  return "https://www.google.com/search?q=" + encodeURIComponent(item.name + extra);
}
let toastTimer = null;
function toast(msg) {
  const t = $("toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 3000);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copiado ✓"); }
  catch (_) {
    try {
      const ta = el("textarea", { style: "position:fixed;opacity:0" }); ta.value = text;
      document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove(); toast("Copiado ✓");
    } catch (__) { window.prompt("Copie o texto:", text); }
  }
}
function download(name, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function stars(n) { n = Math.max(0, Math.min(5, n | 0)); return "★".repeat(n) + "☆".repeat(5 - n); }
function statusLabel(k) { const s = STATUS.find(x => x[0] === k); return s ? s[1] : "Novo"; }

/* ===================== ABAS ===================== */
const TABS = [
  ["suppliers", "🏭 Fornecedores"], ["trends", "📈 Tendências ML"], ["contacts", "📇 Contatos"], ["ml", "🛒 Mercado Livre"], ["products", "📦 Meus produtos"],
  ["cost", "🧮 Custo de importação"], ["price", "💰 Preço e margem"], ["quotes", "📊 Cotações"],
  ["cnpj", "🔎 Verificar CNPJ"], ["messages", "✉️ Mensagens"], ["guide", "📘 Guia e glossário"], ["data", "💾 Meus dados"]
];
function showTab(id) {
  if (id === "trends") { loadTrends(false); loadCategorias(); }
  if (!TABS.some(t => t[0] === id)) id = "suppliers";
  TABS.forEach(t => { $("tab-" + t[0]).hidden = t[0] !== id; });
  document.querySelectorAll("#tabs button").forEach(b => b.setAttribute("aria-selected", String(b.dataset.tab === id)));
  document.querySelector(".fxbar").hidden = !["cost", "quotes"].includes(id);
  try { history.replaceState(null, "", "#" + id); } catch (_) {}
  if (id === "data") renderData();
  if (id === "quotes") renderQuotes();
  if (id === "cost") calcCost();
  if (id === "price") calcPrice();
  if (id === "messages") buildMessage();
  if (id === "contacts") renderContacts();
  if (id === "ml") { renderML(); buildTitle(); buildDesc(); buildResearch(); }
  if (id === "products") renderProducts();
}
(function buildTabs() {
  const nav = $("tabs");
  TABS.forEach(t => nav.append(el("button", { type: "button", role: "tab", "data-tab": t[0], "aria-selected": "false", text: t[1], onclick: () => showTab(t[0]) })));
})();

/* ===================== FORNECEDORES ===================== */
let nicheSel = "all", onlyFav = false;
const searchInput = $("search"), regionSel = $("region"), kindSel = $("kind"), statusFilter = $("statusSel"), sortSel = $("sort");

(function fillSelects() {
  kindSel.append(el("option", { value: "all", text: "Todos os tipos" }));
  Object.keys(KIND_NAMES).forEach(k => kindSel.append(el("option", { value: k, text: KIND_NAMES[k] })));
  statusFilter.append(el("option", { value: "all", text: "Todos os status" }));
  STATUS.forEach(s => statusFilter.append(el("option", { value: s[0], text: s[1] })));
})();
function renderChips() {
  const box = $("chips"); box.replaceChildren();
  const mk = (id, label) => box.append(el("button", {
    type: "button", class: "chip", "aria-pressed": String(nicheSel === id), text: label,
    onclick: () => { nicheSel = id; renderChips(); render(); }
  }));
  mk("all", "Todos os nichos");
  NICHES.forEach(n => mk(n[0], n[1]));
}
function curStatus(id) { return state.status[id] || "novo"; }

function card(item) {
  const isFav = !!state.fav[item.id];
  const rating = state.rating[item.id] | 0;
  const st = curStatus(item.id);
  const c = el("article", { class: "card" + (isFav ? " fav" : "") });
  const tags = el("div", { class: "tags" },
    el("span", { class: "tag", text: REGION_NAMES[item.region] }),
    el("span", { class: "tag", text: KIND_NAMES[item.kind] }),
    item.city ? el("span", { class: "tag", text: item.city }) : null
  );
  const meta = el("div", { class: "tags", style: "margin-top:8px" });
  if (st !== "novo") meta.append(el("span", { class: "st st-" + st, text: statusLabel(st) }));
  if (rating) meta.append(el("span", { class: "stars", "aria-label": rating + " de 5 estrelas", text: stars(rating) }));
  if (state.notes[item.id]) meta.append(el("span", { class: "muted small", title: "Tem anotações", text: "📝" }));
  const links = el("div", { class: "links" });
  const href = safeUrl(item.url);
  if (href) links.append(el("a", { class: "link", href, target: "_blank", rel: "noopener noreferrer", text: "Abrir site ↗" }));
  links.append(el("a", { class: "link", href: googleUrl(item), target: "_blank", rel: "noopener noreferrer", text: href ? "Pesquisar ↗" : "Pesquisar ↗" }));
  links.append(el("button", { type: "button", class: "ghost sm", text: "Detalhes", onclick: () => openDetail(item.id) }));
  links.append(el("button", {
    type: "button", class: "ghost sm" + (isFav ? " on" : ""), style: "margin-left:auto",
    text: isFav ? "★ Favorito" : "☆ Favoritar",
    onclick: () => { if (state.fav[item.id]) delete state.fav[item.id]; else state.fav[item.id] = true; save(); render(); }
  }));
  c.append(tags, el("h3", { text: item.name }), el("p", { class: "niche", text: item.niche }), el("p", { class: "desc", text: item.desc }), meta, links);
  return c;
}
function filtered() {
  const term = searchInput.value.trim().toLocaleLowerCase("pt-BR");
  const list = items.filter(it => {
    if (regionSel.value !== "all" && it.region !== regionSel.value) return false;
    if (kindSel.value !== "all" && it.kind !== kindSel.value) return false;
    if (statusFilter.value !== "all" && curStatus(it.id) !== statusFilter.value) return false;
    if (nicheSel !== "all" && !it.niches.includes(nicheSel)) return false;
    if (onlyFav && !state.fav[it.id]) return false;
    if (!term) return true;
    const hay = [it.name, it.niche, it.desc, it.city, REGION_NAMES[it.region], KIND_NAMES[it.kind], state.notes[it.id] || ""]
      .join(" ").toLocaleLowerCase("pt-BR");
    return term.split(/\s+/).every(w => hay.includes(w));
  });
  if (sortSel.value === "az") list.sort((a, b) => a.name.localeCompare(b.name, "pt-BR"));
  else if (sortSel.value === "rating") list.sort((a, b) => (state.rating[b.id] | 0) - (state.rating[a.id] | 0));
  else if (sortSel.value === "fav") list.sort((a, b) => (state.fav[b.id] ? 1 : 0) - (state.fav[a.id] ? 1 : 0));
  return list;
}
function render() {
  const list = filtered();
  const box = $("results"); box.replaceChildren();
  if (!list.length) box.append(el("div", { class: "empty", text: "Nenhum resultado. Tente outra busca ou remova um filtro." }));
  else { const f = document.createDocumentFragment(); list.forEach(it => f.append(card(it))); box.append(f); }
  $("onlyFav").classList.toggle("on", onlyFav);
  const favCount = Object.keys(state.fav).length;
  $("count").textContent = list.length + " resultado(s) de " + items.length + " entradas · " + favCount + " favorito(s)";
}

/* ----- detalhes ----- */
const dlg = $("dlg");
function openDetail(id) {
  const it = items.find(x => x.id === id); if (!it) return;
  dlg.replaceChildren();
  const href = safeUrl(it.url);
  const checks = state.checks[id] && typeof state.checks[id] === "object" ? state.checks[id] : (state.checks[id] = {});
  const stSel = el("select", { "aria-label": "Status" });
  STATUS.forEach(s => stSel.append(el("option", { value: s[0], text: s[1] })));
  stSel.value = curStatus(id);
  stSel.addEventListener("change", () => { state.status[id] = stSel.value; save(); });
  const rSel = el("select", { "aria-label": "Nota" });
  rSel.append(el("option", { value: "0", text: "Sem nota" }));
  for (let i = 1; i <= 5; i++) rSel.append(el("option", { value: String(i), text: stars(i) }));
  rSel.value = String(state.rating[id] | 0);
  rSel.addEventListener("change", () => { const v = parseInt(rSel.value, 10) || 0; if (v) state.rating[id] = v; else delete state.rating[id]; save(); });
  const contact = el("input", { placeholder: "WhatsApp, e-mail, nome do vendedor...", value: state.contact[id] || "" });
  contact.addEventListener("input", () => { if (contact.value) state.contact[id] = contact.value; else delete state.contact[id]; save(); });
  const last = el("input", { type: "date", value: state.last[id] || "" });
  last.addEventListener("change", () => { if (last.value) state.last[id] = last.value; else delete state.last[id]; save(); });
  const notes = el("textarea", { placeholder: "Preços, mínimos, prazos, impressões...", rows: "5" });
  notes.value = state.notes[id] || "";
  notes.addEventListener("input", () => { if (notes.value) state.notes[id] = notes.value; else delete state.notes[id]; save(); });

  dlg.append(
    el("div", { class: "tags" }, el("span", { class: "tag", text: REGION_NAMES[it.region] }), el("span", { class: "tag", text: KIND_NAMES[it.kind] }), it.city ? el("span", { class: "tag", text: it.city }) : null),
    el("h2", { style: "margin-top:10px", text: it.name }),
    el("p", { class: "niche", text: it.niche }),
    el("p", { class: "desc", text: it.desc }),
    el("div", { class: "form", style: "grid-template-columns:1fr 1fr" },
      el("label", {}, "Status da negociação", stSel),
      el("label", {}, "Sua nota", rSel),
      el("label", { class: "full" }, "Contato", contact),
      el("label", {}, "Último contato", last)
    ),
    el("h3", { text: "Verificações deste fornecedor" }),
    el("div", {}, SUP_CHECKS.map((txt, i) => {
      const cb = el("input", { type: "checkbox" }); cb.checked = !!checks[i];
      cb.addEventListener("change", () => { if (cb.checked) checks[i] = true; else delete checks[i]; save(); });
      return el("label", { class: "check" }, cb, el("span", { text: txt }));
    })),
    el("h3", { text: "Anotações" }), notes,
    el("div", { class: "row", style: "margin-top:12px" },
      href ? el("a", { class: "link", href, target: "_blank", rel: "noopener noreferrer", text: "Abrir site ↗" }) : null,
      el("a", { class: "link", href: googleUrl(it), target: "_blank", rel: "noopener noreferrer", text: "Pesquisar ↗" }),
      el("button", { type: "button", class: "ghost sm", text: "✉ Gerar mensagem", onclick: () => { dlg.close(); $("m_sup").value = it.name; showTab("messages"); } }),
      el("button", { type: "button", class: "ghost sm", text: "📇 Salvar nos contatos", onclick: () => {
        dlg.close(); showTab("contacts"); ctCancel();
        ctFill({ company: it.name, site: it.url || "", place: it.city || "", products: it.niche, type: it.kind === "agent" ? "agente" : it.kind === "wholesale" ? "distribuidor" : "importador" });
        $("ct_name").focus(); toast("Complete o contato e clique em Salvar.");
      } }),
      el("button", { type: "button", class: "sm", style: "margin-left:auto", text: "Fechar", onclick: () => dlg.close() })
    )
  );
  if (typeof dlg.showModal === "function") dlg.showModal(); else dlg.setAttribute("open", "");
}
dlg.addEventListener("close", () => { render(); });
dlg.addEventListener("click", e => { if (e.target === dlg) dlg.close(); });

function csvCell(v) { return '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"'; }
function downloadCsv() {
  const head = ["Nome", "Região", "Tipo", "Nicho", "Descrição", "Site", "Local", "Status", "Nota", "Contato", "Último contato", "Anotações", "Favorito"];
  const rows = filtered().map(it => [
    it.name, REGION_NAMES[it.region], KIND_NAMES[it.kind], it.niche, it.desc, it.url, it.city,
    statusLabel(curStatus(it.id)), state.rating[it.id] || "", state.contact[it.id] || "", state.last[it.id] || "", state.notes[it.id] || "", state.fav[it.id] ? "sim" : ""
  ]);
  const text = "\uFEFF" + [head, ...rows].map(r => r.map(csvCell).join(";")).join("\r\n");
  download("fornecedores.csv", text, "text/csv;charset=utf-8");
}

["input"].forEach(ev => searchInput.addEventListener(ev, render));
[regionSel, kindSel, statusFilter, sortSel].forEach(s => s.addEventListener("change", render));
$("onlyFav").addEventListener("click", () => { onlyFav = !onlyFav; render(); });
$("csv").addEventListener("click", downloadCsv);
$("clear").addEventListener("click", () => {
  searchInput.value = ""; regionSel.value = "all"; kindSel.value = "all"; statusFilter.value = "all";
  sortSel.value = "default"; nicheSel = "all"; onlyFav = false; renderChips(); render();
});

/* ===================== CÂMBIO ===================== */
function syncFxInputs() {
  $("fx_usd").value = numStr(state.settings.usd, 2);
  $("fx_cny").value = numStr(state.settings.cny, 3);
}
function readFx() {
  const u = parseNum($("fx_usd").value), c = parseNum($("fx_cny").value);
  if (u > 0) state.settings.usd = u;
  if (c > 0) state.settings.cny = c;
  save();
  const t = TABS.find(t => !$("tab-" + t[0]).hidden);
  if (t && t[0] === "cost") calcCost();
  if (t && t[0] === "quotes") renderQuotes();
}
$("fx_usd").addEventListener("input", readFx);
$("fx_cny").addEventListener("input", readFx);
$("fxFetch").addEventListener("click", async () => {
  try {
    const r = await fetch("https://economia.awesomeapi.com.br/json/last/USD-BRL,CNY-BRL");
    if (!r.ok) throw new Error("http");
    const j = await r.json();
    const u = parseFloat(j.USDBRL.bid), c = parseFloat(j.CNYBRL.bid);
    if (!(u > 0 && c > 0)) throw new Error("dados");
    state.settings.usd = u; state.settings.cny = c; save(); syncFxInputs();
    $("fxInfo").textContent = "Cotação atualizada em " + new Date().toLocaleString("pt-BR") + ". Vale como referência; o câmbio do seu pagamento pode variar.";
    readFx();
  } catch (_) {
    $("fxInfo").textContent = "Não consegui buscar a cotação agora. Digite os valores manualmente.";
  }
});

/* ===================== CALCULADORA DE CUSTO ===================== */
const PRESETS = {
  remessa_pj: { ii: 60, ded: 0, ipi: 0, pis: 0, cofins: 0, icms: 17 },
  remessa_pf: { ii: 60, ded: 30, ipi: 0, pis: 0, cofins: 0, icms: 17 },
  formal: { ii: 18, ded: 0, ipi: 10, pis: 2.1, cofins: 9.65, icms: 18 }
};
function applyPreset() {
  const p = PRESETS[$("c_mode").value]; if (!p) return;
  $("c_ii").value = numStr(p.ii, 2).replace(",00", ""); $("c_ded").value = String(p.ded);
  $("c_ipi").value = String(p.ipi); $("c_pis").value = numStr(p.pis, 2).replace(",00", "");
  $("c_cofins").value = numStr(p.cofins, 2).replace(",00", ""); $("c_icms").value = String(p.icms);
}
function calcCost() {
  const g = id => parseNum($(id).value);
  const usd = state.settings.usd || 0;
  const price = g("c_price"), qty = Math.max(g("c_qty"), 0), freight = Math.max(g("c_freight"), 0), insPct = Math.max(g("c_ins"), 0);
  const merch = price * qty * usd, frt = freight * usd, ins = merch * insPct / 100;
  const adu = merch + frt + ins;
  const ii = Math.max(adu * g("c_ii") / 100 - g("c_ded") * usd, 0);
  const ipi = (adu + ii) * g("c_ipi") / 100;
  const pis = adu * g("c_pis") / 100, cof = adu * g("c_cofins") / 100;
  const icmsRate = Math.min(Math.max(g("c_icms"), 0), 99) / 100;
  const icms = ((adu + ii + ipi + pis + cof) / (1 - icmsRate)) * icmsRate;
  const other = Math.max(g("c_other"), 0);
  const taxes = ii + ipi + pis + cof + icms;
  const total = adu + taxes + other;
  const unit = qty > 0 ? total / qty : 0;
  lastUnitCost = unit;
  const resale = g("c_resale");

  const kp = $("costKpis"); kp.replaceChildren();
  const k = (label, val) => kp.append(el("div", { class: "kpi" }, el("span", { text: label }), el("div", { class: "big", text: val })));
  k("Custo total", fmt(total));
  k("Custo por unidade", qty > 0 ? fmt(unit) : "—");
  k("Impostos e taxas", fmt(taxes + other));
  k("Imposto sobre o valor aduaneiro", adu > 0 ? pct(taxes / adu * 100) : "—");
  if (resale > 0 && unit > 0) {
    k("Lucro por unidade (antes de taxas de venda)", fmt(resale - unit));
    k("Margem bruta", pct((resale - unit) / resale * 100));
    k("Markup sobre o custo", pct((resale - unit) / unit * 100));
  }
  const t = $("costTable"); t.replaceChildren();
  const row = (label, val, cls) => t.append(el("tr", { class: cls || "" }, el("td", { text: label }), el("td", { class: "num", text: fmt(val) })));
  row("Mercadoria (" + usdF.format(price) + " × " + qty + ")", merch);
  row("Frete internacional", frt);
  row("Seguro", ins);
  row("Valor aduaneiro", adu, "total");
  row("Imposto de importação (II)", ii);
  row("IPI", ipi);
  row("PIS", pis);
  row("COFINS", cof);
  row("ICMS (por dentro)", icms);
  row("Outras despesas", other);
  row("Custo total estimado", total, "total");
  if (qty > 0) row("Custo por unidade", unit, "total");
}

/* ===================== PREÇO E MARGEM ===================== */
function calcPrice() {
  const g = id => parseNum($(id).value);
  const cost = g("p_cost"), fixed = g("p_fixed"), mg = g("p_margin") / 100;
  const fee = g("p_fee") / 100, tax = g("p_tax") / 100, ads = g("p_ads") / 100, price = g("p_price");
  const base = cost + fixed, vars = fee + tax + ads;
  const kp = $("priceKpis"); kp.replaceChildren();
  const k = (label, val) => kp.append(el("div", { class: "kpi" }, el("span", { text: label }), el("div", { class: "big", text: val })));
  const tbl = $("priceTable"); tbl.replaceChildren();
  const denom = 1 - vars - mg;
  if (denom <= 0) {
    kp.append(el("div", { class: "notice bad", text: "Com essa margem e essas taxas, a soma passa de 100% do preço: é impossível atingir. Reduza a margem ou as taxas." }));
  } else {
    const sug = base / denom;
    k("Preço sugerido", fmt(sug));
    k("Lucro por unidade", fmt(sug * mg));
    k("Markup sobre o custo", pct((sug - base) / base * 100));
  }
  if (1 - vars > 0) k("Preço de equilíbrio (lucro zero)", fmt(base / (1 - vars)));
  if (price > 0) {
    const profit = price * (1 - vars) - base;
    k("Lucro no seu preço", fmt(profit));
    k("Margem no seu preço", pct(profit / price * 100));
  }
  tbl.append(el("tr", {}, el("th", { text: "Margem" }), el("th", { class: "num", text: "Preço de venda" }), el("th", { class: "num", text: "Lucro/un" })));
  [10, 15, 20, 25, 30, 40, 50].forEach(m => {
    const d = 1 - vars - m / 100;
    if (d <= 0) { tbl.append(el("tr", {}, el("td", { text: m + "%" }), el("td", { class: "num", text: "—" }), el("td", { class: "num", text: "—" }))); return; }
    const p = base / d;
    tbl.append(el("tr", {}, el("td", { text: m + "%" }), el("td", { class: "num", text: fmt(p) }), el("td", { class: "num", text: fmt(p * m / 100) })));
  });
}

/* ===================== COTAÇÕES ===================== */
function rateOf(cur) { return cur === "USD" ? state.settings.usd : cur === "CNY" ? state.settings.cny : 1; }
function quoteUnitBrl(q) {
  const qty = Math.max(Number(q.qty) || 0, 1);
  return ((Number(q.price) || 0) + (Number(q.freight) || 0) / qty) * rateOf(q.cur) * (1 + (Number(q.tax) || 0) / 100);
}
function renderQuotes() {
  const t = $("quoteTable"); t.replaceChildren();
  if (!state.quotes.length) { t.append(el("tr", {}, el("td", { class: "muted", text: "Nenhuma cotação registrada ainda." }))); return; }
  const rows = state.quotes.map((q, i) => ({ q, i, u: quoteUnitBrl(q) })).sort((a, b) => a.u - b.u);
  t.append(el("tr", {},
    ["Fornecedor", "Produto", "Preço", "Qtd / MOQ", "Prazo", "Custo/un (R$)", "Total (R$)", ""].map((h, n) => el("th", { class: n >= 5 && n < 7 ? "num" : "", text: h }))
  ));
  rows.forEach((r, n) => {
    const q = r.q, sym = q.cur === "USD" ? "US$" : q.cur === "CNY" ? "¥" : "R$";
    t.append(el("tr", { class: n === 0 && rows.length > 1 ? "best" : "" },
      el("td", { text: q.sup || "—" }), el("td", { text: q.prod || "—" }),
      el("td", { text: sym + " " + numStr(q.price, 2) }),
      el("td", { text: (q.qty || "—") + " / " + (q.moq || "—") }),
      el("td", { text: q.days ? q.days + " d" : "—" }),
      el("td", { class: "num", text: fmt(r.u) }),
      el("td", { class: "num", text: fmt(r.u * (Number(q.qty) || 0)) }),
      el("td", {}, el("button", { type: "button", class: "danger sm", text: "Excluir", onclick: () => { state.quotes.splice(r.i, 1); save(); renderQuotes(); } }))
    ));
  });
}
$("q_add").addEventListener("click", () => {
  const price = parseNum($("q_price").value), qty = parseNum($("q_qty").value);
  if (!(price > 0) || !(qty > 0)) { toast("Informe preço e quantidade."); return; }
  state.quotes.push({
    sup: $("q_sup").value.trim(), prod: $("q_prod").value.trim(), cur: $("q_cur").value, price, qty,
    moq: parseNum($("q_moq").value) || "", freight: parseNum($("q_freight").value), days: parseNum($("q_days").value) || "", tax: parseNum($("q_tax").value)
  });
  save(); renderQuotes();
  ["q_sup", "q_prod", "q_price", "q_qty", "q_moq", "q_days"].forEach(id => { $(id).value = ""; });
  toast("Cotação adicionada.");
});
$("q_clear").addEventListener("click", () => {
  if (!state.quotes.length) return;
  if (confirm("Apagar todas as cotações?")) { state.quotes = []; save(); renderQuotes(); }
});

/* ===================== CNPJ ===================== */
function validCnpj(raw) {
  const c = String(raw).replace(/\D/g, "");
  if (c.length !== 14 || /^(\d)\1+$/.test(c)) return false;
  const dig = base => {
    let w = base.length - 7, s = 0;
    for (let i = 0; i < base.length; i++) { s += Number(base[i]) * w--; if (w < 2) w = 9; }
    const r = s % 11; return r < 2 ? 0 : 11 - r;
  };
  const d1 = dig(c.slice(0, 12)), d2 = dig(c.slice(0, 12) + d1);
  return d1 === Number(c[12]) && d2 === Number(c[13]);
}
function fmtCnpj(c) { return c.replace(/^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/, "$1.$2.$3/$4-$5"); }
async function checkCnpj() {
  const c = $("cnpjInput").value.replace(/\D/g, "");
  const out = $("cnpjOut"); out.replaceChildren();
  $("cnpjLinks").hidden = true;
  if (!validCnpj(c)) {
    out.append(el("div", { class: "notice bad", text: "CNPJ inválido: os dígitos verificadores não conferem. Peça o número de novo ao fornecedor. CNPJ que não bate é sinal de alerta." }));
    return;
  }
  out.append(el("div", { class: "notice ok", text: "CNPJ com formato válido: " + fmtCnpj(c) + ". Isso não prova que a empresa é confiável; consultando dados públicos..." }));
  $("cnpjLinkA").href = "https://cnpja.com/office/" + c;
  $("cnpjLinkG").href = "https://www.google.com/search?q=" + encodeURIComponent(fmtCnpj(c) + " reclame aqui");
  $("cnpjLinks").hidden = false;
  try {
    const r = await fetch("https://brasilapi.com.br/api/cnpj/v1/" + c);
    if (!r.ok) throw new Error("http " + r.status);
    const d = await r.json();
    const sit = String(d.descricao_situacao_cadastral || "").toUpperCase();
    const warns = [];
    if (sit && sit !== "ATIVA") warns.push("Situação cadastral: " + sit + ". Evite comprar.");
    if (d.data_inicio_atividade) {
      const days = (Date.now() - new Date(d.data_inicio_atividade).getTime()) / 86400000;
      if (days < 365) warns.push("Empresa aberta há menos de 1 ano. Redobre a cautela.");
    }
    const kv = [
      ["Razão social", d.razao_social], ["Nome fantasia", d.nome_fantasia], ["Situação", d.descricao_situacao_cadastral],
      ["Abertura", d.data_inicio_atividade], ["Atividade principal", d.cnae_fiscal_descricao],
      ["Cidade/UF", [d.municipio, d.uf].filter(Boolean).join(" / ")], ["Capital social", d.capital_social != null ? fmt(Number(d.capital_social)) : ""]
    ];
    out.replaceChildren(
      warns.length ? el("div", { class: "notice warn" }, el("ul", { class: "clean" }, warns.map(w => el("li", { text: w })))) : el("div", { class: "notice ok", text: "Situação ativa e sem alertas automáticos. Ainda confira reputação, nota fiscal e conta de pagamento." }),
      el("table", {}, kv.filter(x => x[1]).map(x => el("tr", {}, el("th", { text: x[0] }), el("td", { text: String(x[1]) }))))
    );
  } catch (_) {
    out.append(el("div", { class: "notice warn", text: "Não consegui consultar os dados agora. Use os links oficiais abaixo." }));
  }
}
$("cnpjGo").addEventListener("click", checkCnpj);
$("cnpjInput").addEventListener("keydown", e => { if (e.key === "Enter") checkCnpj(); });

/* ===================== MENSAGENS ===================== */
const TEMPLATES = [
  ["en_rfq", "[EN] Cotação (RFQ) em inglês — Alibaba/fábrica", v => [
    "Hello " + (v.sup || "Sir/Madam") + ",", "",
    "I am interested in " + (v.prod || "your product") + " and would like to receive a quotation.", "",
    "Quantity: " + (v.qty || "[quantity]") + " pcs" + (v.target ? " | Target price: " + v.target : ""),
    "Destination: Brazil", "",
    "Please let me know:",
    "1. Unit price at different quantities (FOB and CIF Brazil)",
    "2. MOQ and production lead time",
    "3. Sample price and sample lead time",
    "4. Are you a factory or a trading company? Please share your business license",
    "5. Available certifications and warranty",
    "6. Packaging details (carton size, weight, pcs per carton)",
    "7. Payment terms (I prefer Trade Assurance or split payment)", "",
    "Thank you.", (v.me || "[Your name]"), (v.co || "")].join("\n").trim()],
  ["en_sample", "[EN] Pedir amostra em inglês", v => [
    "Hello " + (v.sup || "Sir/Madam") + ",", "",
    "Before placing an order of " + (v.qty || "[quantity]") + " pcs of " + (v.prod || "[product]") + ", I would like to order a paid sample.", "",
    "Please send me: sample price, shipping cost to Brazil, shipping method and delivery time, and a PI (proforma invoice). I will pay through the platform.", "",
    "If the sample is approved, can the sample cost be deducted from the bulk order?", "",
    "Thank you.", (v.me || "[Your name]")].join("\n")],
  ["en_nego", "[EN] Negociar preço em inglês", v => [
    "Hello " + (v.sup || "Sir/Madam") + ",", "",
    "Thank you for your quotation for " + (v.prod || "[product]") + ". We are comparing several suppliers.", "",
    "For " + (v.qty || "[quantity]") + " pcs" + (v.target ? ", our target price is " + v.target : "") + ". Could you improve your price? We plan to place repeat orders if quality and delivery are good.", "",
    "Can you also offer better terms on packaging, freight or payment (30% deposit, 70% before shipment)?", "",
    "Best regards,", (v.me || "[Your name]")].join("\n")],
  ["en_follow", "[EN] Cobrar resposta em inglês", v => [
    "Hello " + (v.sup || "Sir/Madam") + ",", "",
    "I am following up on my inquiry about " + (v.prod || "[product]") + " (" + (v.qty || "[quantity]") + " pcs). Could you please share the quotation and sample details?", "",
    "Thank you,", (v.me || "[Your name]")].join("\n")],
  ["pt_tabela", "[PT] Pedir tabela de atacado (WhatsApp)", v => [
    "Olá" + (v.sup ? ", " + v.sup : "") + "! Tudo bem?", "",
    "Sou " + (v.me || "[seu nome]") + (v.co ? " da " + v.co : "") + " e tenho interesse em " + (v.prod || "seus produtos") + " para revenda.", "",
    "Podem me enviar:",
    "• Tabela de preços de atacado (para CNPJ)",
    "• Pedido mínimo (valor e quantidade)" + (v.qty ? " — pensando em começar com " + v.qty + " un." : ""),
    "• Prazo de entrega e custo de frete para a minha região",
    "• Formas de pagamento",
    "• Emitem nota fiscal? Qual a política de troca e garantia?", "",
    "Obrigado!"].join("\n")],
  ["pt_neg", "[PT] Negociar preço no atacado", v => [
    "Olá" + (v.sup ? ", " + v.sup : "") + "! Obrigado pela tabela de " + (v.prod || "produtos") + ".", "",
    "Estou comparando fornecedores" + (v.target ? " e consigo fechar perto de " + v.target + " por unidade" : "") + " para " + (v.qty || "[quantidade]") + " unidades. Conseguem melhorar o preço ou o frete para fechar o primeiro pedido?", "",
    "Se der certo, a ideia é recomprar todo mês.", "",
    "Aguardo retorno. " + (v.me || "")].join("\n").trim()],
  ["pt_follow", "[PT] Cobrar retorno de cotação", v => [
    "Olá" + (v.sup ? ", " + v.sup : "") + "! Passando para saber se conseguem me enviar a cotação de " + (v.prod || "[produto]") + " (" + (v.qty || "[quantidade]") + " un.).", "",
    "Ainda tenho interesse e posso fechar nos próximos dias. Obrigado! " + (v.me || "")].join("\n").trim()],
  ["pt_agente", "[PT] Pedir orçamento a agente/assessoria de importação", v => [
    "Olá! Sou " + (v.me || "[seu nome]") + (v.co ? " (" + v.co + ")" : "") + " e quero importar " + (v.prod || "[produto]") + " da China para revenda, começando com " + (v.qty || "[quantidade]") + " unidades.", "",
    "Gostaria de saber:",
    "• Quais serviços vocês oferecem (busca de fornecedor, inspeção, consolidação, desembaraço)",
    "• Taxas e comissões (percentual ou valor fixo)",
    "• Custo total estimado até a minha porta, incluindo impostos e despachante",
    "• Prazo médio e riscos principais para esse produto (NCM, Anatel, Inmetro)", "",
    "Obrigado!"].join("\n")]
];
(function () { TEMPLATES.forEach(t => $("m_tpl").append(el("option", { value: t[0], text: t[1] }))); })();
function buildMessage() {
  const v = { sup: $("m_sup").value.trim(), prod: $("m_prod").value.trim(), qty: $("m_qty").value.trim(), target: $("m_target").value.trim(), me: $("m_me").value.trim(), co: $("m_co").value.trim() };
  const t = TEMPLATES.find(x => x[0] === $("m_tpl").value) || TEMPLATES[0];
  const text = t[2](v);
  $("m_out").value = text;
  $("m_wa").href = "https://wa.me/?text=" + encodeURIComponent(text);
}
$("msgForm").addEventListener("input", buildMessage);
$("msgForm").addEventListener("change", buildMessage);
$("m_copy").addEventListener("click", () => copyText($("m_out").value));

/* ===================== GUIA ===================== */
const STEPS = [
  "Escolha 1 ou 2 produtos de alto giro e valide a demanda (vendas de concorrentes, buscas, Comex Stat).",
  "Descubra a NCM do produto e as exigências (Anatel, Inmetro, Anvisa, MAPA) antes de comprar.",
  "Levante 5 a 10 fornecedores em plataformas, polos e agentes. Peça cotação a todos com o mesmo modelo de mensagem.",
  "Compare em reais, já com frete e impostos (aba Cotações e Custo de importação).",
  "Verifique a empresa: licença, conta de pagamento em nome da empresa, reputação e CNPJ (no Brasil).",
  "Peça amostra paga e teste: qualidade, embalagem, funcionamento, marca e prazo.",
  "Negocie: preço por faixa de quantidade, prazo, pagamento em etapas, embalagem e garantia.",
  "Contrate inspeção antes do embarque em pedidos maiores.",
  "Faça o primeiro pedido pequeno. Se girar, aumente aos poucos.",
  "Calcule preço e margem (aba Preço e margem) e acompanhe o resultado real de cada lote."
];
const FLAGS = [
  "Pedem pagamento fora da plataforma (Western Union, gift card, cripto, conta pessoal).",
  "O nome da conta bancária não bate com o da empresa, ou muda no meio da negociação.",
  "Preço muito abaixo do mercado.",
  "Sem licença comercial ou registro verificável.",
  "Respostas evasivas sobre quem realmente fabrica.",
  "Sem Trade Assurance ou pressão para não usá-lo.",
  "Conta nova com avaliações perfeitas demais.",
  "Resistem a vender amostra paga ou exigem 100% antecipado.",
  "Pressa e pressão para pagar o sinal."
];
const MISTAKES = [
  "Descobrir impostos, frete e armazenagem só depois de comprar.",
  "Escolher parceiro sem estrutura para conduzir a operação.",
  "Comprar sem amostra e sem controle de qualidade.",
  "Subestimar o prazo logístico e ficar sem estoque.",
  "Ignorar o câmbio: o dólar pode comer a margem entre o pedido e o pagamento.",
  "Importar sem ligar o produto à demanda real e ao estoque.",
  "Comprar produto que exige homologação (Anatel/Inmetro) sem ter a certificação."
];
const TIPS = [
  "Use o ImportYeti para ver de quais fábricas um concorrente compra: pesquise a marca ou o produto e veja os embarques.",
  "Na 25 de Março, saia com 2 ou 3 contatos por categoria, mesmo que use um por vez.",
  "Para o 1688, use um agente que consolide pedidos e valide o fornecedor. O site é em chinês e voltado ao mercado interno.",
  "Para testar um produto novo, AliExpress ou DHgate em pequena quantidade; para escala, Alibaba e fábricas.",
  "Em eletrônicos de balcão (Santa Efigênia, Brás), teste o equipamento antes de levar.",
  "Peça sempre o custo total por escrito. Relatos de importadores mostram que frete e impostos podem eliminar a margem.",
  "Guarde conversas, contratos e comprovantes. Se algo der errado, isso é sua prova.",
  "Compare fornecedor brasileiro vs. importação direta: o atacado nacional tem preço maior, mas sem prazo, imposto e risco cambial."
];
const GLOSS = [
  ["MOQ", "Quantidade mínima de pedido que o fornecedor aceita."],
  ["FOB", "Free on Board: o preço inclui levar a mercadoria até o navio na origem. Frete internacional e seguro são por sua conta."],
  ["CIF", "Preço inclui mercadoria, frete e seguro até o porto de destino. Impostos e despacho ficam por sua conta."],
  ["EXW", "Ex Works: você retira na fábrica e assume todos os custos e riscos dali em diante."],
  ["DDP", "Entregue com impostos pagos. O vendedor cuida de tudo até a sua porta; confirme o que está incluso."],
  ["Incoterms", "Regras internacionais que dizem quem paga e responde por frete, seguro e riscos em cada etapa."],
  ["NCM", "Código de classificação fiscal do produto. Define alíquotas e exigências de importação."],
  ["II", "Imposto de Importação, cobrado sobre o valor aduaneiro."],
  ["IPI", "Imposto sobre Produtos Industrializados, que varia por NCM."],
  ["ICMS", "Imposto estadual sobre circulação de mercadorias; na importação o cálculo costuma ser “por dentro”."],
  ["PIS/COFINS", "Contribuições federais cobradas também na importação formal."],
  ["Valor aduaneiro", "Base de cálculo dos tributos: mercadoria + frete + seguro."],
  ["Remessa Conforme", "Programa da Receita Federal para compras internacionais pequenas (até US$ 3.000), com regras e alíquotas próprias."],
  ["RADAR", "Habilitação da empresa no Siscomex para fazer importação formal."],
  ["Despachante aduaneiro", "Profissional que cuida da documentação e do desembaraço da importação."],
  ["Trade Assurance", "Proteção de pagamento do Alibaba para pedidos feitos e pagos dentro da plataforma."],
  ["OEM", "Fábrica produz com a sua marca e especificações."],
  ["ODM", "Fábrica oferece um produto próprio já desenhado, que você coloca a sua marca."],
  ["Trading company", "Empresa intermediária que revende produtos de fábricas. Costuma ter preço maior, mas pode ser mais prática."],
  ["LCL / FCL", "LCL: carga compartilhada em contêiner. FCL: contêiner inteiro só para você."],
  ["PI (Proforma Invoice)", "Fatura pró-forma: documento com preço, quantidade e condições antes do pagamento."],
  ["Anatel", "Agência que homologa produtos de telecom e que emitem sinal (Bluetooth, Wi-Fi, celular)."],
  ["Inmetro", "Órgão que exige certificação compulsória de certos produtos."],
  ["Markup", "Quanto você soma ao custo (lucro ÷ custo)."],
  ["Margem", "Parte do preço que sobra de lucro (lucro ÷ preço de venda)."],
  ["Ponta de estoque", "Sobras de coleções ou lotes vendidas mais barato, com pouca variedade de grade."],
  ["Atacarejo", "Loja que vende no atacado e no varejo, geralmente com preço menor em volume."]
];
const SOURCES = [
  ["Imposto de importação e Remessa Conforme — Portaria MF 1.342/2026 (Econet)", "https://blog.econeteditora.com.br/remessa-conforme-o-que-muda-com-a-portaria-mf-1-342-2026/"],
  ["9 sinais de golpe no Alibaba (Epic Sourcing)", "https://www.epicsourcing.co/post/how-to-avoid-alibaba-scams-red-flags-us-importers"],
  ["Erros que reduzem a margem do importador (ABC da Comunicação)", "https://www.abcdacomunicacao.com.br/empresarios-brasileiros-perdem-ate-15-de-margem-ao-importar-errado-da-china-veja-como-evitar-prejuizo/"],
  ["Fornecedores de eletrônicos (Tray)", "https://tray.com.br/escola/fornecedores-de-eletronicos/"],
  ["Fornecedores para revenda (JivoChat)", "https://www.jivochat.com.br/blog/vendas/fornecedores-de-produtos-para-revenda.html"],
  ["Fornecedores da 25 de Março (Tray)", "https://tray.com.br/escola/fornecedores-25-de-marco/"],
  ["Sites da China (Guelcos)", "https://guelcos.com.br/conteudo/empresa-de-importacao/sites-da-china"],
  ["Como usar o ImportYeti para achar fornecedores de concorrentes (My Wife Quit Her Job)", "https://mywifequitherjob.com/?p=73857"]
];
function renderGuide() {
  $("steps").replaceChildren(...STEPS.map(s => el("li", { text: s })));
  $("flags").replaceChildren(...FLAGS.map(s => el("li", { text: s })));
  $("mistakes").replaceChildren(...MISTAKES.map(s => el("li", { text: s })));
  $("tips").replaceChildren(...TIPS.map(s => el("li", { text: s })));
  $("sources").replaceChildren(...SOURCES.map(s => el("li", {}, el("a", { class: "link", href: s[1], target: "_blank", rel: "noopener noreferrer", text: s[0] + " ↗" }))));
  const gc = $("gcheck"); gc.replaceChildren();
  const GC = [
    "Defini o produto e a NCM, e conferi exigências (Anatel/Inmetro/Anvisa)",
    "Comparei pelo menos 3 cotações em reais, com frete e impostos",
    "Verifiquei a empresa (licença ou CNPJ ativo) e a conta de pagamento",
    "Pedi e testei amostra paga",
    "Combinei pagamento protegido ou em etapas (nada de 100% antecipado sem proteção)",
    "Confirmei prazo, embalagem, garantia e política de troca",
    "Calculei preço de venda e margem com taxas e impostos",
    "Guardei conversas, PI/contrato e comprovantes",
    "Fiz o primeiro pedido pequeno para testar o giro"
  ];
  GC.forEach((txt, i) => {
    const cb = el("input", { type: "checkbox" }); cb.checked = !!state.gcheck[i];
    cb.addEventListener("change", () => { if (cb.checked) state.gcheck[i] = true; else delete state.gcheck[i]; save(); });
    gc.append(el("label", { class: "check" }, cb, el("span", { text: txt })));
  });
  renderGloss();
}
function renderGloss() {
  const q = $("glossSearch").value.trim().toLocaleLowerCase("pt-BR");
  const box = $("gloss"); box.replaceChildren();
  const list = GLOSS.filter(g => !q || (g[0] + " " + g[1]).toLocaleLowerCase("pt-BR").includes(q));
  if (!list.length) { box.append(el("p", { class: "muted", text: "Nenhum termo encontrado." })); return; }
  list.forEach(g => { box.append(el("dt", { style: "font-weight:bold;margin-top:8px", text: g[0] }), el("dd", { class: "muted", style: "margin:2px 0 0 0", text: g[1] })); });
}
$("glossSearch").addEventListener("input", renderGloss);
$("gcheckReset").addEventListener("click", () => { state.gcheck = {}; save(); renderGuide(); });

/* ===================== CONTATOS (AGENDA) ===================== */
const CT_TYPES = [["importador", "Importador"], ["fabrica", "Fábrica"], ["agente", "Agente de compras"], ["distribuidor", "Distribuidor / atacadista"], ["frete", "Frete / transportadora"], ["despachante", "Despachante / contador"], ["outro", "Outro"]];
const CT_STATUS = [["novo", "Novo contato"], ["conversa", "Em conversa"], ["cotando", "Cotação em andamento"], ["comprei", "Já comprei"], ["bom", "Bom fornecedor"], ["evitar", "Evitar"]];
const CT_FIELDS = ["name", "company", "type", "place", "phone", "email", "wechat", "site", "products", "moq", "lead", "owner", "status", "next", "rating", "notes"];
let editingContact = null, onlyDue = false;
const ctEl = f => $("ct_" + f);
const ctLabel = (list, k) => { const x = list.find(y => y[0] === k); return x ? x[1] : (k || ""); };
function newId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
function todayStr() {
  const d = new Date(), p = n => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate());
}
function dueState(c) {
  if (!c.next) return "";
  const t = todayStr();
  if (c.next < t) return "overdue";
  if (c.next === t) return "today";
  const diff = (new Date(c.next + "T00:00:00") - new Date(t + "T00:00:00")) / 86400000;
  return diff <= 3 ? "soon" : "later";
}
function fmtDate(s) { return /^\d{4}-\d{2}-\d{2}$/.test(s || "") ? s.split("-").reverse().join("/") : (s || ""); }
function waLink(raw) {
  const s = String(raw || "").trim();
  let d = s.replace(/\D/g, "");
  if (!d) return null;
  if (!s.startsWith("+") && d.length <= 11) d = "55" + d;
  return "https://wa.me/" + d;
}
function mailLink(m) {
  const s = String(m || "").trim();
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s) ? "mailto:" + s : null;
}
function siteLink(s) {
  const v = String(s || "").trim();
  if (!v) return null;
  return safeUrl(/^https?:\/\//i.test(v) ? v : "https://" + v);
}
function ctFill(o) {
  const def = { type: "importador", status: "novo", rating: "0" };
  CT_FIELDS.forEach(f => { ctEl(f).value = (o && o[f] != null && o[f] !== "") ? o[f] : (def[f] || ""); });
}
function ctCancel() {
  editingContact = null; ctFill(null);
  $("ct_save").textContent = "Salvar contato"; $("ct_cancel").hidden = true; $("ct_formTitle").textContent = "Novo contato";
}
function ctSave() {
  const o = {};
  CT_FIELDS.forEach(f => { o[f] = ctEl(f).value.trim(); });
  if (!o.name && !o.company) { toast("Informe o nome do contato ou da empresa."); return; }
  if (editingContact) {
    const i = state.contacts.findIndex(c => c.id === editingContact);
    if (i >= 0) state.contacts[i] = Object.assign({}, state.contacts[i], o);
  } else {
    state.contacts.unshift(Object.assign({ id: newId(), created: todayStr() }, o));
  }
  save(); ctCancel(); renderContacts(); toast("Contato salvo ✓");
}
function ctEdit(id) {
  const c = state.contacts.find(x => x.id === id); if (!c) return;
  editingContact = id; ctFill(c);
  $("ct_save").textContent = "Salvar alterações"; $("ct_cancel").hidden = false; $("ct_formTitle").textContent = "Editando contato";
  $("ct_formTitle").scrollIntoView({ behavior: "smooth", block: "center" });
}
function ctDelete(id) {
  const c = state.contacts.find(x => x.id === id); if (!c) return;
  if (!confirm("Excluir o contato " + (c.name || c.company) + "?")) return;
  state.contacts = state.contacts.filter(x => x.id !== id);
  if (editingContact === id) ctCancel();
  save(); renderContacts();
}
function ctOwners() {
  return [...new Set(state.contacts.map(c => (c.owner || "").trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b, "pt-BR"));
}
function ctRefreshOwners() {
  const owners = ctOwners();
  const dl = $("ct_owners"); dl.replaceChildren(...owners.map(o => el("option", { value: o })));
  const sel = $("ct_fowner"), cur = sel.value;
  sel.replaceChildren(el("option", { value: "all", text: "Todos os responsáveis" }), ...owners.map(o => el("option", { value: o, text: o })));
  sel.value = owners.includes(cur) ? cur : "all";
}
function ctFiltered() {
  const q = $("ct_q").value.trim().toLocaleLowerCase("pt-BR");
  const t = $("ct_ftype").value, o = $("ct_fowner").value, s = $("ct_fstatus").value;
  const list = state.contacts.filter(c => {
    if (t !== "all" && c.type !== t) return false;
    if (o !== "all" && (c.owner || "") !== o) return false;
    if (s !== "all" && c.status !== s) return false;
    if (onlyDue && !["overdue", "today"].includes(dueState(c))) return false;
    if (!q) return true;
    const hay = [c.name, c.company, c.place, c.phone, c.email, c.wechat, c.site, c.products, c.moq, c.owner, c.notes, ctLabel(CT_TYPES, c.type), ctLabel(CT_STATUS, c.status)].join(" ").toLocaleLowerCase("pt-BR");
    return q.split(/\s+/).every(w => hay.includes(w));
  });
  const mode = $("ct_sort").value;
  const nm = c => (c.name || c.company || "");
  if (mode === "az") list.sort((a, b) => nm(a).localeCompare(nm(b), "pt-BR"));
  else if (mode === "new") list.sort((a, b) => (b.created || "").localeCompare(a.created || ""));
  else if (mode === "rating") list.sort((a, b) => (Number(b.rating) || 0) - (Number(a.rating) || 0));
  else list.sort((a, b) => (a.next ? 0 : 1) - (b.next ? 0 : 1) || (a.next || "").localeCompare(b.next || "") || nm(a).localeCompare(nm(b), "pt-BR"));
  return list;
}
function ctCard(c) {
  const due = dueState(c), rating = Number(c.rating) || 0;
  const card = el("article", { class: "card" });
  const tags = el("div", { class: "tags" },
    el("span", { class: "tag", text: ctLabel(CT_TYPES, c.type) }),
    c.status ? el("span", { class: "st" + (c.status === "bom" || c.status === "comprei" ? " st-aprovado" : c.status === "evitar" ? " st-descartado" : c.status === "novo" ? "" : " st-contatado"), text: ctLabel(CT_STATUS, c.status) }) : null,
    c.owner ? el("span", { class: "tag", text: "👤 " + c.owner }) : null,
    c.place ? el("span", { class: "tag", text: c.place }) : null
  );
  const line = (label, val) => val ? el("div", { class: "ctline" }, el("b", { text: label + ": " }), val) : null;
  const meta = el("div", { class: "tags", style: "margin-top:6px" });
  if (c.next) meta.append(el("span", { class: "badge " + due, text: (due === "overdue" ? "⚠ Retorno atrasado: " : due === "today" ? "⏰ Retornar hoje: " : "Retornar em ") + fmtDate(c.next) }));
  if (rating) meta.append(el("span", { class: "stars", "aria-label": rating + " de 5 estrelas", text: stars(rating) }));
  const links = el("div", { class: "links" });
  const wa = waLink(c.phone), ml = mailLink(c.email), site = siteLink(c.site);
  if (wa) links.append(el("a", { class: "link", href: wa, target: "_blank", rel: "noopener noreferrer", text: "WhatsApp ↗" }));
  if (ml) links.append(el("a", { class: "link", href: ml, text: "E-mail ↗" }));
  if (site) links.append(el("a", { class: "link", href: site, target: "_blank", rel: "noopener noreferrer", text: "Site ↗" }));
  links.append(el("button", { type: "button", class: "ghost sm", text: "Copiar", onclick: () => copyText([c.name, c.company, c.phone, c.email, c.wechat ? "WeChat: " + c.wechat : "", c.site].filter(Boolean).join("\n")) }));
  links.append(el("button", { type: "button", class: "ghost sm", text: "Editar", onclick: () => ctEdit(c.id) }));
  links.append(el("button", { type: "button", class: "danger sm", text: "Excluir", onclick: () => ctDelete(c.id) }));
  card.append(
    tags,
    el("h3", { text: c.name || c.company }),
    c.name && c.company ? el("p", { class: "niche", text: c.company }) : null,
    line("Produtos", c.products), line("Pedido mínimo", c.moq), line("Prazo", c.lead),
    line("Telefone", c.phone), line("E-mail", c.email), line("WeChat", c.wechat),
    c.notes ? el("p", { class: "desc", style: "margin-top:8px", text: c.notes }) : null,
    meta, links
  );
  return card;
}
function renderContacts() {
  ctRefreshOwners();
  const list = ctFiltered();
  const box = $("ct_list"); box.replaceChildren();
  if (!state.contacts.length) box.append(el("div", { class: "empty", text: "Nenhum contato ainda. Preencha o formulário acima para adicionar o primeiro." }));
  else if (!list.length) box.append(el("div", { class: "empty", text: "Nenhum contato com esses filtros." }));
  else { const f = document.createDocumentFragment(); list.forEach(c => f.append(ctCard(c))); box.append(f); }
  const overdue = state.contacts.filter(c => dueState(c) === "overdue").length;
  const today = state.contacts.filter(c => dueState(c) === "today").length;
  $("ct_count").textContent = list.length + " de " + state.contacts.length + " contato(s)" + (overdue ? " · " + overdue + " retorno(s) atrasado(s)" : "") + (today ? " · " + today + " para hoje" : "");
  $("ct_dueBtn").classList.toggle("on", onlyDue);
}
function ctCsv() {
  const head = ["Nome", "Empresa", "Tipo", "País/Cidade", "Telefone", "E-mail", "WeChat", "Site", "Produtos", "MOQ", "Prazo", "Responsável", "Status", "Próximo contato", "Nota", "Anotações"];
  const rows = ctFiltered().map(c => [c.name, c.company, ctLabel(CT_TYPES, c.type), c.place, c.phone, c.email, c.wechat, c.site, c.products, c.moq, c.lead, c.owner, ctLabel(CT_STATUS, c.status), fmtDate(c.next), c.rating || "", c.notes]);
  download("contatos-importadores.csv", "\uFEFF" + [head, ...rows].map(r => r.map(csvCell).join(";")).join("\r\n"), "text/csv;charset=utf-8");
}
function ctExport() {
  download("contatos-importadores-" + todayStr() + ".json", JSON.stringify({ kind: "radar-contatos", version: 1, contacts: state.contacts }, null, 2), "application/json");
}
function ctSig(c) {
  const d = String(c.phone || "").replace(/\D/g, "");
  return (d || String(c.email || "").toLowerCase() || (String(c.name || "") + "|" + String(c.company || "")).toLowerCase());
}
function ctImport(text) {
  const parsed = JSON.parse(text);
  const arr = Array.isArray(parsed) ? parsed : (parsed && Array.isArray(parsed.contacts) ? parsed.contacts : null);
  if (!arr) throw new Error("formato");
  const ids = new Set(state.contacts.map(c => c.id)), sigs = new Set(state.contacts.map(ctSig));
  let added = 0, skipped = 0;
  arr.forEach(raw => {
    if (!raw || typeof raw !== "object") return;
    const c = {};
    CT_FIELDS.forEach(f => { c[f] = String(raw[f] == null ? "" : raw[f]).slice(0, 2000); });
    c.id = typeof raw.id === "string" && raw.id ? raw.id.slice(0, 40) : newId();
    c.created = typeof raw.created === "string" ? raw.created.slice(0, 10) : todayStr();
    if (!c.name && !c.company) return;
    if (ids.has(c.id) || sigs.has(ctSig(c))) { skipped++; return; }
    ids.add(c.id); sigs.add(ctSig(c)); state.contacts.push(c); added++;
  });
  save(); renderContacts();
  return { added, skipped };
}
(function ctInit() {
  CT_TYPES.forEach(t => $("ct_type").append(el("option", { value: t[0], text: t[1] })));
  CT_STATUS.forEach(s => $("ct_status").append(el("option", { value: s[0], text: s[1] })));
  $("ct_rating").append(el("option", { value: "0", text: "Sem nota" }));
  for (let i = 1; i <= 5; i++) $("ct_rating").append(el("option", { value: String(i), text: stars(i) }));
  $("ct_ftype").append(el("option", { value: "all", text: "Todos os tipos" }), ...CT_TYPES.map(t => el("option", { value: t[0], text: t[1] })));
  $("ct_fstatus").append(el("option", { value: "all", text: "Todos os status" }), ...CT_STATUS.map(s => el("option", { value: s[0], text: s[1] })));
  ctFill(null);
  $("ct_save").addEventListener("click", ctSave);
  $("ct_cancel").addEventListener("click", ctCancel);
  $("ct_q").addEventListener("input", renderContacts);
  ["ct_ftype", "ct_fowner", "ct_fstatus", "ct_sort"].forEach(id => $(id).addEventListener("change", renderContacts));
  $("ct_dueBtn").addEventListener("click", () => { onlyDue = !onlyDue; renderContacts(); });
  $("ct_csv").addEventListener("click", ctCsv);
  $("ct_exp").addEventListener("click", ctExport);
  $("ct_imp").addEventListener("click", () => $("ct_impFile").click());
  $("ct_impFile").addEventListener("change", () => {
    const f = $("ct_impFile").files && $("ct_impFile").files[0]; if (!f) return;
    const r = new FileReader();
    r.onload = () => {
      try { const res = ctImport(String(r.result)); toast(res.added + " contato(s) importado(s)" + (res.skipped ? ", " + res.skipped + " já existiam" : "") + "."); }
      catch (_) { toast("Arquivo inválido. Use um arquivo exportado por este site."); }
      $("ct_impFile").value = "";
    };
    r.readAsText(f);
  });
})();

/* ===================== MERCADO LIVRE ===================== */
let lastUnitCost = 0;
const ML_IDS = ["ml_cost", "ml_pack", "ml_type", "ml_comm", "ml_fixed", "ml_thr", "ml_ship", "ml_tax", "ml_ads", "ml_margin", "ml_price", "ml_qty"];
function loadML() { ML_IDS.forEach(id => { const v = state.ml[id]; if (typeof v === "string") $(id).value = v; }); }
function mlParams() {
  const g = id => parseNum($(id).value);
  return { cost: g("ml_cost"), pack: g("ml_pack"), comm: g("ml_comm") / 100, fixed: g("ml_fixed"), thr: g("ml_thr"), ship: g("ml_ship"), tax: g("ml_tax") / 100, ads: g("ml_ads") / 100, margin: g("ml_margin") / 100, price: g("ml_price"), qty: g("ml_qty") };
}
function mlFees(P, p) { return { comm: P * p.comm, fixed: P < p.thr ? p.fixed : 0, ship: p.ship, tax: P * p.tax, ads: P * p.ads }; }
function mlProfit(P, p) { const f = mlFees(P, p); return P - f.comm - f.fixed - f.ship - f.tax - f.ads - p.cost - p.pack; }
function mlPriceFor(m, p) {
  const d = 1 - (p.comm + p.tax + p.ads) - m;
  if (d <= 0) return null;
  const base = p.cost + p.pack + p.ship;
  const withFixed = (base + p.fixed) / d;
  if (withFixed < p.thr) return withFixed;
  return Math.max(base / d, p.thr);
}
function renderML() {
  const p = mlParams();
  const kp = $("mlKpis"); kp.replaceChildren();
  const k = (label, val) => kp.append(el("div", { class: "kpi" }, el("span", { text: label }), el("div", { class: "big", text: val })));
  const sug = mlPriceFor(p.margin, p), be = mlPriceFor(0, p);
  if (sug == null) kp.append(el("div", { class: "notice bad", text: "Com essa margem, comissão, imposto e anúncios, a soma passa de 100% do preço. Reduza a margem ou as taxas." }));
  else {
    k("Preço sugerido", fmt(sug));
    k("Lucro por unidade", fmt(mlProfit(sug, p)));
    const f = mlFees(sug, p);
    k("Mercado Livre leva (comissão + fixo + frete)", fmt(f.comm + f.fixed + f.ship));
  }
  k("Preço de equilíbrio (lucro zero)", be == null ? "—" : fmt(be));
  if (p.price > 0) {
    const pr = mlProfit(p.price, p);
    const kk = el("div", { class: "kpi" }, el("span", { text: "Lucro no seu preço" }), el("div", { class: "big " + (pr < 0 ? "neg" : "pos"), text: fmt(pr) }));
    kp.append(kk);
    k("Margem no seu preço", pct(pr / p.price * 100));
    if (p.cost + p.pack > 0) k("Retorno sobre o custo (ROI)", pct(pr / (p.cost + p.pack) * 100));
    if (p.qty > 0) k("Lucro estimado no mês", fmt(pr * p.qty));
  } else if (sug != null && p.qty > 0) k("Lucro no mês (preço sugerido)", fmt(mlProfit(sug, p) * p.qty));
  const P = p.price > 0 ? p.price : sug;
  const bt = $("mlBreak"); bt.replaceChildren();
  if (P != null) {
    const f = mlFees(P, p);
    const row = (label, val, cls) => bt.append(el("tr", { class: cls || "" }, el("td", { text: label }), el("td", { class: "num", text: fmt(val) })));
    row("Preço de venda" + (p.price > 0 ? " (o seu)" : " (sugerido)"), P, "total");
    row("− Comissão (" + pct(p.comm * 100) + ")", -f.comm);
    row("− Custo fixo / operacional" + (P < p.thr ? "" : " (não incide)"), -f.fixed);
    row("− Frete que você paga", -f.ship);
    row("− Imposto (" + pct(p.tax * 100) + ")", -f.tax);
    row("− Anúncios (" + pct(p.ads * 100) + ")", -f.ads);
    row("− Custo do produto", -p.cost);
    row("− Embalagem e outros", -p.pack);
    row("= Lucro por unidade", mlProfit(P, p), "total");
    if (P >= p.thr && p.ship === 0) bt.append(el("tr", {}, el("td", { colspan: "2", class: "small muted", text: "Acima de R$ " + numStr(p.thr, 0) + " o frete grátis costuma ser obrigatório. Informe o frete que você paga para o lucro ficar realista." })));
  }
  const mt = $("mlTable"); mt.replaceChildren();
  mt.append(el("tr", {}, el("th", { text: "Margem" }), el("th", { class: "num", text: "Preço" }), el("th", { class: "num", text: "Lucro/un" })));
  [0, 10, 15, 20, 25, 30, 40].forEach(m => {
    const pr = mlPriceFor(m / 100, p);
    mt.append(el("tr", {}, el("td", { text: m === 0 ? "0% (equilíbrio)" : m + "%" }), el("td", { class: "num", text: pr == null ? "—" : fmt(pr) }), el("td", { class: "num", text: pr == null ? "—" : fmt(mlProfit(pr, p)) })));
  });
}
function bindML() {
  document.querySelector('[data-calc="ml"]').addEventListener("input", e => {
    if (ML_IDS.includes(e.target.id)) { state.ml[e.target.id] = e.target.value; save(); }
    if (e.target.id !== "ml_type") renderML();
  });
  $("ml_type").addEventListener("change", () => {
    const v = $("ml_type").value;
    if (v === "classico") $("ml_comm").value = "12"; else if (v === "premium") $("ml_comm").value = "16";
    state.ml.ml_type = v; state.ml.ml_comm = $("ml_comm").value; save(); renderML();
  });
  $("ml_fromCost").addEventListener("click", () => {
    calcCost();
    if (!(lastUnitCost > 0)) { toast("Calcule primeiro o custo na aba Custo de importação."); return; }
    $("ml_cost").value = numStr(lastUnitCost, 2); state.ml.ml_cost = $("ml_cost").value; save(); renderML();
    toast("Custo por unidade atualizado.");
  });
  $("c_toML").addEventListener("click", () => {
    calcCost();
    if (!(lastUnitCost > 0)) { toast("Preencha preço e quantidade para calcular o custo."); return; }
    $("ml_cost").value = numStr(lastUnitCost, 2); state.ml.ml_cost = $("ml_cost").value; save();
    showTab("ml"); toast("Custo enviado para a aba Mercado Livre.");
  });
}

/* título e descrição */
function buildTitle() {
  const g = id => $(id).value.trim();
  const parts = [g("t_prod"), g("t_brand"), g("t_model"), g("t_f1"), g("t_f2"), g("t_color"), g("t_qty")].filter(Boolean);
  const full = parts.join(" ");
  const fit = parts.slice();
  while (fit.join(" ").length > 60 && fit.length > 1) fit.pop();
  let fitStr = fit.join(" ");
  if (fitStr.length > 60) fitStr = fitStr.slice(0, 60).trim();
  $("t_full").value = full; $("t_fit").value = fitStr;
  const c1 = $("t_cnt1"), c2 = $("t_cnt2");
  c1.textContent = full.length + " / 60 caracteres" + (full.length > 60 ? " — passou do limite" : "");
  c1.className = "counter" + (full.length > 60 ? " over" : "");
  c2.textContent = fitStr.length + " / 60 caracteres";
  c2.className = "counter";
}
function buildDesc() {
  const g = id => $(id).value.trim();
  const lines = id => g(id).split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const out = [];
  const name = [g("t_prod"), g("t_brand"), g("t_model")].filter(Boolean).join(" ");
  if (name) out.push(name.toUpperCase(), "");
  const b = lines("d_bul");
  if (b.length) { out.push("CARACTERÍSTICAS"); b.forEach(x => out.push("• " + x)); out.push(""); }
  const bx = lines("d_box");
  if (bx.length) { out.push("O QUE VEM NA CAIXA"); bx.forEach(x => out.push("• " + x)); out.push(""); }
  if (g("d_war")) out.push("GARANTIA E ENVIO", g("d_war"), "");
  out.push("Enviamos com nota fiscal. Tem dúvida? Pergunte antes de comprar que respondemos rápido.");
  $("d_out").value = out.join("\n");
}
function slugML(s) { return s.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""); }
function buildResearch() {
  const q = $("r_q").value.trim(), box = $("r_links"); box.replaceChildren();
  if (!q) { box.append(el("span", { class: "muted small", text: "Digite um produto para gerar os links de pesquisa." })); return; }
  const e = encodeURIComponent(q), slug = slugML(q);
  const L = [
    ["Mercado Livre: concorrentes", slug ? "https://lista.mercadolivre.com.br/" + slug : null],
    ["Tendências do Mercado Livre", "https://tendencias.mercadolivre.com.br/"],
    ["Google Trends (Brasil)", "https://trends.google.com.br/trends/explore?geo=BR&q=" + e],
    ["Shopee", "https://shopee.com.br/search?keyword=" + e],
    ["Amazon Brasil", "https://www.amazon.com.br/s?k=" + e],
    ["AliExpress", "https://www.aliexpress.com/wholesale?SearchText=" + e],
    ["Alibaba", "https://www.alibaba.com/trade/search?SearchText=" + e],
    ["Google: fornecedor no atacado", "https://www.google.com/search?q=" + encodeURIComponent(q + " atacado fornecedor")]
  ];
  L.forEach(x => { if (x[1]) box.append(el("a", { class: "link", href: x[1], target: "_blank", rel: "noopener noreferrer", text: x[0] + " ↗" })); });
}
const ML_CHECK = [
  "Tenho CNPJ ou MEI e emito nota fiscal das vendas",
  "Pesquisei os concorrentes: preço, reputação, quantidade vendida e se já existe catálogo",
  "Calculei o preço com comissão, custo fixo ou operacional, frete e imposto",
  "O produto não usa marca de terceiros sem autorização (pode derrubar o anúncio)",
  "Se emite sinal (Bluetooth, Wi-Fi, celular), tenho a homologação da Anatel",
  "Conferi se o produto exige Inmetro, Anvisa ou outra certificação",
  "Título claro com produto, marca, modelo e principais características",
  "Fotos nítidas: fundo branco na principal, vários ângulos e o produto em uso",
  "Ficha técnica completa (ajuda na busca e no catálogo)",
  "Medi e pesei a embalagem (peso e dimensões erradas encarecem o frete)",
  "Estoque real cadastrado e prazo de postagem que consigo cumprir",
  "Vou responder perguntas e mensagens rápido para proteger a reputação",
  "Testei kits ou combos para subir o ticket e diluir o frete"
];
const ML_TIPS = [
  "Se o seu preço fica pouco abaixo de R$ 79, veja se compensa um kit que passe desse valor: o custo fixo deixa de incidir, mas o frete grátis passa a pesar. Simule os dois casos acima.",
  "Reputação verde é o que mais pesa. Um produto bom com atraso na postagem perde mais do que ganha.",
  "Não copie fotos nem descrições de outros vendedores: o Mercado Livre derruba anúncios por isso.",
  "Eletrônicos sem Anatel e produtos com marca falsificada são os principais motivos de anúncio removido.",
  "Compre um lote pequeno para testar. Só reponha o que girar nas primeiras semanas.",
  "Calcule o preço com o custo nacionalizado (com frete e imposto), não com o preço da fábrica.",
  "Fique de olho no câmbio: se o dólar sobe, o custo do próximo lote sobe junto, e o preço no anúncio precisa acompanhar.",
  "Product Ads ajudam a ganhar tráfego no início, mas entram no cálculo: coloque o percentual no campo de anúncios.",
  "Use a pesquisa do produto acima antes de comprar o lote e veja quantos vendedores iguais já existem."
];
function renderMlStatic() {
  const gc = $("mlCheck"); gc.replaceChildren();
  ML_CHECK.forEach((txt, i) => {
    const cb = el("input", { type: "checkbox" }); cb.checked = !!state.mlcheck[i];
    cb.addEventListener("change", () => { if (cb.checked) state.mlcheck[i] = true; else delete state.mlcheck[i]; save(); });
    gc.append(el("label", { class: "check" }, cb, el("span", { text: txt })));
  });
  $("mlTips").replaceChildren(...ML_TIPS.map(s => el("li", { text: s })));
}
(function mlInit() {
  bindML();
  $("titleForm").addEventListener("input", () => { buildTitle(); buildDesc(); });
  ["d_bul", "d_box", "d_war"].forEach(id => $(id).addEventListener("input", buildDesc));
  $("t_copy").addEventListener("click", () => copyText($("t_fit").value));
  $("d_copy").addEventListener("click", () => copyText($("d_out").value));
  $("r_q").addEventListener("input", buildResearch);
  $("mlCheckReset").addEventListener("click", () => { state.mlcheck = {}; save(); renderMlStatic(); });
})();

/* ===================== MEUS PRODUTOS ===================== */
function prAdd() {
  const name = $("pr_name").value.trim(), price = parseNum($("pr_price").value);
  if (!name || !(price > 0)) { toast("Informe o nome e o preço no Mercado Livre."); return; }
  state.products.unshift({ id: newId(), name, supplier: $("pr_sup").value.trim(), cost: parseNum($("pr_cost").value), price, stock: parseNum($("pr_stock").value), sales: parseNum($("pr_sales").value) });
  save();
  ["pr_name", "pr_sup", "pr_cost", "pr_price", "pr_stock", "pr_sales"].forEach(id => { $(id).value = ""; });
  renderProducts(); toast("Produto adicionado.");
}
function renderProducts() {
  const p = mlParams();
  const t = $("prTable"); t.replaceChildren();
  const kp = $("prKpis"); kp.replaceChildren();
  const k = (label, val) => kp.append(el("div", { class: "kpi" }, el("span", { text: label }), el("div", { class: "big", text: val })));
  if (!state.products.length) { t.append(el("tr", {}, el("td", { class: "muted", text: "Nenhum produto cadastrado ainda." }))); k("Produtos", "0"); return; }
  let capital = 0, monthly = 0, low = 0;
  t.append(el("tr", {}, ["Produto", "Fornecedor", "Custo", "Preço ML", "Lucro/un", "Margem", "Estoque", "Vendas/mês", "Lucro/mês", ""].map((h, i) => el("th", { class: i >= 2 && i <= 8 ? "num" : "", text: h }))));
  state.products.forEach(pr => {
    const q = Object.assign({}, p, { cost: Number(pr.cost) || 0 });
    const profit = mlProfit(pr.price, q), margin = pr.price > 0 ? profit / pr.price * 100 : 0;
    capital += (Number(pr.cost) || 0) * (Number(pr.stock) || 0);
    monthly += profit * (Number(pr.sales) || 0);
    if (margin < 10) low++;
    t.append(el("tr", {},
      el("td", { text: pr.name }), el("td", { text: pr.supplier || "—" }),
      el("td", { class: "num", text: fmt(Number(pr.cost) || 0) }), el("td", { class: "num", text: fmt(pr.price) }),
      el("td", { class: "num " + (profit < 0 ? "neg" : ""), text: fmt(profit) }),
      el("td", { class: "num " + (margin < 10 ? "neg" : "pos"), text: pct(margin) }),
      el("td", { class: "num", text: String(pr.stock || 0) }), el("td", { class: "num", text: String(pr.sales || 0) }),
      el("td", { class: "num", text: fmt(profit * (Number(pr.sales) || 0)) }),
      el("td", {},
        el("button", { type: "button", class: "ghost sm", text: "Simular", onclick: () => { $("ml_cost").value = numStr(Number(pr.cost) || 0, 2); $("ml_price").value = numStr(pr.price, 2); state.ml.ml_cost = $("ml_cost").value; state.ml.ml_price = $("ml_price").value; save(); showTab("ml"); } }),
        " ",
        el("button", { type: "button", class: "danger sm", text: "Excluir", onclick: () => { if (confirm("Excluir " + pr.name + "?")) { state.products = state.products.filter(x => x.id !== pr.id); save(); renderProducts(); } } })
      )));
  });
  k("Produtos", String(state.products.length));
  k("Dinheiro parado em estoque", fmt(capital));
  k("Lucro estimado no mês", fmt(monthly));
  k("Com margem abaixo de 10%", String(low));
}
$("pr_add").addEventListener("click", prAdd);

/* ===================== MEUS DADOS ===================== */
function renderData() {
  const kp = $("dataKpis"); kp.replaceChildren();
  const k = (label, val) => kp.append(el("div", { class: "kpi" }, el("span", { text: label }), el("div", { class: "big", text: String(val) })));
  k("Favoritos", Object.keys(state.fav).length);
  k("Com status definido", Object.keys(state.status).filter(id => state.status[id] !== "novo").length);
  k("Com anotações", Object.keys(state.notes).length);
  k("Cotações salvas", state.quotes.length);
  k("Aprovados", Object.keys(state.status).filter(id => state.status[id] === "aprovado").length);
  k("Contatos na agenda", state.contacts.length);
  k("Meus produtos", state.products.length);
}
$("expJson").addEventListener("click", () => {
  download("radar-fornecedores-backup-" + new Date().toISOString().slice(0, 10) + ".json", JSON.stringify(state, null, 2), "application/json");
});
$("impBtn").addEventListener("click", () => $("impFile").click());
$("impFile").addEventListener("change", () => {
  const f = $("impFile").files && $("impFile").files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    try {
      const parsed = JSON.parse(String(r.result));
      if (!mergeState(parsed)) throw new Error("formato");
      save(); syncFxInputs(); applyTheme(); loadML(); renderMlStatic(); render(); renderData(); renderQuotes(); renderContacts(); renderProducts();
      toast("Backup restaurado ✓");
    } catch (_) { toast("Arquivo inválido. Use um backup baixado deste site."); }
    $("impFile").value = "";
  };
  r.readAsText(f);
});
$("resetAll").addEventListener("click", () => {
  if (!confirm("Apagar favoritos, status, notas, cotações e checklist deste navegador? Isso não pode ser desfeito.")) return;
  state = defaults(); save(); syncFxInputs(); applyTheme(); loadML(); renderMlStatic(); render(); renderData(); renderQuotes(); renderGuide(); renderContacts(); renderProducts();
  toast("Dados apagados.");
});

/* ===================== TEMA / GERAL ===================== */
function applyTheme() {
  const t = state.settings.theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t);
  const m = document.querySelector('meta[name="theme-color"]'); if (m) m.setAttribute("content", t === "light" ? "#f4f6fb" : "#101827");
}
$("themeBtn").addEventListener("click", () => {
  state.settings.theme = state.settings.theme === "light" ? "dark" : "light"; save(); applyTheme();
});
$("printBtn").addEventListener("click", () => window.print());
window.addEventListener("pageshow", () => { render(); });
document.addEventListener("keydown", e => {
  if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "")) {
    e.preventDefault(); showTab("suppliers"); searchInput.focus();
  }
});

document.querySelector('[data-calc="cost"]').addEventListener("input", e => { if (e.target.id !== "c_mode") calcCost(); });
$("c_mode").addEventListener("change", () => { applyPreset(); calcCost(); });
document.querySelector('[data-calc="price"]').addEventListener("input", calcPrice);

/* ===================== PAINEL, GERENCIAR, ADMIN ===================== */
(function proModule() {
  document.head.append(el("style", { text:
    "nav.tabs{scrollbar-width:thin}" +
    "@media(max-width:700px){nav.tabs{flex-wrap:nowrap;overflow-x:auto;padding-bottom:6px}nav.tabs button{white-space:nowrap;flex:none}}" +
    ".card{transition:transform .15s,border-color .15s}.card:hover{transform:translateY(-2px);border-color:var(--accent)}" +
    ".kpi .big,td.num{font-variant-numeric:tabular-nums}" +
    ".pbar{height:8px;background:var(--panel2);border-radius:99px;overflow:hidden;border:1px solid var(--line);margin:4px 0 10px}" +
    ".pbar>i{display:block;height:100%;background:var(--accent)}" +
    ".pro-row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px}" +
    ".pro-row label{display:flex;flex-direction:column;font-size:13px;gap:4px;color:var(--muted)}" +
    ".pro-row input,.pro-row select{width:auto;min-width:130px}" +
    ".pro-sec h3{margin:20px 0 8px}.pro-list{list-style:none;margin:0;padding:0}" +
    ".pro-list li{display:flex;gap:10px;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--line)}" +
    ".userchip{font-size:13px;color:var(--muted);align-self:center;margin-right:6px}" +
    "#toTop{position:fixed;right:16px;bottom:16px;min-height:40px;width:40px;padding:0;border-radius:50%;z-index:30}" +
    ".msgbox{white-space:pre-wrap;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px;font-size:14px;margin:8px 0}" }));
  (function cleanup() {
    const pb = $("printBtn"); if (pb) pb.remove();
    const top = el("button", { id: "toTop", type: "button", "aria-label": "Voltar ao topo", text: "↑", hidden: true, onclick: () => window.scrollTo({ top: 0, behavior: "smooth" }) });
    document.body.append(top);
    window.addEventListener("scroll", () => { top.hidden = window.scrollY < 600; }, { passive: true });
    const ft = document.querySelector("footer .container");
    if (ft) ft.append(el("div", { class: "small", style: "margin-top:6px", text: "Atalho: tecle / para buscar fornecedores." }));
  })();

  let me = null;

  const CKEY = "radar-custom-v1";
  const BUILTIN = items.slice();
  let custom = { list: [], hidden: {}, next: 1 };
  try {
    const raw = JSON.parse(localStorage.getItem(CKEY) || "null");
    if (raw && typeof raw === "object") {
      custom.list = Array.isArray(raw.list) ? raw.list.filter(x => x && Array.isArray(x.row) && x.row.length >= 7 && x.id).slice(0, 3000) : [];
      custom.hidden = (raw.hidden && typeof raw.hidden === "object" && !Array.isArray(raw.hidden)) ? raw.hidden : {};
      custom.next = Number(raw.next) > 0 ? Number(raw.next) : custom.list.length + 1;
    }
  } catch (_) {}
  function saveCustom() { try { localStorage.setItem(CKEY, JSON.stringify(custom)); } catch (_) {} }
  function mkItem(id, r) {
    const hay = r[3] + " " + r[4];
    return { id, name: r[0], region: r[1], kind: r[2], niche: r[3], desc: r[4], url: r[5], city: r[6], niches: NICHES.filter(n => n[2].test(hay)).map(n => n[0]), mine: String(id).startsWith("c") };
  }
  function rebuild(noRender) {
    const house = items.filter(i => String(i.id).startsWith("h"));
    items.length = 0;
    BUILTIN.forEach(i => { if (!custom.hidden[i.id]) items.push(i); });
    custom.list.forEach(x => items.push(mkItem("c" + x.id, x.row)));
    house.forEach(i => items.push(i));
    if (!noRender) render();
  }
  function cleanRow(o) {
    const s = (v, n) => String(v == null ? "" : v).trim().slice(0, n);
    const name = s(o.name, 80); if (!name) return null;
    let url = s(o.url, 300);
    if (url) { const u = safeUrl(/^https?:\/\//i.test(url) ? url : "https://" + url); url = u || ""; }
    return [name, o.region === "brasil" ? "brasil" : "china", KIND_NAMES[o.kind] ? o.kind : "wholesale", s(o.niche, 120), s(o.desc, 400), url, s(o.city, 80)];
  }
  function addCustom(rows) {
    let n = 0;
    rows.forEach(r => { if (r && custom.list.length < 3000) { custom.list.push({ id: custom.next++, row: r }); n++; } });
    saveCustom(); rebuild(); return n;
  }
  rebuild(true);

  function addTab(id, label, position, onOpen) {
    const sec = el("section", { id: "tab-" + id, role: "tabpanel", hidden: true });
    if (position === "first") $("tab-suppliers").before(sec); else if (position === "end") $("tab-data").after(sec);
    else $("tab-suppliers").after(sec);
    const btn = el("button", { type: "button", role: "tab", "data-tab": id, "aria-selected": "false", text: label, onclick: () => { showTab(id); onOpen(); } });
    const nav = $("tabs");
    if (position === "first") { TABS.unshift([id, label]); nav.prepend(btn); }
    else if (position === "end") { TABS.push([id, label]); nav.append(btn); }
    else { TABS.splice(2, 0, [id, label]); nav.children[1].after(btn); }
    return sec;
  }

  const painel = addTab("painel", "🏠 Painel", "first", () => renderPainel());
  function go(id, fn) { showTab(id); if (fn) fn(); }
  function renderPainel() {
    painel.replaceChildren();
    const h = new Date().getHours();
    const hi = h < 12 ? "Bom dia" : h < 18 ? "Boa tarde" : "Boa noite";
    painel.append(el("h2", { text: hi + (me ? ", " + me.user : "") + "!" }));
    if (me && !me.admin && me.expiresAt) {
      const d = Math.ceil((me.expiresAt - Date.now()) / 86400000);
      if (d <= 7) painel.append(el("div", { class: "notice warn", text: "Seu acesso vence em " + Math.max(d, 0) + " dia(s). Fale com o suporte para renovar." }));
    }
    const due = state.contacts.filter(c => ["overdue", "today"].includes(dueState(c)));
    const overdue = state.contacts.filter(c => dueState(c) === "overdue").length;
    const p = mlParams();
    const lowMargin = state.products.filter(pr => pr.price > 0 && mlProfit(pr.price, Object.assign({}, p, { cost: Number(pr.cost) || 0 })) / pr.price * 100 < 10);
    const kp = el("div", { class: "kpis" });
    const k = (label, val, cls) => kp.append(el("div", { class: "kpi" }, el("span", { text: label }), el("div", { class: "big " + (cls || ""), text: String(val) })));
    k("Fornecedores na lista", items.length);
    k("Favoritos", Object.keys(state.fav).length);
    k("Aprovados", Object.keys(state.status).filter(id => state.status[id] === "aprovado").length, "pos");
    k("Contatos na agenda", state.contacts.length);
    k("Retornos hoje", due.length - overdue);
    k("Retornos atrasados", overdue, overdue ? "neg" : "");
    k("Meus produtos", state.products.length);
    k("Produtos com margem < 10%", lowMargin.length, lowMargin.length ? "neg" : "");
    painel.append(kp);
    const steps = [];
    if (overdue) steps.push(["Você tem " + overdue + " retorno(s) atrasado(s) na agenda.", "Abrir contatos", () => go("contacts", () => { onlyDue = true; renderContacts(); })]);
    if (!state.contacts.length) steps.push(["Cadastre seus primeiros contatos de importadores.", "Ir para contatos", () => go("contacts", renderContacts)]);
    if (lowMargin.length) steps.push(["Há produto com margem abaixo de 10%. Revise preço ou custo.", "Ver produtos", () => go("products", renderProducts)]);
    if (!state.quotes.length) steps.push(["Registre cotações para comparar fornecedores em reais.", "Abrir cotações", () => go("quotes", renderQuotes)]);
    if (!Object.keys(state.fav).length) steps.push(["Marque com ★ os fornecedores que quer acompanhar.", "Ver fornecedores", () => go("suppliers")]);
    if (!state.products.length) steps.push(["Cadastre o primeiro produto para acompanhar lucro e estoque.", "Meus produtos", () => go("products", renderProducts)]);
    const sp = el("div", { class: "panel" }, el("h3", { style: "margin-top:0", text: "Próximos passos" }));
    if (!steps.length) sp.append(el("p", { class: "muted", text: "Tudo em dia. Continue pesquisando fornecedores e acompanhando seus produtos." }));
    else { const ul = el("ul", { class: "pro-list" }); steps.slice(0, 4).forEach(s => ul.append(el("li", {}, el("span", { text: s[0] }), el("button", { type: "button", class: "ghost sm", text: s[1], onclick: s[2] })))); sp.append(ul); }
    painel.append(sp);
    if (due.length) {
      const dp = el("div", { class: "panel" }, el("h3", { style: "margin-top:0", text: "Retornos de hoje e atrasados" }));
      const ul = el("ul", { class: "pro-list" });
      due.slice(0, 6).forEach(c => ul.append(el("li", {}, el("span", { text: (c.name || c.company) + " · " + fmtDate(c.next) }), el("button", { type: "button", class: "ghost sm", text: "Abrir", onclick: () => go("contacts", () => { $("ct_q").value = c.name || c.company; renderContacts(); }) }))));
      dp.append(ul); painel.append(dp);
    }
    const gDone = Object.keys(state.gcheck).length, mDone = Object.keys(state.mlcheck).length;
    const bar = (label, done, total) => [el("div", { class: "small muted", text: label + ": " + done + " de " + total }), el("div", { class: "pbar" }, el("i", { style: "width:" + Math.round(done / total * 100) + "%" }))];
    painel.append(el("div", { class: "panel" }, el("h3", { style: "margin-top:0", text: "Seu progresso" }),
      ...bar("Checklist de importação segura", Math.min(gDone, 9), 9), ...bar("Checklist para vender no Mercado Livre", Math.min(mDone, ML_CHECK.length), ML_CHECK.length)));
    const sc = el("div", { class: "panel" }, el("h3", { style: "margin-top:0", text: "Atalhos" }), el("div", { class: "row" }));
    [["🏭 Buscar fornecedores", "suppliers"], ["🧮 Custo de importação", "cost"], ["🛒 Preço no Mercado Livre", "ml"], ["🔎 Verificar CNPJ", "cnpj"], ["✉️ Mensagens prontas", "messages"], ["📘 Guia", "guide"]]
      .forEach(a => sc.lastChild.append(el("button", { type: "button", class: "ghost", text: a[0], onclick: () => go(a[1], () => { if (a[1] === "cost") calcCost(); if (a[1] === "ml") { renderML(); buildTitle(); buildDesc(); buildResearch(); } if (a[1] === "messages") buildMessage(); }) })));
    painel.append(sc);
    if (me) {
      const op = el("input", { type: "password", placeholder: "senha atual", autocomplete: "current-password" });
      const np = el("input", { type: "password", placeholder: "nova senha (mín. 6)", autocomplete: "new-password" });
      const msg = el("div", { class: "small", role: "status" });
      painel.append(el("div", { class: "panel" }, el("h3", { style: "margin-top:0", text: "Minha conta" }),
        el("p", { class: "small muted", text: "Usuário: " + me.user + " · Validade: " + (me.expiresAt ? new Date(me.expiresAt).toLocaleDateString("pt-BR") : "sem validade") + ". Cada conta funciona em um IP por vez." }),
        el("div", { class: "pro-row" }, op, np, el("button", { type: "button", class: "ghost", text: "Alterar senha", onclick: async () => {
          try { await api("POST", "/api/password", { old: op.value, pw: np.value }); op.value = ""; np.value = ""; msg.textContent = "Senha alterada ✓"; msg.style.color = "var(--ok)"; }
          catch (e) { msg.textContent = e.message; msg.style.color = "var(--bad)"; }
        } })), msg));
    }
  }

  const ger = addTab("gerenciar", "🗂 Gerenciar", "second", () => renderGer());
  const gq = { text: "", view: "all" };
  function renderGer() {
    ger.replaceChildren();
    ger.append(el("h2", { text: "Gerenciar fornecedores" }),
      el("div", { class: "notice small", text: "Adicione seus próprios fornecedores e remova da sua lista os que não interessam. Fica salvo neste navegador. Os removidos podem ser restaurados." }));
    const f = {
      name: el("input", { placeholder: "Nome do fornecedor", maxlength: "80" }),
      region: el("select", {}, el("option", { value: "china", text: "China / internacional" }), el("option", { value: "brasil", text: "Brasil" })),
      kind: el("select", {}, Object.keys(KIND_NAMES).map(k => el("option", { value: k, text: KIND_NAMES[k] }))),
      niche: el("input", { placeholder: "Nicho (ex.: eletrônicos)", maxlength: "120" }),
      desc: el("input", { placeholder: "Descrição curta", maxlength: "400", style: "min-width:240px" }),
      url: el("input", { placeholder: "site (opcional)", maxlength: "300" }),
      city: el("input", { placeholder: "Cidade / observação", maxlength: "80" })
    };
    f.kind.value = "wholesale";
    ger.append(el("div", { class: "panel" }, el("h3", { style: "margin-top:0", text: "Adicionar fornecedor" }),
      el("div", { class: "pro-row" },
        el("label", {}, "Nome", f.name), el("label", {}, "Região", f.region), el("label", {}, "Tipo", f.kind), el("label", {}, "Nicho", f.niche),
        el("label", {}, "Descrição", f.desc), el("label", {}, "Site", f.url), el("label", {}, "Local", f.city),
        el("button", { type: "button", text: "Adicionar", onclick: () => {
          const row = cleanRow({ name: f.name.value, region: f.region.value, kind: f.kind.value, niche: f.niche.value, desc: f.desc.value, url: f.url.value, city: f.city.value });
          if (!row) { toast("Informe pelo menos o nome."); return; }
          if (f.url.value.trim() && !row[5]) { toast("O endereço do site não parece válido."); return; }
          addCustom([row]); toast("Fornecedor adicionado ✓"); renderGer();
        } }))));
    const ta = el("textarea", { placeholder: "Um por linha:\nNome | site | nicho | china ou brasil | cidade", rows: "5" });
    ger.append(el("div", { class: "panel" }, el("h3", { style: "margin-top:0", text: "Adicionar vários de uma vez" }), ta,
      el("div", { class: "row", style: "margin-top:8px" }, el("button", { type: "button", class: "ghost", text: "Adicionar lista", onclick: () => {
        const rows = ta.value.split(/\r?\n/).slice(0, 300).map(l => l.trim()).filter(Boolean).map(l => {
          const p = l.split("|").map(x => x.trim());
          const reg = /bra/i.test(p[3] || "") ? "brasil" : "china";
          return cleanRow({ name: p[0], url: p[1], niche: p[2], region: reg, city: p[4] });
        }).filter(Boolean);
        if (!rows.length) { toast("Nenhuma linha válida."); return; }
        const n = addCustom(rows); ta.value = ""; toast(n + " fornecedor(es) adicionado(s) ✓"); renderGer();
      } }))));
    const hiddenCount = BUILTIN.filter(i => custom.hidden[i.id]).length;
    const q = el("input", { type: "search", placeholder: "Buscar na lista...", value: gq.text, "aria-label": "Buscar fornecedor para gerenciar" });
    const v = el("select", { "aria-label": "Mostrar" }, el("option", { value: "all", text: "Todos" }), el("option", { value: "mine", text: "Somente os meus" }), el("option", { value: "std", text: "Somente os padrão" }), el("option", { value: "hidden", text: "Removidos (" + hiddenCount + ")" }));
    v.value = gq.view;
    const box = el("div", { class: "tablewrap" });
    const draw = () => {
      gq.text = q.value; gq.view = v.value;
      const term = q.value.trim().toLocaleLowerCase("pt-BR");
      let rows = [];
      if (v.value !== "mine" && v.value !== "hidden") BUILTIN.forEach(i => { if (!custom.hidden[i.id]) rows.push({ i, std: true }); });
      if (v.value === "all" || v.value === "mine") custom.list.forEach(x => rows.push({ i: mkItem("c" + x.id, x.row), cid: x.id }));
      if (v.value === "hidden") BUILTIN.forEach(i => { if (custom.hidden[i.id]) rows.push({ i, std: true, hid: true }); });
      if (v.value === "mine") rows = rows.filter(r => r.cid);
      if (v.value === "std") rows = rows.filter(r => r.std);
      if (term) rows = rows.filter(r => (r.i.name + " " + r.i.niche).toLocaleLowerCase("pt-BR").includes(term));
      const t = el("table", {}, el("thead", {}, el("tr", {}, ["Nome", "Origem", "Região", "Nicho", ""].map(h => el("th", { text: h })))));
      const tb = el("tbody");
      rows.slice(0, 200).forEach(r => tb.append(el("tr", {},
        el("td", { text: r.i.name }), el("td", { text: r.cid ? "Meu" : "Padrão" }), el("td", { text: REGION_NAMES[r.i.region] || r.i.region }), el("td", { text: r.i.niche }),
        el("td", {}, r.hid
          ? el("button", { type: "button", class: "ghost sm", text: "Restaurar", onclick: () => { delete custom.hidden[r.i.id]; saveCustom(); rebuild(); renderGer(); } })
          : el("button", { type: "button", class: "danger sm", text: "Remover", onclick: () => {
              if (r.cid) { if (!confirm("Excluir " + r.i.name + "?")) return; custom.list = custom.list.filter(x => x.id !== r.cid); }
              else custom.hidden[r.i.id] = true;
              saveCustom(); rebuild(); renderGer();
            } })))));
      t.append(tb); box.replaceChildren(t);
      box.append(el("p", { class: "small muted", text: rows.length ? (rows.length > 200 ? "Mostrando 200 de " + rows.length + ". Use a busca para filtrar." : rows.length + " item(ns).") : "Nada para mostrar." }));
    };
    q.addEventListener("input", draw); v.addEventListener("change", draw);
    const impFile = el("input", { type: "file", accept: "application/json,.json", hidden: true });
    impFile.addEventListener("change", () => {
      const file = impFile.files && impFile.files[0]; if (!file) return;
      const r = new FileReader();
      r.onload = () => {
        try {
          const arr = JSON.parse(String(r.result));
          const list = Array.isArray(arr) ? arr : (arr && Array.isArray(arr.suppliers) ? arr.suppliers : null);
          if (!list) throw new Error("formato");
          const n = addCustom(list.map(x => Array.isArray(x) ? cleanRow({ name: x[0], region: x[1], kind: x[2], niche: x[3], desc: x[4], url: x[5], city: x[6] }) : cleanRow(x || {})).filter(Boolean));
          toast(n + " fornecedor(es) importado(s) ✓"); renderGer();
        } catch (_) { toast("Arquivo inválido. Use um arquivo baixado aqui."); }
      };
      r.readAsText(file);
    });
    ger.append(el("div", { class: "panel" }, el("h3", { style: "margin-top:0", text: "Sua lista" }),
      el("div", { class: "pro-row" }, q, v,
        el("button", { type: "button", class: "ghost", text: "Restaurar todos os removidos", onclick: () => { custom.hidden = {}; saveCustom(); rebuild(); renderGer(); toast("Restaurados ✓"); } }),
        el("button", { type: "button", class: "ghost", text: "⬇ Baixar meus fornecedores", onclick: () => download("meus-fornecedores-" + todayStr() + ".json", JSON.stringify({ kind: "radar-fornecedores", suppliers: custom.list.map(x => x.row) }, null, 2), "application/json") }),
        el("button", { type: "button", class: "ghost", text: "⬆ Importar", onclick: () => impFile.click() }), impFile),
      box));
    draw();
  }

  async function api(method, url, body) {
    const opt = { method, headers: {}, credentials: "same-origin" };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    const r = await fetch(url, opt);
    let j = {}; try { j = await r.json(); } catch (_) {}
    if (r.status === 401 && !/\/api\/login/.test(url)) { location.replace("/"); throw new Error("sessão"); }
    if (!r.ok) throw new Error(j.error || "Erro " + r.status);
    return j;
  }
  const fmtD = t => t ? new Date(t).toLocaleDateString("pt-BR") : "sem validade";
  const fmtDT = t => t ? new Date(t).toLocaleString("pt-BR") : "nunca";

  function addHouseSuppliers(list) {
    for (let i = items.length - 1; i >= 0; i--) if (String(items[i].id).startsWith("h")) items.splice(i, 1);
    list.forEach(x => {
      const r = x.row; if (!Array.isArray(r)) return;
      const it = mkItem("h" + x.id, r); it.city = r[6] || "Indicação da casa"; items.push(it);
    });
    render();
  }
  async function loadHouse() { try { addHouseSuppliers(await api("GET", "/api/suppliers")); } catch (_) {} }

  const admin = { box: null, msg: null, q: "", welcome: null };
  function note(text, bad) { if (admin.msg) { admin.msg.textContent = text; admin.msg.style.color = bad ? "var(--bad)" : "var(--ok)"; } }
  async function act(fn, okMsg) {
    try { await fn(); await renderAdmin(); note(okMsg || "Feito ✓"); } catch (e) { note(e.message, true); }
  }
  function welcomeMsg(user, pass, exp) {
    return ["Olá! Seu acesso ao Radar de Fornecedores está liberado.", "", "Link: " + location.origin + "/", "Usuário: " + user, "Senha: " + pass, "Validade: " + fmtD(exp), "",
      "Regras: cada login funciona em um IP por vez, então não compartilhe. Se trocar de rede, aguarde 30 minutos sem uso ou fale comigo para liberar. Depois de entrar, você pode trocar a senha no Painel."].join("\n");
  }
  async function renderAdmin() {
    if (!admin.box) return;
    const users = await api("GET", "/api/admin/users").catch(e => { note(e.message, true); return []; });
    const sup = await api("GET", "/api/suppliers").catch(() => []);
    addHouseSuppliers(sup);
    admin.box.replaceChildren();
    admin.msg = el("div", { class: "small", role: "status" });
    const now = Date.now();
    const clients = users.filter(u => !u.admin);
    const expOf = u => u.expiresAt && now > u.expiresAt;
    const soon = clients.filter(u => u.active && !expOf(u) && u.expiresAt && u.expiresAt - now <= 7 * 86400000).length;
    const kp = el("div", { class: "kpis" });
    const k = (l, v, c) => kp.append(el("div", { class: "kpi" }, el("span", { text: l }), el("div", { class: "big " + (c || ""), text: String(v) })));
    k("Clientes ativos", clients.filter(u => u.active && !expOf(u)).length, "pos");
    k("Vencem em 7 dias", soon, soon ? "neg" : "");
    k("Vencidos", clients.filter(expOf).length);
    k("Desativados", clients.filter(u => !u.active).length);
    k("Fornecedores da casa", sup.length);
    admin.box.append(kp);
    const fu = el("input", { placeholder: "usuario", autocomplete: "off", maxlength: "32" });
    const fp = el("input", { placeholder: "senha (mín. 6)", autocomplete: "new-password", maxlength: "100" });
    const fd = el("input", { type: "number", min: "0", value: "30", style: "width:90px" });
    admin.box.append(el("div", { class: "pro-sec" }, el("h3", { text: "Criar acesso para cliente" }),
      el("div", { class: "pro-row" },
        el("label", {}, "Usuário", fu), el("label", {}, "Senha", fp), el("label", {}, "Dias de acesso (0 = sem validade)", fd),
        el("button", { type: "button", text: "Criar acesso", onclick: async () => {
          try {
            const days = parseInt(fd.value, 10) || 0;
            await api("POST", "/api/admin/users", { user: fu.value, pass: fp.value, days });
            admin.welcome = welcomeMsg(fu.value.trim().toLowerCase(), fp.value, days ? Date.now() + days * 86400000 : null);
            await renderAdmin(); note("Acesso criado ✓ Copie a mensagem abaixo e envie ao cliente.");
          } catch (e) { note(e.message, true); }
        } })), admin.msg));
    if (admin.welcome) {
      const w = admin.welcome;
      admin.box.append(el("div", { class: "msgbox", text: w }), el("div", { class: "row" },
        el("button", { type: "button", class: "ghost", text: "Copiar mensagem", onclick: () => copyText(w) }),
        el("a", { class: "link", href: "https://wa.me/?text=" + encodeURIComponent(w), target: "_blank", rel: "noopener noreferrer", text: "Enviar por WhatsApp ↗" }),
        el("button", { type: "button", class: "ghost", text: "Fechar", onclick: () => { admin.welcome = null; renderAdmin(); } })));
    }
    const search = el("input", { type: "search", placeholder: "Buscar cliente...", value: admin.q, "aria-label": "Buscar cliente" });
    const tbl = el("table", {}, el("thead", {}, el("tr", {}, ["Usuário", "Validade", "Situação", "IP atual", "Último uso", "Ações"].map(h => el("th", { text: h })))));
    const tb = el("tbody");
    const drawUsers = () => {
      admin.q = search.value;
      const term = search.value.trim().toLowerCase();
      tb.replaceChildren();
      users.filter(u => !term || u.user.includes(term)).sort((a, b) => (a.expiresAt || 9e15) - (b.expiresAt || 9e15)).forEach(u => {
        const exp = expOf(u);
        const left = u.expiresAt ? Math.ceil((u.expiresAt - now) / 86400000) : null;
        const st = !u.active ? "Desativado" : exp ? "Vencido" : (left != null && left <= 7 ? "Vence em " + left + " d" : "Ativo");
        const b = (label, fn, okMsg) => el("button", { type: "button", class: "ghost sm", text: label, onclick: () => act(fn, okMsg) });
        tb.append(el("tr", {},
          el("td", { text: u.user + (u.admin ? " (admin)" : "") }), el("td", { text: fmtD(u.expiresAt) }),
          el("td", { class: !u.active || exp ? "neg" : (left != null && left <= 7 ? "" : "pos"), text: st }),
          el("td", { text: u.ip || "—" }), el("td", { text: fmtDT(u.lastSeen) }),
          el("td", {},
            b("+30 dias", () => api("PATCH", "/api/admin/users/" + u.user, { addDays: 30 })),
            b("Liberar IP", () => api("PATCH", "/api/admin/users/" + u.user, { resetIp: true }), "IP liberado ✓ O cliente pode entrar de outro lugar."),
            b(u.active ? "Desativar" : "Ativar", () => api("PATCH", "/api/admin/users/" + u.user, { active: !u.active })),
            b("Nova senha", () => {
              const pw = window.prompt("Nova senha para " + u.user + " (mín. 6):");
              if (pw == null) return Promise.resolve();
              return api("PATCH", "/api/admin/users/" + u.user, { pass: pw }).then(() => { admin.welcome = welcomeMsg(u.user, pw, u.expiresAt); });
            }, "Senha alterada ✓ A mensagem com o novo acesso está logo acima."),
            u.admin ? null : el("button", { type: "button", class: "ghost sm", text: "Msg renovação", onclick: () => copyText("Olá! Seu acesso ao Radar de Fornecedores " + (exp ? "venceu em " : "vence em ") + fmtD(u.expiresAt) + ". Quer renovar? Me avise que eu libero na hora.") }),
            u.admin ? null : b("Excluir", () => {
              if (!confirm("Excluir o usuário " + u.user + "?")) return Promise.resolve();
              return api("DELETE", "/api/admin/users/" + u.user);
            }, "Usuário excluído."))));
      });
    };
    search.addEventListener("input", drawUsers); drawUsers();
    tbl.append(tb);
    admin.box.append(el("div", { class: "pro-sec" }, el("h3", { text: "Clientes (" + users.length + ")" }), search, el("div", { class: "tablewrap", style: "margin-top:8px" }, tbl),
      el("p", { class: "small muted", text: "Cada conta usa um IP por vez. Se o cliente trocar de rede, ele espera alguns minutos sem uso ou você clica em “Liberar IP”." })));
    const f = {
      name: el("input", { placeholder: "Nome do fornecedor", maxlength: "80" }),
      region: el("select", {}, el("option", { value: "china", text: "China / internacional" }), el("option", { value: "brasil", text: "Brasil" })),
      kind: el("select", {}, Object.keys(KIND_NAMES).map(k => el("option", { value: k, text: KIND_NAMES[k] }))),
      niche: el("input", { placeholder: "Nicho (ex.: eletrônicos, moda)", maxlength: "120" }),
      desc: el("input", { placeholder: "Descrição curta", maxlength: "400", style: "min-width:240px" }),
      url: el("input", { placeholder: "https://site-do-fornecedor.com", maxlength: "300" }),
      city: el("input", { placeholder: "Cidade / observação", maxlength: "80" })
    };
    f.kind.value = "wholesale";
    const bulk = el("textarea", { rows: "4", placeholder: "Em lote, um por linha:\nNome | site | nicho | china ou brasil | cidade" });
    admin.box.append(el("div", { class: "pro-sec" }, el("h3", { text: "Adicionar fornecedor para todos os clientes" }),
      el("div", { class: "pro-row" },
        el("label", {}, "Nome", f.name), el("label", {}, "Região", f.region), el("label", {}, "Tipo", f.kind),
        el("label", {}, "Nicho", f.niche), el("label", {}, "Descrição", f.desc), el("label", {}, "Site", f.url), el("label", {}, "Local", f.city),
        el("button", { type: "button", text: "Adicionar", onclick: () => act(async () => {
          await api("POST", "/api/admin/suppliers", { name: f.name.value, region: f.region.value, kind: f.kind.value, niche: f.niche.value, desc: f.desc.value, url: f.url.value, city: f.city.value });
        }, "Fornecedor adicionado ✓ Já aparece para todos.") })),
      bulk, el("div", { class: "row", style: "margin-top:8px" }, el("button", { type: "button", class: "ghost", text: "Adicionar lista", onclick: () => act(async () => {
        const lines = bulk.value.split(/\r?\n/).slice(0, 100).map(l => l.trim()).filter(Boolean);
        for (const l of lines) {
          const p = l.split("|").map(x => x.trim());
          await api("POST", "/api/admin/suppliers", { name: p[0], url: p[1], niche: p[2], region: /bra/i.test(p[3] || "") ? "brasil" : "china", city: p[4] });
        }
      }, "Lista adicionada ✓") }))));
    const st2 = el("table", {}, el("thead", {}, el("tr", {}, ["Nome", "Região", "Nicho", "Site", ""].map(h => el("th", { text: h })))));
    const tb2 = el("tbody");
    sup.forEach(x => {
      const r = x.row;
      tb2.append(el("tr", {}, el("td", { text: r[0] }), el("td", { text: REGION_NAMES[r[1]] || r[1] }), el("td", { text: r[3] }), el("td", { text: r[5] || "—" }),
        el("td", {}, el("button", { type: "button", class: "danger sm", text: "Remover", onclick: () => { if (confirm("Remover " + r[0] + " para todos?")) act(() => api("DELETE", "/api/admin/suppliers/" + x.id), "Removido."); } }))));
    });
    st2.append(tb2);
    admin.box.append(el("div", { class: "pro-sec" }, el("h3", { text: "Fornecedores da casa (" + sup.length + ")" }),
      sup.length ? el("div", { class: "tablewrap" }, st2) : el("p", { class: "small muted", text: "Nenhum ainda." })));
  }

  async function start() {
    try { me = await api("GET", "/api/me"); } catch (_) { return; }
    const bar = $("themeBtn").parentNode;
    bar.insertBefore(el("span", { class: "userchip", text: "👤 " + me.user + (me.expiresAt ? " · até " + fmtD(me.expiresAt) : "") }), $("themeBtn"));
    bar.insertBefore(el("button", { type: "button", class: "ghost sm", text: "Sair", onclick: async () => {
      try { await api("POST", "/api/logout", {}); } catch (_) {}
      location.replace("/");
    } }), $("themeBtn"));
    await loadHouse();
    if (me.admin) {
      const sec = addTab("admin", "🔑 Admin", "end", () => renderAdmin());
      sec.append(el("h2", { text: "Administração" }));
      admin.box = el("div", { class: "panel" }); sec.append(admin.box);
      if (location.hash === "#admin") { showTab("admin"); renderAdmin(); }
    }
    if (location.hash === "#painel") renderPainel();
  }
  try { if (!location.hash) history.replaceState(null, "", "#painel"); } catch (_) {}
  setTimeout(() => { if (location.hash === "#painel") renderPainel(); if (location.hash === "#gerenciar") renderGer(); }, 0);
  start();
})();

/* ===================== TENDÊNCIAS ML ===================== */
let trendsCache = null;
let categoriasCache = null;

async function loadTrends(force) {
  const box = $("tr_list");
  if (trendsCache && !force) { renderTrends(trendsCache, box); return; }
  box.replaceChildren(el("div", { class: "tr-loading", text: "Carregando tendências" }));
  try {
    const r = await fetch("/api/ml/trends", { credentials: "same-origin" });
    const j = await r.json();
    if (!Array.isArray(j)) throw new Error(j.error || "formato inesperado");
    trendsCache = j;
    renderTrends(j, box);
  } catch (e) {
    box.replaceChildren(el("div", { class: "notice bad", text: "Erro ao buscar tendências: " + e.message }));
  }
}

function renderTrends(lista, box) {
  box.replaceChildren();
  if (!lista.length) { box.append(el("div", { class: "empty", text: "Sem tendências no momento." })); return; }
  lista.slice(0, 30).forEach(t => {
    const kw = t.keyword || "—";
    const prod = t.produto;
    const urlML = "https://lista.mercadolivre.com.br/" + encodeURIComponent(kw);
    const urlAli = "https://www.alibaba.com/trade/search?SearchText=" + encodeURIComponent(kw);
    const url1688 = "https://s.1688.com/selloffer/offer_search.htm?keywords=" + encodeURIComponent(kw);
    const card = el("article", { class: "tr-card" });
    if (prod && prod.foto) {
      const img = el("img", { class: "tr-foto", src: prod.foto, alt: prod.titulo, loading: "lazy" });
      img.addEventListener("error", () => img.remove());
      card.append(img);
    }
    card.append(el("div", { class: "tr-termo", text: "🔥 " + kw }));
    if (prod && prod.titulo && prod.titulo !== prod.id) {
      card.append(el("h4", { text: prod.titulo }));
      if (prod.preco != null) {
        card.append(el("div", { class: "tr-preco", text: "R$ " + Number(prod.preco).toLocaleString("pt-BR", { minimumFractionDigits: 2 }) }));
      }
      if (prod.vendidos != null) {
        card.append(el("div", { class: "tr-meta" }, el("span", { text: "✅ " + prod.vendidos + " vendidos" })));
      }
    } else {
      card.append(el("h4", { class: "muted", text: "Sem produto em destaque no momento" }));
    }
    card.append(el("div", { class: "tr-links" },
      el("a", { href: urlML, target: "_blank", rel: "noopener noreferrer", text: "🔵 ML" }),
      el("a", { class: "tr-ali", href: urlAli, target: "_blank", rel: "noopener noreferrer", text: "🟠 Alibaba" }),
      el("a", { class: "tr-1688", href: url1688, target: "_blank", rel: "noopener noreferrer", text: "🔴 1688" })
    ));
    box.append(card);
  });
}

async function loadCategorias() {
  const sel = $("tr_cat");
  if (categoriasCache) { fillCategorias(categoriasCache, sel); return; }
  try {
    const r = await fetch("/api/ml/categories", { credentials: "same-origin" });
    const j = await r.json();
    if (!Array.isArray(j)) throw new Error("formato");
    categoriasCache = j;
    fillCategorias(j, sel);
  } catch (e) {
    sel.replaceChildren(el("option", { value: "", text: "Erro ao carregar categorias" }));
  }
}

function fillCategorias(lista, sel) {
  const atual = sel.value;
  sel.replaceChildren(el("option", { value: "", text: "Escolha uma categoria" }));
  lista.forEach(c => sel.append(el("option", { value: c.id, text: c.name })));
  if (atual) sel.value = atual;
}

async function loadHighlights() {
  const cat = $("tr_cat").value;
  const box = $("tr_catList");
  if (!cat) { toast("Escolha uma categoria primeiro."); return; }
  box.replaceChildren(el("div", { class: "tr-loading", text: "Buscando os produtos mais vendidos" }));
  try {
    const r = await fetch("/api/ml/highlights?cat=" + encodeURIComponent(cat), { credentials: "same-origin" });
    const j = await r.json();
    const lista = Array.isArray(j) ? j : [];
    box.replaceChildren();
    if (!lista.length) { box.append(el("div", { class: "empty", text: "Sem dados para essa categoria." })); return; }
    lista.slice(0, 20).forEach(it => {
      const id = it.id || "";
      const nome = it.titulo || it.title || id;
      const preco = it.preco != null ? "R$ " + Number(it.preco).toLocaleString("pt-BR", { minimumFractionDigits: 2 }) : "—";
      const permalink = it.permalink || ("https://www.mercadolivre.com.br/p/" + id);
      const urlAli = "https://www.alibaba.com/trade/search?SearchText=" + encodeURIComponent(nome);
      const url1688 = "https://s.1688.com/selloffer/offer_search.htm?keywords=" + encodeURIComponent(nome);
      const meta = el("div", { class: "tr-meta" });
      if (it.vendidos != null) meta.append(el("span", { text: "✅ " + it.vendidos + " vendidos" }));
      if (it.estoque != null) meta.append(el("span", { text: "📦 " + it.estoque + " em estoque" }));
      const card = el("article", { class: "tr-card" });
      if (it.foto) {
        const img = el("img", { class: "tr-foto", src: it.foto, alt: nome, loading: "lazy" });
        img.addEventListener("error", () => img.remove());
        card.append(img);
      }
      card.append(
        el("h4", { text: nome }),
        el("div", { class: "tr-preco", text: preco }),
        meta,
        el("div", { class: "tr-links" },
          el("a", { href: permalink, target: "_blank", rel: "noopener noreferrer", text: "🔵 ML" }),
          el("a", { class: "tr-ali", href: urlAli, target: "_blank", rel: "noopener noreferrer", text: "🟠 Alibaba" }),
          el("a", { class: "tr-1688", href: url1688, target: "_blank", rel: "noopener noreferrer", text: "🔴 1688" })
        )
      );
      box.append(card);
    });
  } catch (e) {
    box.replaceChildren(el("div", { class: "notice bad", text: "Erro: " + e.message }));
  }
}

if ($("tr_load")) $("tr_load").addEventListener("click", () => loadTrends(true));
if ($("tr_loadCat")) $("tr_loadCat").addEventListener("click", loadHighlights);

/* ===================== INÍCIO ===================== */
applyTheme();
syncFxInputs();
loadML();
renderMlStatic();
renderChips();
renderGuide();
render();
applyPreset();
(function init() {
  let h = "suppliers";
  try { h = (location.hash || "").replace("#", "") || "suppliers"; } catch (_) {}
  showTab(h);
})();
</script>
</body>
</html>
`;