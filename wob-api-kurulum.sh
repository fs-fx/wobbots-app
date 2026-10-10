#!/bin/bash
# WOBBOTS hesap sunucusu (wob-api) kurulumu — Ubuntu 22.04
# Kullanım: bash wob-api-kurulum.sh
set -e
[ "$(id -u)" = 0 ] || { echo "root olarak çalıştır"; exit 1; }
echo ">> Hesap sunucusu kuruluyor..."
command -v node >/dev/null || { echo "Node.js yok — önce ana kurulum (kur.sh) yapılmalı"; exit 1; }

HOST=$(awk 'NF && $1!~/^#/ {print $1; exit}' /etc/caddy/Caddyfile 2>/dev/null)
case "$HOST" in *.*) ;; *) HOST="$(curl -4 -s ifconfig.me | tr . -).sslip.io";; esac
echo ">> Alan adı: $HOST"

mkdir -p /opt/wobapi && cd /opt/wobapi
id -u wobapi >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin wobapi
[ -f package.json ] || npm init -y >/dev/null
npm install --omit=dev nodemailer@6 >/dev/null 2>&1
echo ">> nodemailer kuruldu"

cat > /opt/wobapi/server.js <<'WOBAPI_EOF'
// Wobbots hesap sunucusu — bağımlılık: nodemailer (yalnızca e-posta kodu için)
// Misafir hesap, Apple / Google / E-posta kodu / Game Center ile giriş, bulut kayıt, hesap silme.
'use strict';
const http = require('http'), https = require('https'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const DIR = process.env.WOB_DIR || __dirname;
const CFG_F = path.join(DIR, 'config.json'), DB_F = path.join(DIR, 'db.json');
const CFG = Object.assign({ port: 9100, secret: '', appleAud: [], googleAud: [], gcBundle: [], smtp: null }, JSON.parse(fs.readFileSync(CFG_F, 'utf8')));
if (!CFG.secret) throw new Error('config.json: secret boş');

// ---------- veritabanı (JSON dosyası, atomik yazma) ----------
let DB = { users: {}, idx: {}, codes: {} };
try { DB = Object.assign(DB, JSON.parse(fs.readFileSync(DB_F, 'utf8'))) } catch (e) { }
let dirty = false;
const persist = () => { dirty = true };
setInterval(() => {
  if (!dirty) return; dirty = false;
  const tmp = DB_F + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(DB)); fs.renameSync(tmp, DB_F);
}, 1500);
process.on('SIGTERM', () => { try { fs.writeFileSync(DB_F, JSON.stringify(DB)) } catch (e) { } process.exit(0) });

// ---------- yardımcılar ----------
const now = () => Date.now();
const b64u = b => Buffer.from(b).toString('base64url');
const sign = s => crypto.createHmac('sha256', CFG.secret).update(s).digest('base64url');
function token(uid) { const p = uid + '.' + (now() + 1000 * 3600 * 24 * 180); return p + '.' + sign(p) }
function checkToken(t) {
  if (typeof t !== 'string') return null; const [uid, exp, sg] = t.split('.');
  if (!uid || !exp || !sg) return null;
  const good = sign(uid + '.' + exp);
  if (sg.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sg), Buffer.from(good))) return null;
  if (+exp < now() || !DB.users[uid]) return null; return uid;
}
const BAD = ['orospu', 'siktir', 'sikerim', 'yarak', 'amcik', 'amina', 'gotveren', 'kahpe', 'pezevenk', 'ibne', 'fuck', 'shit', 'bitch', 'nigg', 'whore', 'porn', 'nazi', 'hitler'];
function cleanNick(n) {
  n = String(n || '').replace(/[<>"'`]/g, '').trim().slice(0, 12);
  const t = n.toLocaleLowerCase('tr').replace(/ı/g, 'i').replace(/ş/g, 's').replace(/ğ/g, 'g').replace(/ü/g, 'u').replace(/ö/g, 'o').replace(/ç/g, 'c').replace(/[^a-z]/g, '');
  return BAD.some(w => t.includes(w)) ? 'Robo' + (10 + crypto.randomInt(90)) : n;
}
function newUser(nick) {
  let uid; do { uid = crypto.randomBytes(9).toString('base64url') } while (DB.users[uid]);
  DB.users[uid] = { uid, nick: cleanNick(nick) || ('Robo' + (10 + crypto.randomInt(90))), created: now(), updated: 0, save: null, ids: {} };
  persist(); return DB.users[uid];
}
const pub = u => ({ uid: u.uid, nick: u.nick, created: u.created, updated: u.updated, save: u.save, linked: Object.keys(u.ids).filter(k => k !== 'guest') });
function getJSON(url) {
  return new Promise((res, rej) => {
    https.get(url, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => { try { res(JSON.parse(d)) } catch (e) { rej(e) } }) }).on('error', rej);
  })
}
function getBuf(url) {
  return new Promise((res, rej) => { https.get(url, r => { const a = []; r.on('data', c => a.push(c)); r.on('end', () => res(Buffer.concat(a))) }).on('error', rej) })
}
const JWKS = {};
async function verifyJWT(tok, jwksUrl, issuers, auds) {
  const [h, p, sg] = String(tok || '').split('.'); if (!sg) throw new Error('token');
  const head = JSON.parse(Buffer.from(h, 'base64url')), body = JSON.parse(Buffer.from(p, 'base64url'));
  let ks = JWKS[jwksUrl];
  if (!ks || ks.t < now() - 3600e3 || !ks.keys.find(k => k.kid === head.kid)) { const j = await getJSON(jwksUrl); ks = JWKS[jwksUrl] = { t: now(), keys: j.keys || [] } }
  const jwk = ks.keys.find(k => k.kid === head.kid); if (!jwk || head.alg !== 'RS256') throw new Error('anahtar');
  const ok = crypto.verify('RSA-SHA256', Buffer.from(h + '.' + p), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(sg, 'base64url'));
  if (!ok) throw new Error('imza');
  if (!issuers.includes(body.iss)) throw new Error('iss');
  const aud = Array.isArray(body.aud) ? body.aud : [body.aud];
  if (!auds.length || !aud.some(a => auds.includes(a))) throw new Error('aud');
  if (body.exp * 1000 < now() - 60e3) throw new Error('süre');
  return body;
}
async function verifyGameCenter(b) {
  const pid = String(b.teamPlayerID || b.playerId || ''), url = String(b.publicKeyUrl || '');
  if (!pid || !/^https:\/\/static\.gc\.apple\.com\/[\w\-./]+\.cer$/.test(url)) throw new Error('gc url');
  if (!CFG.gcBundle.includes(b.bundleId)) throw new Error('gc bundle');
  const ts = BigInt(b.timestamp); if (Math.abs(Number(ts) - now()) > 600e3) throw new Error('gc zaman');
  const der = await getBuf(url), cert = new crypto.X509Certificate(der);
  const tsb = Buffer.alloc(8); tsb.writeBigUInt64BE(ts);
  const data = Buffer.concat([Buffer.from(pid, 'utf8'), Buffer.from(b.bundleId, 'utf8'), tsb, Buffer.from(b.salt, 'base64')]);
  if (!crypto.verify('RSA-SHA256', data, cert.publicKey, Buffer.from(b.signature, 'base64'))) throw new Error('gc imza');
  return pid;
}
let mailer = null;
function getMailer() {
  if (!CFG.smtp || !CFG.smtp.host) return null;
  if (!mailer) { const nm = require('nodemailer'); mailer = nm.createTransport({ host: CFG.smtp.host, port: CFG.smtp.port || 465, secure: (CFG.smtp.port || 465) === 465, auth: { user: CFG.smtp.user, pass: CFG.smtp.pass } }) }
  return mailer;
}
const RL = new Map();
function limited(key, max, ms) { const t = now(), a = (RL.get(key) || []).filter(x => x > t - ms); a.push(t); RL.set(key, a); return a.length > max }
const emailOK = e => typeof e === 'string' && e.length < 120 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const hashCode = (e, c) => crypto.createHash('sha256').update(CFG.secret + '|' + e + '|' + c).digest('hex');

// hesap bağlama: kimlik başka hesaptaysa o hesaba geçilir, yoksa mevcut hesaba eklenir
function link(prov, sub, cur, nick) {
  const key = prov + ':' + sub, owner = DB.idx[key];
  if (owner && DB.users[owner]) return { uid: owner, switched: owner !== cur };
  let u = cur && DB.users[cur];
  if (!u) u = newUser(nick);
  DB.idx[key] = u.uid; u.ids[prov] = prov === 'guest' ? [...new Set([...(u.ids.guest || []), sub])] : sub; persist();
  return { uid: u.uid, switched: false };
}

// ---------- HTTP ----------
function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
const routes = {
  'GET /status': async () => ({ ok: true, email: !!(CFG.smtp && CFG.smtp.host), apple: CFG.appleAud.length > 0, google: CFG.googleAud.length > 0, gc: CFG.gcBundle.length > 0 }),
  'POST /guest': async (b) => {
    const dev = String(b.dev || ''); if (!/^[a-f0-9]{24,64}$/.test(dev)) throw [400, 'cihaz kimliği geçersiz'];
    const r = link('guest', dev, null, b.nick); return { token: token(r.uid), user: pub(DB.users[r.uid]) };
  },
  'POST /email/start': async (b, uid, ip) => {
    const e = String(b.email || '').trim().toLowerCase(); if (!emailOK(e)) throw [400, 'e-posta adresi geçersiz'];
    const m = getMailer(); if (!m) throw [503, 'e-posta ile giriş henüz aktif değil'];
    if (limited('em:' + e, 3, 600e3) || limited('ip:' + ip, 10, 3600e3)) throw [429, 'çok fazla deneme, biraz bekle'];
    const code = String(crypto.randomInt(100000, 1000000));
    DB.codes[e] = { h: hashCode(e, code), exp: now() + 600e3, tries: 0 }; persist();
    await m.sendMail({ from: CFG.smtp.from || CFG.smtp.user, to: e, subject: 'Wobbots giriş kodun: ' + code, text: 'Wobbots giriş kodun: ' + code + '\n\nKod 10 dakika geçerlidir. Bu isteği sen yapmadıysan bu e-postayı yok sayabilirsin.' });
    return { ok: true };
  },
  'POST /link/email': async (b, uid) => {
    const e = String(b.email || '').trim().toLowerCase(), c = DB.codes[e];
    if (!c || c.exp < now()) throw [400, 'kodun süresi doldu, yeniden iste'];
    if (++c.tries > 5) { delete DB.codes[e]; persist(); throw [429, 'çok fazla hatalı deneme'] }
    if (hashCode(e, String(b.code || '').trim()) !== c.h) { persist(); throw [400, 'kod hatalı'] }
    delete DB.codes[e]; const r = link('email', e, uid, b.nick); return { token: token(r.uid), switched: r.switched, user: pub(DB.users[r.uid]) };
  },
  'POST /link/apple': async (b, uid) => {
    let p; try { p = await verifyJWT(b.idToken, 'https://appleid.apple.com/auth/keys', ['https://appleid.apple.com'], CFG.appleAud) } catch (e) { throw [401, 'Apple doğrulaması başarısız (' + e.message + ')'] }
    const r = link('apple', p.sub, uid, b.nick); return { token: token(r.uid), switched: r.switched, user: pub(DB.users[r.uid]) };
  },
  'POST /link/google': async (b, uid) => {
    let p; try { p = await verifyJWT(b.idToken, 'https://www.googleapis.com/oauth2/v3/certs', ['https://accounts.google.com', 'accounts.google.com'], CFG.googleAud) } catch (e) { throw [401, 'Google doğrulaması başarısız (' + e.message + ')'] }
    const r = link('google', p.sub, uid, b.nick); return { token: token(r.uid), switched: r.switched, user: pub(DB.users[r.uid]) };
  },
  'POST /link/gc': async (b, uid) => {
    let pid; try { pid = await verifyGameCenter(b) } catch (e) { throw [401, 'Game Center doğrulaması başarısız (' + e.message + ')'] }
    const r = link('gc', pid, uid, b.nick); return { token: token(r.uid), switched: r.switched, user: pub(DB.users[r.uid]) };
  },
  'GET /me': async (b, uid) => { if (!uid) throw [401, 'oturum yok']; return { user: pub(DB.users[uid]) } },
  'PUT /me': async (b, uid) => {
    if (!uid) throw [401, 'oturum yok']; const u = DB.users[uid];
    if (b.nick !== undefined) u.nick = cleanNick(b.nick) || u.nick;
    if (b.save !== undefined) { const s = JSON.stringify(b.save); if (s.length > 40000) throw [413, 'kayıt çok büyük']; u.save = b.save; u.updated = now() }
    persist(); return { user: pub(u) };
  },
  'DELETE /me': async (b, uid) => {
    if (!uid) throw [401, 'oturum yok']; const u = DB.users[uid];
    for (const k of Object.keys(DB.idx)) if (DB.idx[k] === uid) delete DB.idx[k];
    delete DB.users[uid]; persist(); return { ok: true, deleted: true };
  }
};
http.createServer((req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  const url = new URL(req.url, 'http://x'), key = req.method + ' ' + url.pathname.replace(/\/+$/, ''), fn = routes[key];
  if (!fn) return send(res, 404, { error: 'bulunamadı' });
  let body = '', size = 0;
  req.on('data', c => { size += c.length; if (size > 60000) { req.destroy() } else body += c });
  req.on('end', async () => {
    let b = {}; try { b = body ? JSON.parse(body) : {} } catch (e) { return send(res, 400, { error: 'geçersiz istek' }) }
    const auth = (req.headers.authorization || '').replace(/^Bearer\s+/i, ''), uid = checkToken(auth);
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    try { send(res, 200, await fn(b, uid, ip)) }
    catch (e) { if (Array.isArray(e)) send(res, e[0], { error: e[1] }); else { console.error(e); send(res, 500, { error: 'sunucu hatası' }) } }
  });
}).listen(CFG.port, '127.0.0.1', () => console.log('wob-api 127.0.0.1:' + CFG.port));
WOBAPI_EOF

if [ ! -f /opt/wobapi/config.json ]; then
cat > /opt/wobapi/config.json <<CFG
{"port":9100,"secret":"$(openssl rand -hex 32)","appleAud":[],"googleAud":[],"gcBundle":[],"smtp":null}
CFG
fi
[ -f db.json ] || echo '{"users":{},"idx":{},"codes":{}}' > db.json
chown -R wobapi:wobapi /opt/wobapi
chmod 600 /opt/wobapi/config.json

cat > /etc/systemd/system/wobapi.service <<'UNIT'
[Unit]
Description=Wobbots hesap sunucusu
After=network.target
[Service]
User=wobapi
WorkingDirectory=/opt/wobapi
ExecStart=/usr/bin/env node /opt/wobapi/server.js
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT

# --- ayar yardımcısı: wobcfg
cat > /usr/local/bin/wobcfg <<'HLP'
#!/bin/bash
F=/opt/wobapi/config.json
case "$1" in
  smtp)   [ $# -ge 5 ] || { echo "wobcfg smtp SUNUCU PORT KULLANICI SIFRE"; exit 1; }
          K=smtp A="$2" B="$3" C="$4" D="${*:5}" ;;
  apple)  [ -n "$2" ] || { echo "wobcfg apple com.ornek.wobbots"; exit 1; }; K=appleAud A="$2" ;;
  google) [ -n "$2" ] || { echo "wobcfg google XXXX.apps.googleusercontent.com"; exit 1; }; K=googleAud A="$2" ;;
  gc)     [ -n "$2" ] || { echo "wobcfg gc com.ornek.wobbots"; exit 1; }; K=gcBundle A="$2" ;;
  show)   node -e 'const c=require("'$F'");if(c.smtp)c.smtp.pass="****";c.secret="****";console.log(JSON.stringify(c,null,1))'; exit ;;
  *) echo "Kullanım: wobcfg smtp|apple|google|gc|show"; exit 1 ;;
esac
K="$K" A="$A" B="$B" C="$C" D="$D" F="$F" node -e '
const fs=require("fs"),e=process.env,c=JSON.parse(fs.readFileSync(e.F));
if(e.K==="smtp")c.smtp={host:e.A,port:+e.B,user:e.C,pass:e.D.replace(/ /g,""),from:"Wobbots <"+e.C+">"};
else{c[e.K]=c[e.K]||[];if(!c[e.K].includes(e.A))c[e.K].push(e.A)}
fs.writeFileSync(e.F,JSON.stringify(c));'
systemctl restart wobapi && sleep 1 && echo "Tamam:" && curl -s 127.0.0.1:9100/status; echo
HLP
chmod +x /usr/local/bin/wobcfg

# --- Caddy: /peer + /api
cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.yedek 2>/dev/null || true
cat > /etc/caddy/Caddyfile <<CADDY
${HOST} {
  encode gzip
  handle_path /peer/* {
    reverse_proxy 127.0.0.1:9000
  }
  handle_path /api/* {
    reverse_proxy 127.0.0.1:9100
  }
  handle {
    root * /var/www/oyunlar
    file_server
  }
}
CADDY

# --- gizlilik sayfası (varsa eski destek e-postasını korur)
mkdir -p /var/www/oyunlar
MAIL=$(grep -o 'mailto:[^"]*' /var/www/oyunlar/privacy.html 2>/dev/null | head -1 | cut -d: -f2)
cat > /var/www/oyunlar/privacy.html <<'PRIV_EOF'
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wobbots – Gizlilik Politikası / Privacy Policy</title>
<style>
:root{--bg:#f6f4ff;--ink:#1d1a3a;--mut:#5b5880;--card:#fff;--acc:#6a3ad0}
@media (prefers-color-scheme:dark){:root{--bg:#120e2e;--ink:#f1efff;--mut:#b4b0d8;--card:#1d1844;--acc:#b08aff}}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:720px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:20px;margin:28px 0 8px;color:var(--acc)}h3{font-size:17px;margin:20px 0 4px}
.d{color:var(--mut);font-size:14px;margin-bottom:24px}
section{background:var(--card);border-radius:16px;padding:8px 20px 16px;margin-bottom:20px;box-shadow:0 4px 18px rgba(0,0,0,.06)}
ul{padding-left:20px}a{color:var(--acc)}
</style>
</head>
<body>
<main>
<h1>Wobbots</h1>
<div class="d">Gizlilik Politikası · Privacy Policy — Son güncelleme / Last updated: 10.10.2026</div>

<section>
<h2>Türkçe</h2>
<p>Wobbots'u hesap açmadan, misafir olarak oynayabilirsin. Topladığımız veriler yalnızca oyunun çalışması için gereken en az bilgidir.</p>
<ul>
<li><b>Misafir hesabı:</b> İlk açılışta rastgele bir oyuncu kimliği oluşturulur. İlerlemen (seviye, jetonlar, kostümler, görevler) ve takma adın bu kimlikle sunucumuzda yedeklenir.</li>
<li><b>Giriş yöntemleri (isteğe bağlı):</b> Apple ile Giriş, Google, e-posta kodu veya Game Center ile giriş yapabilirsin. Bu durumda yalnızca hizmetin verdiği benzersiz hesap kimliği ve (paylaşırsan) e-posta adresin saklanır. Şifre saklamayız. E-posta adresin sadece giriş kodu göndermek için kullanılır.</li>
<li><b>Çok oyunculu mod:</b> Takma adın, robotunun görünümü ve oyun içi hareketlerin aynı odadaki oyunculara (WebRTC) iletilir. Bağlantı için IP adresin eşleştirme sunucusu ve diğer oyuncular tarafından teknik olarak görülebilir; bu bilgi kaydedilmez.</li>
<li><b>Reklam, analitik ve takip:</b> Yoktur. Verilerin satılmaz, üçüncü taraflarla paylaşılmaz. Sunucularımız AB'dedir (Bulgaristan).</li>
<li><b>Saklama süresi:</b> Veriler hesabın var olduğu sürece saklanır. Hesap silindiğinde kalıcı olarak ve hemen silinir.</li>
<li><b>Çocuklar:</b> Oyun genel kitleye uygundur. Uygunsuz takma adlar otomatik filtrelenir.</li>
</ul>
<h3 id="hesap-sil">Hesabını silme</h3>
<p>Oyunda <b>Profil → Hesabımı sil</b> ile hesabını ve tüm verilerini anında silebilirsin. Uygulamaya erişemiyorsan <a href="mailto:DESTEK_EPOSTA">DESTEK_EPOSTA</a> adresine oyuncu adınla yaz; 30 gün içinde silinir.</p>
<p><b>İletişim:</b> <a href="mailto:DESTEK_EPOSTA">DESTEK_EPOSTA</a></p>
</section>

<section>
<h2>English</h2>
<p>You can play Wobbots as a guest without creating an account. We collect only the minimum data needed for the game to work.</p>
<ul>
<li><b>Guest account:</b> A random player ID is created on first launch. Your progress (level, coins, cosmetics, quests) and nickname are backed up on our server under this ID.</li>
<li><b>Sign-in (optional):</b> You can sign in with Apple, Google, an email code or Game Center. We then store only the unique account identifier provided by that service and, if shared, your email address. We never store passwords. Your email is used only to send sign-in codes.</li>
<li><b>Multiplayer:</b> Your nickname, robot appearance and in-game movements are sent to players in the same room (WebRTC). To connect, your IP address is technically visible to the matchmaking server and other players; it is not stored.</li>
<li><b>Ads, analytics and tracking:</b> None. Your data is never sold or shared with third parties. Our servers are in the EU (Bulgaria).</li>
<li><b>Retention:</b> Data is kept while your account exists and is permanently deleted immediately when the account is deleted.</li>
<li><b>Children:</b> The game is suitable for a general audience. Inappropriate nicknames are filtered automatically.</li>
</ul>
<h3 id="delete-account">Deleting your account</h3>
<p>In the game, go to <b>Profile → Delete my account</b> to instantly delete your account and all its data. If you cannot access the app, email <a href="mailto:DESTEK_EPOSTA">DESTEK_EPOSTA</a> with your nickname and it will be deleted within 30 days.</p>
<p><b>Contact:</b> <a href="mailto:DESTEK_EPOSTA">DESTEK_EPOSTA</a></p>
</section>
</main>
</body>
</html>
PRIV_EOF
[ -n "$MAIL" ] && [ "$MAIL" != "DESTEK_EPOSTA" ] && sed -i "s/DESTEK_EPOSTA/$MAIL/g" /var/www/oyunlar/privacy.html

systemctl daemon-reload
systemctl enable --now wobapi >/dev/null 2>&1
systemctl restart wobapi
systemctl restart caddy
sleep 3
echo
echo "================ KURULUM TAMAM ================"
echo "Test:  curl https://$HOST/api/status"
curl -s "https://$HOST/api/status" || curl -s 127.0.0.1:9100/status
echo
echo "E-posta girişi için:  wobcfg smtp smtp.gmail.com 465 adresin@gmail.com UYGULAMA_SIFRESI"
echo "==============================================="
