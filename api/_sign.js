// Token bertanda tangan (HMAC), tanpa database.
// Format: RZX-<exp jam base36>-<id 8 hex>-<id perangkat 8 hex atau 0>-<tanda tangan 16 hex>
const crypto = require('crypto');

const secret = () => process.env.TOKEN_SECRET || '';
const sig = (body) => crypto.createHmac('sha256', secret()).update(body).digest('hex').slice(0, 16).toUpperCase();
const normDev = (d) => String(d || '').replace(/[^0-9A-Fa-f]/g, '').toUpperCase().slice(0, 8);

function make({ days, device }) {
  days = Math.min(Math.max(Number(days) || 0, 0), 3650); // maks 10 tahun
  const expH = days > 0 ? Math.floor((Date.now() + days * 86400000) / 3600000) : 0;
  const e = expH.toString(36).toUpperCase();
  const id = crypto.randomBytes(4).toString('hex').toUpperCase();
  const dev = normDev(device) || '0';
  const body = `RZX-${e}-${id}-${dev}`;
  return { token: `${body}-${sig(body)}`, id, exp: expH * 3600000 };
}

// kembalikan { ok, reason, id, exp }
function check(token, device) {
  const p = String(token || '').trim().toUpperCase().split('-');
  if (p.length !== 5 || p[0] !== 'RZX' || !secret()) return { ok: false, reason: 'Token tidak valid' };
  const [, e, id, dev, s] = p;
  const body = `RZX-${e}-${id}-${dev}`;
  const a = Buffer.from(sig(body)), b = Buffer.from(s);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'Token tidak valid' };
  const revoked = (process.env.REVOKED || '').toUpperCase().split(',').map((x) => x.trim()).filter(Boolean);
  if (revoked.includes(id)) return { ok: false, reason: 'Token dinonaktifkan' };
  const exp = parseInt(e, 36) * 3600000;
  if (exp > 0 && Date.now() > exp) return { ok: false, reason: 'Token kedaluwarsa' };
  if (dev !== '0' && dev !== normDev(device)) return { ok: false, reason: `Token untuk perangkat lain (token: ${dev}, HP: ${normDev(device) || 'kosong'})` };
  return { ok: true, id, exp };
}

module.exports = { make, check };
