// Jalur /token -> khusus admin (header x-admin-key harus sama dengan env ADMIN_KEY)
const crypto = require('crypto');
const { make } = require('./_sign');

const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ ok: false, reason: 'Metode salah' });
  const key = process.env.ADMIN_KEY;
  if (!key || !process.env.TOKEN_SECRET || !same(req.headers['x-admin-key'] || '', key)) {
    await new Promise((r) => setTimeout(r, 500));
    return res.status(401).json({ ok: false, reason: 'Admin key salah (atau env belum diisi)' });
  }
  let b = req.body || {};
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  const t = make({ days: Number(b.days) || 0, device: b.device });
  return res.status(200).json({ ok: true, ...t });
};
