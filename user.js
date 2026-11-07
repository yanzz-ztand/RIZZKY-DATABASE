// Jalur /user -> dipakai APK untuk cek token (tanpa database)
const { check } = require('./_sign');

module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(200).json({ ok: false, reason: 'Metode salah' });
  let b = req.body || {};
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  const r = check(b.token, b.device);
  return res.status(200).json(r.ok ? { ok: true, exp: r.exp } : { ok: false, reason: r.reason });
};
