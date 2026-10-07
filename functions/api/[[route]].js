// ══════════════════════════════════════════════════════
// Worker API — Penjadwalan Multimedia Gereja
// ══════════════════════════════════════════════════════

const BIDANG_BY_DOMAIN = {
  videotron: ['operator_videotron'],
  kameramen: ['videografer', 'fotografer', 'cam_director'],
  vj_dubber: ['voice_over', 'presenter_vj'],
};

const CORS = {
  'Access-Control-Allow-Origin': '*', // ganti dengan domain Pages Anda di production
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
};

const enc = new TextEncoder();
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlToBytes = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

// ─────────── JWT (HS256, Web Crypto native, tanpa dependency) ───────────
async function signJwt(payload, secret) {
  const h = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const b = b64url(enc.encode(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 604800 }))); // 7 hari
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${b}`));
  return `${h}.${b}.${b64url(sig)}`;
}

async function verifyJwt(token, secret) {
  try {
    const [h, b, s] = token.split('.');
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('HMAC', key, b64urlToBytes(s), enc.encode(`${h}.${b}`));
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(b)));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ─────────── Password hashing (salted SHA-256 ×1000, demo-grade) ───────────
async function hashPassword(password, salt) {
  let data = enc.encode(`${salt}:${password}`);
  for (let i = 0; i < 1000; i++) data = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return Array.from(data).map((b) => b.toString(16).padStart(2, '0')).join('');
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...CORS } });

// ─────────── Auth middleware ───────────
async function getAuth(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;
  const payload = await verifyJwt(token, env.JWT_SECRET);
  if (!payload) return null;
  const { results } = await env.DB.prepare(
    `SELECT id, email, full_name, whatsapp, gender, age, class_job, roles, admin_domain
     FROM profiles WHERE id = ?`
  ).bind(payload.uid).all();
  return results[0] || null;
}

async function notify(db, userId, message, swapId = null) {
  await db.prepare(
    `INSERT INTO notifications (user_id, message, swap_request_id) VALUES (?, ?, ?)`
  ).bind(userId, message, swapId).run();
}

// ═══════════════════════ FETCH HANDLER ═══════════════════════
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const db = env.DB;

    try {
      // ─────────── PUBLIC ───────────

      // LOGIN
      if (path === '/api/login' && method === 'POST') {
        const { email, password } = await request.json();
        const { results } = await db.prepare(`SELECT * FROM profiles WHERE email = ?`).bind(email).all();
        const user = results[0];
        if (!user || (await hashPassword(password, user.salt)) !== user.password_hash) {
          return json({ error: 'Email atau password salah' }, 401);
        }
        const token = await signJwt({ uid: user.id, role: user.roles }, env.JWT_SECRET);
        const { password_hash, salt, ...safe } = user;
        return json({ token, user: safe });
      }

      // ─────────── SEMUA ENDPOINT DI BAWAH INI: HARUS LOGIN ───────────
      const user = await getAuth(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);

      // ME
      if (path === '/api/me' && method === 'GET') return json({ user });

      // GET JADWAL (anggota/sekretariat/admin — filter bulan + bidang)
      if (path === '/api/schedules' && method === 'GET') {
        const month = url.searchParams.get('month');   // YYYY-MM
        const bidang = url.searchParams.get('bidang');
        let q = `SELECT s.*, p.full_name, p.whatsapp FROM schedules s
                 JOIN profiles p ON p.id = s.user_id WHERE 1=1`;
        const binds = [];
        if (month) { q += ` AND strftime('%Y-%m', s.service_date) = ?`; binds.push(month); }
        if (bidang) { q += ` AND s.bidang = ?`; binds.push(bidang); }
        q += ` ORDER BY s.service_date`;
        const { results } = await db.prepare(q).bind(...binds).all();
        return json({ schedules: results });
      }

      // KANDIDAT TUKAR: anggota lain, bidang sama, tanggal sama, bukan diri sendiri
      if (path === '/api/swap-targets' && method === 'GET') {
        const scheduleId = url.searchParams.get('schedule_id');
        const { results: mine } = await db.prepare(
          `SELECT * FROM schedules WHERE id = ? AND user_id = ?`
        ).bind(scheduleId, user.id).all();
        if (!mine[0]) return json({ error: 'Jadwal tidak ditemukan' }, 404);

        const { results: targets } = await db.prepare(
          `SELECT s.id AS schedule_id, s.service_date, s.bidang, p.full_name, p.whatsapp
           FROM schedules s JOIN profiles p ON p.id = s.user_id
           WHERE s.bidang = ? AND s.service_date = ? AND s.user_id != ?`
        ).bind(mine[0].bidang, mine[0].service_date, user.id).all();
        return json({ targets });
      }

      // BUAT REQUEST TUKAR
      if (path === '/api/swap-requests' && method === 'POST') {
        const { my_schedule_id, target_schedule_id } = await request.json();
        const { results: mySch } = await db.prepare(
          `SELECT * FROM schedules WHERE id = ? AND user_id = ?`).bind(my_schedule_id, user.id).all();
        const { results: tgtSch } = await db.prepare(
          `SELECT s.*, p.full_name AS target_name, p.id AS target_uid FROM schedules s
           JOIN profiles p ON p.id = s.user_id WHERE s.id = ?`).bind(target_schedule_id).all();
        if (!mySch[0] || !tgtSch[0]) return json({ error: 'Jadwal tidak valid' }, 400);
        if (mySch[0].bidang !== tgtSch[0].bidang) return json({ error: 'Bidang harus sama' }, 400);

        // tentukan domain admin berwenang
        let domain = null;
        for (const [d, list] of Object.entries(BIDANG_BY_DOMAIN))
          if (list.includes(mySch[0].bidang)) domain = d;

        const { results: inserted } = await db.prepare(
          `INSERT INTO swap_requests
             (requester_id, target_id, requester_schedule_id, target_schedule_id, status, admin_domain)
           VALUES (?, ?, ?, ?, 'pending_target', ?)
           RETURNING id`
        ).bind(user.id, tgtSch[0].user_id, my_schedule_id, target_schedule_id, domain).all();

        const swapId = inserted[0].id;
        const tgl = mySch[0].service_date;
        await notify(db, tgtSch[0].target_uid,
          `${user.full_name} mengajak Anda tukar jadwal ibadah tanggal ${tgl}`, swapId);
        return json({ id: swapId, status: 'pending_target' });
      }

      // TARGET RESPOND (terima / tolak)
      const respondMatch = path.match(/^\/api\/swap-requests\/(\d+)\/respond$/);
      if (respondMatch && method === 'POST') {
        const { action } = await request.json(); // accept | reject
        const { results: swaps } = await db.prepare(
          `SELECT sr.*, pr.full_name AS requester_name, ts.service_date,
                  pt.full_name AS target_name
           FROM swap_requests sr
           JOIN profiles pr ON pr.id = sr.requester_id
           JOIN profiles pt ON pt.id = sr.target_id
           JOIN schedules ts ON ts.id = sr.requester_schedule_id
           WHERE sr.id = ? AND sr.target_id = ? AND sr.status = 'pending_target'`
        ).bind(respondMatch[1], user.id).all();
        const sw = swaps[0];
        if (!sw) return json({ error: 'Request tidak ditemukan' }, 404);

        if (action === 'reject') {
          await db.prepare(`UPDATE swap_requests SET status = 'rejected', decided_at = datetime('now') WHERE id = ?`)
            .bind(sw.id).run();
          await notify(db, sw.requester_id,
            `${user.full_name} menolak permintaan tukar jadwal Anda`, sw.id);
        } else {
          await db.prepare(`UPDATE swap_requests SET status = 'pending_admin' WHERE id = ?`).bind(sw.id).run();
          // notifikasi ke SEMUA admin domain terkait
          const { results: admins } = await db.prepare(
            `SELECT id FROM profiles WHERE roles = 'admin' AND admin_domain = ?`
          ).bind(sw.admin_domain).all();
          for (const a of admins) {
            await notify(db, a.id,
              `${sw.requester_name} dan ${sw.target_name} ingin bertukar jadwal`, sw.id);
          }
        }
        return json({ ok: true });
      }

      // LIST REQUEST (anggota: miliknya | admin: pending_admin domainnya)
      if (path === '/api/swap-requests' && method === 'GET') {
        let q, binds = [];
        if (user.roles === 'admin') {
          q = `SELECT sr.*, pr.full_name AS requester_name, pt.full_name AS target_name,
                      sr1.service_date AS req_date, sr2.service_date AS tgt_date, sr1.bidang
               FROM swap_requests sr
               JOIN profiles pr ON pr.id = sr.requester_id
               JOIN profiles pt ON pt.id = sr.target_id
               JOIN schedules sr1 ON sr1.id = sr.requester_schedule_id
               JOIN schedules sr2 ON sr2.id = sr.target_schedule_id
               WHERE sr.status = 'pending_admin' AND sr.admin_domain = ?
               ORDER BY sr.created_at DESC`;
          binds = [user.admin_domain];
        } else {
          q = `SELECT sr.*, pr.full_name AS requester_name, pt.full_name AS target_name,
                      sr1.service_date AS req_date, sr2.service_date AS tgt_date, sr1.bidang,
                      pt.whatsapp AS target_wa
               FROM swap_requests sr
               JOIN profiles pr ON pr.id = sr.requester_id
               JOIN profiles pt ON pt.id = sr.target_id
               JOIN schedules sr1 ON sr1.id = sr.requester_schedule_id
               JOIN schedules sr2 ON sr2.id = sr.target_schedule_id
               WHERE sr.requester_id = ? OR sr.target_id = ?
               ORDER BY sr.created_at DESC`;
          binds = [user.id, user.id];
        }
        const { results } = await db.prepare(q).bind(...binds).all();
        return json({ requests: results });
      }

      // APPROVE / REJECT ADMIN → tukar nama otomatis di jadwal
      const decideMatch = path.match(/^\/api\/swap-requests\/(\d+)\/decide$/);
      if (decideMatch && method === 'POST') {
        if (user.roles !== 'admin') return json({ error: 'Khusus admin' }, 403);
        const { action } = await request.json(); // approve | reject
        const { results: swaps } = await db.prepare(
          `SELECT sr.*, pr.full_name AS requester_name, pt.full_name AS target_name,
                  sr1.service_date AS req_date
           FROM swap_requests sr
           JOIN profiles pr ON pr.id = sr.requester_id
           JOIN profiles pt ON pt.id = sr.target_id
           JOIN schedules sr1 ON sr1.id = sr.requester_schedule_id
           WHERE sr.id = ? AND sr.status = 'pending_admin' AND sr.admin_domain = ?`
        ).bind(decideMatch[1], user.admin_domain).all();
        const sw = swaps[0];
        if (!sw) return json({ error: 'Request tidak ditemukan / bukan domain Anda' }, 404);

        if (action === 'approve') {
          // ATOMIC: tukar user di kedua jadwal + update status
          await db.batch([
            db.prepare(`UPDATE schedules SET user_id = ? WHERE id = ?`).bind(sw.target_id, sw.requester_schedule_id),
            db.prepare(`UPDATE schedules SET user_id = ? WHERE id = ?`).bind(sw.requester_id, sw.target_schedule_id),
            db.prepare(`UPDATE swap_requests SET status = 'approved', decided_by = ?, decided_at = datetime('now') WHERE id = ?`)
              .bind(user.id, sw.id),
          ]);
          const msg = `Permintaan tukar jadwal Anda tanggal ${sw.req_date} telah DISETUJUI. Jadwal sudah ditukar.`;
          await notify(db, sw.requester_id, msg, sw.id);
          await notify(db, sw.target_id, msg, sw.id);
        } else {
          await db.prepare(`UPDATE swap_requests SET status = 'rejected', decided_by = ?, decided_at = datetime('now') WHERE id = ?`)
            .bind(user.id, sw.id).run();
          const msg = `Permintaan tukar jadwal tanggal ${sw.req_date} DITOLAK admin.`;
          await notify(db, sw.requester_id, msg, sw.id);
          await notify(db, sw.target_id, msg, sw.id);
        }
        return json({ ok: true });
      }

      // NOTIFIKASI
      if (path === '/api/notifications' && method === 'GET') {
        const { results } = await db.prepare(
          `SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`
        ).bind(user.id).all();
        const { results: unread } = await db.prepare(
          `SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND is_read = 0`
        ).bind(user.id).all();
        return json({ notifications: results, unread: unread[0].n });
      }
      if (path === '/api/notifications/read' && method === 'POST') {
        await db.prepare(`UPDATE notifications SET is_read = 1 WHERE user_id = ?`).bind(user.id).run();
        return json({ ok: true });
      }

      // ADMIN: BUAT ANGGOTA BARU
      if (path === '/api/users' && method === 'POST') {
        if (user.roles !== 'admin') return json({ error: 'Khusus admin' }, 403);
        const b = await request.json();
        const salt = crypto.randomUUID();
        const hash = await hashPassword(b.password, salt);
        await db.prepare(
          `INSERT INTO profiles (email, password_hash, salt, full_name, whatsapp, gender, age, class_job, roles, admin_domain)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(b.email, hash, salt, b.full_name, b.whatsapp || null, b.gender || null,
               b.age || null, b.class_job || null, b.roles || 'anggota',
               b.roles === 'admin' ? b.admin_domain : null).run();
        return json({ ok: true });
      }

      // ADMIN: LIST ANGGOTA (untuk pilihan bidang di form jadwal)
      if (path === '/api/users' && method === 'GET') {
        const { results } = await db.prepare(
          `SELECT id, full_name, whatsapp, roles, admin_domain FROM profiles ORDER BY full_name`
        ).all();
        return json({ users: results });
      }

      // ADMIN/SEKRETARIAT: TAMBAH JADWAL
      if (path === '/api/schedules' && method === 'POST') {
        if (user.roles === 'anggota') return json({ error: 'Khusus admin/sekretariat' }, 403);
        const b = await request.json(); // {service_date, bidang, user_id}
        await db.prepare(
          `INSERT INTO schedules (service_date, bidang, user_id) VALUES (?, ?, ?)`
        ).bind(b.service_date, b.bidang, b.user_id).run();
        return json({ ok: true });
      }

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};
