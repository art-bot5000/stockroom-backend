// ═══════════════════════════════════════════════════════════
//  STOCKROOM — Backend Service (Deno Deploy)
//  Handles OAuth, KV storage, cron email reminders
// ═══════════════════════════════════════════════════════════

// ── Environment helpers ───────────────────────────────────
const env = {
  get: (key) => Deno.env.get(key) ?? '',
  APP_URL:              Deno.env.get('APP_URL')              || 'https://art-bot5000.github.io/stockroom/',
  WORKER_URL:           Deno.env.get('WORKER_URL')           || '',
  GOOGLE_CLIENT_ID:     Deno.env.get('GOOGLE_CLIENT_ID')     || '',
  GOOGLE_CLIENT_SECRET: Deno.env.get('GOOGLE_CLIENT_SECRET') || '',
  DROPBOX_APP_KEY:      Deno.env.get('DROPBOX_APP_KEY')      || '',
  RESEND_API_KEY:       Deno.env.get('RESEND_API_KEY')       || '',
  FROM_EMAIL:           Deno.env.get('FROM_EMAIL')           || 'onboarding@resend.dev',
};

// ── Deno KV (built-in, zero config) ──────────────────────
const kv = await Deno.openKv();

const KV = {
  async get(key) {
    const res = await kv.get([key]);
    return res.value ?? null;
  },
  async put(key, value, opts) {
    const options = opts?.expirationTtl ? { expireIn: opts.expirationTtl * 1000 } : {};
    await kv.set([key], value, options);
  },
  async delete(key) {
    await kv.delete([key]);
  },
};

// ── Hourly cron ───────────────────────────────────────────
Deno.cron('stockroom-email-check', '0 * * * *', async () => {
  console.log('Cron: running hourly check');
  await cronCheck();
});

// ── HTTP server ───────────────────────────────────────────
Deno.serve(handleRequest);

async function handleRequest(request) {
  const allowedOrigins = [
    'https://art-bot5000.github.io',
    'http://localhost',
    'http://127.0.0.1',
  ];
  const origin     = request.headers.get('Origin') || '';
  const corsOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];
  const corsHeaders = {
    'Access-Control-Allow-Origin':  corsOrigin,
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age':       '86400',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const url = new URL(request.url);

  // ── Debug: inspect current schedule state ───────────────
  if (url.pathname === '/debug-schedule' && request.method === 'GET') {
    const email       = await KV.get('user_email');
    const scheduleRaw = await KV.get('schedule');
    const lastSentAt  = await KV.get('last_sent');
    const hasRefresh  = !!(await KV.get('drive_refresh_token'));
    const hasDropbox  = !!(await KV.get('dropbox_refresh_token'));
    const hasItems    = !!(await KV.get('user_items'));
    const schedule    = scheduleRaw ? JSON.parse(scheduleRaw) : null;
    const now         = new Date();
    let nextSendUTC   = null;
    if (schedule && !lastSentAt) {
      nextSendUTC = `${schedule.startDate}T${schedule.startTime || '09:00'} UK time (check timezone)`;
    } else if (schedule && lastSentAt) {
      const next = new Date(new Date(lastSentAt).getTime() + schedule.intervalDays * 86400000);
      nextSendUTC = next.toISOString();
    }
    return json({
      now:            now.toISOString(),
      email:          email ? '✓ set' : '✗ missing',
      schedule:       schedule || '✗ missing',
      lastSent:       lastSentAt || 'never',
      nextSend:       nextSendUTC,
      driveRefresh:   hasRefresh ? '✓ stored' : '✗ missing',
      dropboxRefresh: hasDropbox ? '✓ stored' : '✗ missing',
      kvSnapshot:     hasItems   ? '✓ stored' : '✗ missing',
    }, corsHeaders);
  }

  // ── Health check ────────────────────────────────────────
  if (url.pathname === '/ping') {
    return json({ ok: true }, corsHeaders);
  }

  // ── Google Drive OAuth code exchange ────────────────────
  if (url.pathname === '/auth/google' && request.method === 'GET') {
    const code        = url.searchParams.get('code');
    const redirectUri = `${env.WORKER_URL}/auth/google`;

    console.log('auth/google: code present:', !!code, 'CLIENT_ID:', !!env.GOOGLE_CLIENT_ID, 'SECRET:', !!env.GOOGLE_CLIENT_SECRET);

    if (!code) return redirect(`${env.APP_URL}?drive_auth=error&reason=no_code`);

    try {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id:     env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri:  redirectUri,
          grant_type:    'authorization_code',
        }),
      });
      const tokens = await tokenRes.json();
      console.log('Google token exchange status:', tokenRes.status);
      if (!tokenRes.ok || !tokens.access_token) {
        const reason = tokens.error_description || tokens.error || 'token_exchange';
        console.error('Google exchange failed:', reason);
        return redirect(`${env.APP_URL}?drive_auth=error&reason=${encodeURIComponent(reason)}`);
      }
      if (tokens.refresh_token) {
        await KV.put('drive_refresh_token', tokens.refresh_token);
        console.log('Drive refresh token stored');
      }
      await KV.put('drive_access_token_temp', tokens.access_token, { expirationTtl: 3600 });
      return redirect(`${env.APP_URL}?drive_auth=success`);
    } catch (err) {
      console.error('Google auth error:', err.message);
      return redirect(`${env.APP_URL}?drive_auth=error&reason=${encodeURIComponent(err.message)}`);
    }
  }

  // ── Dropbox PKCE code exchange ──────────────────────────
  if (url.pathname === '/auth/dropbox' && request.method === 'GET') {
    const code     = url.searchParams.get('code');
    const verifier = url.searchParams.get('state');
    const redirectUri = `${env.WORKER_URL}/auth/dropbox`;

    if (!code)     return redirect(`${env.APP_URL}?dropbox_auth=error&reason=no_code`);
    if (!verifier) return redirect(`${env.APP_URL}?dropbox_auth=error&reason=no_verifier`);

    try {
      const tokenRes = await fetch('https://api.dropbox.com/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          grant_type:    'authorization_code',
          client_id:     env.DROPBOX_APP_KEY,
          redirect_uri:  redirectUri,
          code_verifier: verifier,
        }),
      });
      const tokens = await tokenRes.json();
      if (!tokenRes.ok || !tokens.access_token) {
        console.error('Dropbox exchange failed:', tokens);
        return redirect(`${env.APP_URL}?dropbox_auth=error&reason=token_exchange`);
      }
      const refreshToken = tokens.refresh_token || tokens.access_token;
      await KV.put('dropbox_refresh_token', refreshToken);
      await KV.put('dropbox_access_token_temp', tokens.access_token, { expirationTtl: 14400 });
      return redirect(`${env.APP_URL}?dropbox_auth=success`);
    } catch (err) {
      return redirect(`${env.APP_URL}?dropbox_auth=error&reason=${encodeURIComponent(err.message)}`);
    }
  }

  // ── Silent token refresh (uses stored refresh token) ────
  if (url.pathname === '/auth/refresh' && request.method === 'GET') {
    const provider = url.searchParams.get('provider') || 'google';
    try {
      if (provider === 'dropbox') {
        const refreshToken = await KV.get('dropbox_refresh_token');
        if (!refreshToken) return json({ error: 'No refresh token stored' }, corsHeaders, 404);
        const token = await getDropboxAccessToken(refreshToken);
        return json({ access_token: token }, corsHeaders);
      } else {
        const refreshToken = await KV.get('drive_refresh_token');
        if (!refreshToken) return json({ error: 'No refresh token stored' }, corsHeaders, 404);
        const token = await getGoogleAccessToken(refreshToken);
        return json({ access_token: token }, corsHeaders);
      }
    } catch (err) {
      return json({ error: err.message }, corsHeaders, 401);
    }
  }

  // ── Retrieve temp Google access token ───────────────────
  if (url.pathname === '/auth/token' && request.method === 'GET') {
    const token = await KV.get('drive_access_token_temp');
    if (token) {
      await KV.delete('drive_access_token_temp');
      return json({ access_token: token }, corsHeaders);
    }
    return json({ error: 'No token available' }, corsHeaders, 404);
  }

  // ── Retrieve temp Dropbox access token ──────────────────
  if (url.pathname === '/auth/dropbox-token' && request.method === 'GET') {
    const token = await KV.get('dropbox_access_token_temp');
    if (token) {
      await KV.delete('dropbox_access_token_temp');
      return json({ access_token: token }, corsHeaders);
    }
    return json({ error: 'No token available' }, corsHeaders, 404);
  }

  // ── Store schedule ──────────────────────────────────────
  if (url.pathname === '/set-schedule' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { email, startDate, startTime, intervalDays, urgent = [], upcoming = [] } = body;
      if (!email || !startDate) {
        return json({ error: 'Missing email or startDate' }, corsHeaders, 400);
      }
      await KV.put('user_email', email);
      await KV.put('schedule', JSON.stringify({ startDate, startTime: startTime || '09:00', intervalDays: intervalDays ?? 30 }));
      if (urgent.length || upcoming.length) {
        await KV.put('user_items', JSON.stringify({ urgent, upcoming }));
      }
      return json({ ok: true }, corsHeaders);
    } catch (err) {
      return json({ error: err.message }, corsHeaders, 500);
    }
  }

  // ── Reset last sent ─────────────────────────────────────
  if (url.pathname === '/reset-schedule' && request.method === 'POST') {
    await KV.delete('last_sent');
    return json({ ok: true }, corsHeaders);
  }

  // ── Unsubscribe ─────────────────────────────────────────
  if (url.pathname === '/unsubscribe' && request.method === 'POST') {
    await KV.delete('schedule');
    await KV.delete('last_sent');
    await KV.delete('user_email');
    await KV.delete('user_items');
    return json({ ok: true }, corsHeaders);
  }

  // ── Manual send ─────────────────────────────────────────
  if (url.pathname === '/send-reminder' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { to, urgent = [], upcoming = [], items = [], manual = false } = body;
      const urgentItems   = urgent.length   ? urgent   : items.filter(i => i.daysLeft <= 7);
      const upcomingItems = upcoming.length ? upcoming : items.filter(i => i.daysLeft > 7);
      if (to) await KV.put('user_email', to);
      if (urgentItems.length || upcomingItems.length) {
        await KV.put('user_items', JSON.stringify({ urgent: urgentItems, upcoming: upcomingItems }));
      }
      const result = await sendEmail(to, urgentItems, upcomingItems);
      // Only update last_sent for scheduled sends — manual "Send Now" must not shift the schedule
      if (result.ok && !manual) await KV.put('last_sent', new Date().toISOString());
      return json(result.ok ? { ok: true } : { error: result.error }, corsHeaders, result.ok ? 200 : 502);
    } catch (err) {
      return json({ error: err.message }, corsHeaders, 500);
    }
  }

  // ── Presence: write this user's presence to KV ──────────
  if (url.pathname === '/presence-update' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { userId, name, initials, colour, view, ts } = body;
      if (!userId) return json({ error: 'Missing userId' }, corsHeaders, 400);
      await kv.set(['presence', userId], JSON.stringify({ userId, name, initials, colour, view, ts }), { expireIn: 35000 });
      return json({ ok: true }, corsHeaders);
    } catch(err) {
      return json({ error: err.message }, corsHeaders, 500);
    }
  }

  // ── Presence: SSE stream of all active users ─────────────
  // Uses Deno KV Watch to push updates whenever any presence key changes.
  if (url.pathname === '/presence-stream' && request.method === 'GET') {
    const userId = url.searchParams.get('userId') || '';

    const sseHeaders = {
      ...corsHeaders,
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no',
    };

    const stream = new ReadableStream({
      async start(controller) {
        const encode = (s) => new TextEncoder().encode(s);
        let closed = false;

        const sendUsers = async () => {
          if (closed) return;
          const entries = kv.list({ prefix: ['presence'] });
          const users = [];
          for await (const entry of entries) {
            try { users.push(JSON.parse(entry.value)); } catch(e) {}
          }
          const payload = `data: ${JSON.stringify({ type: 'presence', users })}\n\n`;
          try { controller.enqueue(encode(payload)); } catch(e) { closed = true; }
        };

        // Send current presence immediately on connect
        await sendUsers();

        // Heartbeat every 20s to keep connection alive through proxies
        const heartbeat = setInterval(() => {
          if (closed) { clearInterval(heartbeat); return; }
          try { controller.enqueue(encode(': heartbeat\n\n')); } catch(e) { closed = true; }
        }, 20000);

        // Poll for presence changes every 5s
        // (KV Watch on a prefix requires iterating — polling is simpler and reliable on Deploy)
        const pollInterval = setInterval(async () => {
          if (closed) { clearInterval(pollInterval); clearInterval(heartbeat); return; }
          await sendUsers();
        }, 5000);
      },
      cancel() {
        // Client disconnected — remove their presence entry
        kv.delete(['presence', userId]).catch(() => {});
      }
    });

    return new Response(stream, { headers: sseHeaders });
  }

  // ── Household: owner creates an invite code ─────────────
  // Stores the owner's driveFileId under a short invite code (6 chars, 24hr TTL).
  // The partner pastes this code to join — no credentials are ever shared.
  if (url.pathname === '/invite/create' && request.method === 'POST') {
    try {
      const body       = await request.json();
      const { fileId } = body;
      if (!fileId) return json({ error: 'Missing fileId' }, corsHeaders, 400);
      // Verify owner has a refresh token stored
      const refreshToken = await KV.get('drive_refresh_token');
      if (!refreshToken) return json({ error: 'No Drive connection on server — sync first' }, corsHeaders, 400);
      // Generate a short invite code
      const code = Array.from(crypto.getRandomValues(new Uint8Array(4)))
        .map(b => b.toString(36).padStart(2,'0')).join('').toUpperCase().slice(0,6);
      await kv.set(['invite', code], JSON.stringify({ fileId }), { expireIn: 86400000 }); // 24hr
      return json({ code }, corsHeaders);
    } catch(err) {
      return json({ error: err.message }, corsHeaders, 500);
    }
  }

  // ── Household: partner joins via invite code ──────────────
  // Resolves the code to a fileId and returns it. The partner's app
  // then uses the proxy endpoints to read/write that file via the owner's token.
  if (url.pathname === '/invite/join' && request.method === 'POST') {
    try {
      const body     = await request.json();
      const { code } = body;
      if (!code) return json({ error: 'Missing code' }, corsHeaders, 400);
      const raw = await KV.get('invite:' + code.toUpperCase());
      // Try both key formats
      const entryRaw = raw || await (async () => {
        const r = await kv.get(['invite', code.toUpperCase()]);
        return r.value ?? null;
      })();
      if (!entryRaw) return json({ error: 'Invalid or expired invite code' }, corsHeaders, 404);
      const { fileId } = JSON.parse(entryRaw);
      // Don't delete — allow multiple devices to join with same code within 24hr
      return json({ fileId, ok: true }, corsHeaders);
    } catch(err) {
      return json({ error: err.message }, corsHeaders, 500);
    }
  }

  // ── Household: proxy Drive file read (uses owner's token) ─
  // Partner devices call this instead of Drive directly.
  if (url.pathname === '/drive/read' && request.method === 'GET') {
    try {
      const fileId = url.searchParams.get('fileId');
      if (!fileId) return json({ error: 'Missing fileId' }, corsHeaders, 400);
      const refreshToken = await KV.get('drive_refresh_token');
      if (!refreshToken) return json({ error: 'No owner Drive token on server' }, corsHeaders, 503);
      const accessToken = await getGoogleAccessToken(refreshToken);
      const res = await fetch(
        `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      if (!res.ok) return json({ error: `Drive read failed: ${res.status}` }, corsHeaders, res.status);
      const data = await res.json();
      return json(data, corsHeaders);
    } catch(err) {
      return json({ error: err.message }, corsHeaders, 500);
    }
  }

  // ── Household: proxy Drive file write (uses owner's token) ─
  if (url.pathname === '/drive/write' && request.method === 'POST') {
    try {
      const fileId  = url.searchParams.get('fileId');
      if (!fileId) return json({ error: 'Missing fileId' }, corsHeaders, 400);
      const refreshToken = await KV.get('drive_refresh_token');
      if (!refreshToken) return json({ error: 'No owner Drive token on server' }, corsHeaders, 503);
      const accessToken = await getGoogleAccessToken(refreshToken);
      const payload = await request.text();
      const res = await fetch(
        `https://www.googleapis.com/upload/drive/v3/files/${fileId}?uploadType=media`,
        {
          method:  'PATCH',
          headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body:    payload,
        }
      );
      if (!res.ok) return json({ error: `Drive write failed: ${res.status}` }, corsHeaders, res.status);
      return json({ ok: true }, corsHeaders);
    } catch(err) {
      return json({ error: err.message }, corsHeaders, 500);
    }
  }

  // ── Household: get modified time (for checkCloudAhead) ───
  if (url.pathname === '/drive/modified' && request.method === 'GET') {
    try {
      const fileId = url.searchParams.get('fileId');
      if (!fileId) return json({ error: 'Missing fileId' }, corsHeaders, 400);
      const refreshToken = await KV.get('drive_refresh_token');
      if (!refreshToken) return json({ error: 'No owner Drive token' }, corsHeaders, 503);
      const accessToken = await getGoogleAccessToken(refreshToken);
      const res = await fetch(
        `https://www.googleapis.com/drive/v3/files/${fileId}?fields=modifiedTime`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      if (!res.ok) return json({ error: `Drive stat failed: ${res.status}` }, corsHeaders, res.status);
      const data = await res.json();
      return json({ modifiedTime: data.modifiedTime }, corsHeaders);
    } catch(err) {
      return json({ error: err.message }, corsHeaders, 500);
    }
  }

  return new Response('Not found', { status: 404 });
}

// ── Cron logic ────────────────────────────────────────────
async function cronCheck() {
  try {
    const email      = await KV.get('user_email');
    const scheduleRaw = await KV.get('schedule');
    const lastSentAt  = await KV.get('last_sent');

    if (!email || !scheduleRaw) { console.log('Cron: no schedule configured'); return; }

    const { startDate, startTime, intervalDays } = JSON.parse(scheduleRaw);
    const now      = new Date();

    // Parse startDate+startTime as Europe/London time
    function toUKDate(dateStr, timeStr) {
      // Build a temp date to measure the UK offset at that moment
      const probe = new Date(`${dateStr}T${timeStr || '09:00'}:00Z`); // treat as UTC first
      const ukParts = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Europe/London',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false,
      }).formatToParts(probe);
      const get = (type) => parseInt(ukParts.find(p => p.type === type)?.value || '0');
      const ukDate = new Date(Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second')));
      // Offset = difference between UTC representation and UK representation
      const offsetMs = ukDate.getTime() - probe.getTime();
      // Target: dateStr + timeStr in UK local time → UTC
      const localMs = new Date(`${dateStr}T${timeStr || '09:00'}:00Z`).getTime();
      return new Date(localMs - offsetMs);
    }

    const nextSend = !lastSentAt
      ? toUKDate(startDate, startTime || '09:00')
      : new Date(new Date(lastSentAt).getTime() + intervalDays * 86400000);

    if (now < nextSend) {
      console.log(`Cron: next send in ${Math.round((nextSend.getTime() - now.getTime()) / 60000)} mins`);
      return;
    }

    let urgentItems = [], upcomingItems = [], source = null;

    // Try Google Drive
    const driveRefresh = await KV.get('drive_refresh_token');
    if (driveRefresh) {
      try {
        const fresh = await getItemsFromDrive(driveRefresh);
        urgentItems   = fresh.filter(i => i.daysLeft <= 7);
        upcomingItems = fresh.filter(i => i.daysLeft > 7 && i.daysLeft <= 30);
        source = 'Drive';
        console.log(`Cron: ${fresh.length} items from Drive`);
      } catch (err) { console.warn('Cron: Drive failed:', err.message); }
    }

    // Try Dropbox
    if (!source) {
      const dropboxRefresh = await KV.get('dropbox_refresh_token');
      if (dropboxRefresh) {
        try {
          const fresh = await getItemsFromDropbox(dropboxRefresh);
          urgentItems   = fresh.filter(i => i.daysLeft <= 7);
          upcomingItems = fresh.filter(i => i.daysLeft > 7 && i.daysLeft <= 30);
          source = 'Dropbox';
          console.log(`Cron: ${fresh.length} items from Dropbox`);
        } catch (err) { console.warn('Cron: Dropbox failed:', err.message); }
      }
    }

    // KV snapshot fallback
    if (!source) {
      const itemsRaw = await KV.get('user_items');
      if (!itemsRaw) { console.log('Cron: no items available'); return; }
      const { urgent = [], upcoming = [] } = JSON.parse(itemsRaw);
      urgentItems = urgent; upcomingItems = upcoming;
      source = 'KV snapshot';
    }

    if (!urgentItems.length && !upcomingItems.length) {
      await KV.put('last_sent', now.toISOString());
      console.log('Cron: nothing due, marking sent');
      return;
    }

    const result = await sendEmail(email, urgentItems, upcomingItems);
    if (result.ok) {
      await KV.put('last_sent', now.toISOString());
      console.log(`Cron: sent to ${email} (${source})`);
    } else {
      console.error('Cron send failed:', result.error);
    }
  } catch (err) {
    console.error('Cron error:', err.message);
  }
}

// ── Google Drive helpers ──────────────────────────────────
async function getGoogleAccessToken(refreshToken) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      client_id:     env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      grant_type:    'refresh_token',
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) throw new Error(`Google token refresh failed: ${data.error}`);
  return data.access_token;
}

async function getItemsFromDrive(refreshToken) {
  const accessToken = await getGoogleAccessToken(refreshToken);
  const searchRes   = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=name='stockroom_data.json'+and+trashed=false&fields=files(id)`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const searchData = await searchRes.json();
  if (!searchData.files?.length) throw new Error('stockroom_data.json not found in Drive');
  const fileId  = searchData.files[0].id;
  const fileRes = await fetch(
    `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  if (!fileRes.ok) throw new Error(`Drive read failed: ${fileRes.status}`);
  const data = await fileRes.json();
  if (!Array.isArray(data.items)) throw new Error('Invalid Drive file format');
  return computeDaysLeft(data.items);
}

// ── Dropbox helpers ───────────────────────────────────────
async function getDropboxAccessToken(refreshToken) {
  const res = await fetch('https://api.dropbox.com/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      grant_type:    'refresh_token',
      client_id:     env.DROPBOX_APP_KEY,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) throw new Error(`Dropbox refresh failed: ${JSON.stringify(data)}`);
  return data.access_token;
}

async function getItemsFromDropbox(refreshToken) {
  const accessToken = await getDropboxAccessToken(refreshToken);
  const res = await fetch('https://content.dropboxapi.com/2/files/download', {
    method: 'POST',
    headers: {
      'Authorization':   `Bearer ${accessToken}`,
      'Dropbox-API-Arg': JSON.stringify({ path: '/stockroom_data.json' }),
    },
  });
  if (!res.ok) throw new Error(`Dropbox read failed: ${res.status}`);
  const data = await res.json();
  if (!Array.isArray(data.items)) throw new Error('Invalid Dropbox file');
  return computeDaysLeft(data.items);
}

// ── Stock calculation ─────────────────────────────────────
// Must match frontend calcStock() exactly so cron sees same daysLeft as the UI.
function computeDaysLeft(itemsArr) {
  const now = Date.now();
  return itemsArr
    .filter(item => item.logs?.length)
    .map(item => {
      // Only count delivered logs — skip pending deliveries
      const deliveredLogs = (item.logs || []).filter(l => !l.pendingDelivery);
      if (!deliveredLogs.length) return null;

      // Sum total qty across all delivered logs (same as frontend calcStock)
      const totalQty  = deliveredLogs.reduce((s, l) => s + (parseFloat(l.qty) || 1), 0);
      const totalDays = (item.months || 1) * 30.5 * totalQty;

      // Reference date: startedUsing if set, otherwise earliest log date
      const sortedLogs = [...deliveredLogs].sort((a, b) => new Date(a.date) - new Date(b.date));
      const refDate    = item.startedUsing || sortedLogs[0].date;
      const daysSince  = (now - new Date(refDate + 'T12:00:00').getTime()) / 86400000;
      const daysLeft   = Math.round(Math.max(0, totalDays - daysSince));

      // Include items within 45 days (raised from 30 to avoid edge cases)
      if (daysLeft > 45) return null;

      const prices = deliveredLogs
        .map(l => parseFloat(String(l.price || '').replace(/[^0-9.]/g, '')))
        .filter(v => !isNaN(v) && v > 0);
      return {
        name:        item.name,
        daysLeft,
        store:       item.store || '',
        url:         item.url   || '',
        lastPrice:   prices.length ? `£${prices[prices.length - 1].toFixed(2)}` : null,
        storePrices: item.storePrices || [],
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.daysLeft - b.daysLeft);
}

// ── Email ─────────────────────────────────────────────────
async function sendEmail(to, urgentItems, upcomingItems) {
  const appUrl     = env.APP_URL;
  const totalItems = urgentItems.length + upcomingItems.length;

  const makeRows = items => items.map(item => {
    const priceCell = item.lastPrice
      ? `<span style="font-family:monospace;font-weight:700;color:#111">${h(item.lastPrice)}</span>`
      : '<span style="color:#999">—</span>';
    const buyCell = item.url
      ? `<a href="${h(item.url)}" style="display:inline-block;background:#5b8dee;color:#fff;padding:4px 12px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:600">Buy ↗</a>`
      : '<span style="color:#999">—</span>';
    const storePrices = (item.storePrices || []).filter(sp => sp.store && sp.price);
    const spHtml = storePrices.length > 1
      ? `<div style="margin-top:4px;display:flex;gap:6px;flex-wrap:wrap">${storePrices.map(sp =>
          `<span style="font-size:11px;font-family:monospace;padding:2px 7px;border-radius:99px;background:#f0f0f0;color:#555">${h(sp.store)}: ${h(sp.price)}</span>`
        ).join('')}</div>` : '';
    const daysColor = item.daysLeft <= 7 ? '#e85050' : '#e8a838';
    return `<tr>
      <td style="padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top">
        <div style="font-weight:600;color:#111;margin-bottom:2px">${h(item.name)}</div>
        ${item.store ? `<div style="font-size:12px;color:#666">${h(item.store)}</div>` : ''}${spHtml}
      </td>
      <td style="padding:12px 14px;border-bottom:1px solid #eee;color:${daysColor};font-family:monospace;font-weight:700;white-space:nowrap;vertical-align:top">${item.daysLeft}d</td>
      <td style="padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top">${priceCell}</td>
      <td style="padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top">${buyCell}</td>
    </tr>`;
  }).join('');

  const tableWrap = rows => `
    <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px">
      <thead><tr style="background:#f9f9f9">
        <th style="padding:10px 14px;text-align:left;font-size:11px;color:#999;text-transform:uppercase;border-bottom:2px solid #eee">Item</th>
        <th style="padding:10px 14px;text-align:left;font-size:11px;color:#999;text-transform:uppercase;border-bottom:2px solid #eee">Left</th>
        <th style="padding:10px 14px;text-align:left;font-size:11px;color:#999;text-transform:uppercase;border-bottom:2px solid #eee">Price</th>
        <th style="padding:10px 14px;text-align:left;font-size:11px;color:#999;text-transform:uppercase;border-bottom:2px solid #eee">Order</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;

  const urgentSection = urgentItems.length ? `
    <div style="background:#fff5f5;border-left:4px solid #e85050;border-radius:4px;padding:12px 16px;margin-bottom:12px">
      <div style="font-weight:700;color:#e85050">🔴 Order immediately — ${urgentItems.length} item${urgentItems.length !== 1 ? 's' : ''} within 7 days</div>
    </div>${tableWrap(makeRows(urgentItems))}` : '';

  const upcomingSection = upcomingItems.length ? `
    <div style="background:#fffbf0;border-left:4px solid #e8a838;border-radius:4px;padding:12px 16px;margin-bottom:12px${urgentItems.length ? ';margin-top:8px' : ''}">
      <div style="font-weight:700;color:#c8861a">🟡 Order soon — ${upcomingItems.length} item${upcomingItems.length !== 1 ? 's' : ''} within 30 days</div>
    </div>${tableWrap(makeRows(upcomingItems))}` : '';

  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:system-ui,sans-serif">
  <div style="max-width:600px;margin:32px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)">
    <div style="background:#0f1117;padding:24px 28px">
      <div style="font-family:monospace;font-size:16px;letter-spacing:3px;color:#e8a838;font-weight:700">📦 STOCKROOM</div>
      <div style="font-size:12px;color:#7880a0;margin-top:4px">Household Consumables Tracker</div>
    </div>
    <div style="padding:28px">
      <h2 style="margin:0 0 8px;font-size:20px;color:#111">Your stock reminder</h2>
      <p style="margin:0 0 24px;color:#666;font-size:14px">
        ${totalItems} item${totalItems !== 1 ? 's' : ''} need attention.
        ${urgentItems.length ? `<strong style="color:#e85050">${urgentItems.length} urgent.</strong>` : ''}
      </p>
      ${urgentSection}${upcomingSection}
      <div style="margin-top:28px;text-align:center">
        <a href="${appUrl}" style="display:inline-block;background:#e8a838;color:#111;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px">Open STOCKROOM</a>
      </div>
    </div>
    <div style="background:#f9f9f9;padding:16px 28px;font-size:12px;color:#999;text-align:center;border-top:1px solid #eee">
      Sent from STOCKROOM &nbsp;·&nbsp;
      <a href="${appUrl}" style="color:#999">${appUrl}</a> &nbsp;·&nbsp;
      <a href="${appUrl}?action=unsubscribe" style="color:#999">Unsubscribe</a>
    </div>
  </div>
</body></html>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from:    env.FROM_EMAIL,
      to:      [to],
      subject: `📦 STOCKROOM — ${urgentItems.length ? `${urgentItems.length} urgent, ` : ''}${totalItems} item${totalItems !== 1 ? 's' : ''} running low`,
      html,
    }),
  });
  const data = await res.json();
  return res.ok ? { ok: true } : { ok: false, error: data.message || JSON.stringify(data) };
}

// ── Helpers ───────────────────────────────────────────────
function json(data, headers = {}, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, 'Content-Type': 'application/json' },
  });
}

function redirect(url) {
  return Response.redirect(url, 302);
}

function h(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
