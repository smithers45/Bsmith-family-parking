/* =============================================================================
   Asbury St Parking - reservation worker
   -----------------------------------------------------------------------------
   Two endpoints:

     POST /checkout         called by the public page. Validates the request,
                            works out the price ITSELF, places a short hold,
                            and returns a Square checkout URL.

     POST /square-webhook   called by Square. Verifies the signature, and only
                            then turns the hold into a confirmed reservation.

   Plus a cron handler that expires abandoned holds.

   Principles this file exists to enforce:
     - The browser is never trusted. Prices, availability and windows are all
       recomputed here. The page could send $1 for a whole-fair spot and it
       would be rejected.
     - A reservation is only ever created by a signature-verified Square
       webhook. Nothing the public can call writes a confirmed booking.
     - Square retries webhooks. Every write is idempotent.
   ========================================================================== */

const PRICES = {
  standard: 40,
  late: 30,
  alldayQuiet: 100,      // fair days 5-8
  alldayBusy: 120,       // all other days
  wholeFair: 1000
};
const QUIET_DAYS = [5, 6, 7, 8];
const BOOKING_FEE = 2;
const WHOLE_FAIR_SPOTS = ['backtruck', 'backgarden', 'backdavid'];
const HOLD_MINUTES = 20;

const ARRIVAL_WINDOWS = {
  standard_morning:   ['06:30', '14:00'],
  standard_afternoon: ['14:00', '23:00'],
  late:               ['18:00', '23:00'],
  allday:             ['06:30', '23:00'],
  wholefair:          ['06:30', '23:00']
};

/* ---------- fair calendar (same rule as both web pages) ---------- */

function laborDay(year){
  const sept1 = new Date(Date.UTC(year, 8, 1));
  return new Date(Date.UTC(year, 8, 1 + ((8 - sept1.getUTCDay()) % 7)));
}
function fairDayNumber(dateStr){
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr);
  if(!m) return 0;
  const y = Number(m[1]);
  const d = Date.UTC(y, Number(m[2]) - 1, Number(m[3]));
  const end = laborDay(y).getTime();
  const start = end - 11 * 86400000;
  if(d < start || d > end) return 0;
  return Math.round((d - start) / 86400000) + 1;
}
/* Booking for a fair opens the day after the previous one ends. */
function bookableYear(now){
  const y = now.getUTCFullYear();
  const opens = laborDay(y).getTime() + 86400000;
  return now.getTime() >= opens ? y + 1 : y;
}

/* ---------- small helpers ---------- */

const enc = new TextEncoder();

function json(body, status, extraHeaders){
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {})
  });
}
function toMinutes(t){
  const m = /^(\d{1,2}):(\d{2})$/.exec(t || '');
  return m ? Number(m[1]) * 60 + Number(m[2]) : null;
}
function clean(s, max){
  return String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
}
function digits(s){ return String(s == null ? '' : s).replace(/\D/g, ''); }

function corsHeaders(env, request){
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s=> s.trim()).filter(Boolean);
  const origin = request.headers.get('Origin') || '';
  const ok = allowed.indexOf(origin) >= 0;
  return {
    'Access-Control-Allow-Origin': ok ? origin : (allowed[0] || ''),
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

/* Constant-time compare, so a wrong signature leaks nothing by timing. */
function timingSafeEqual(a, b){
  if(a.length !== b.length) return false;
  let diff = 0;
  for(let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ---------- Firebase: service account -> access token -> REST ---------- */

let tokenCache = { value: null, expires: 0 };

function b64url(bytes){
  let s = '';
  const arr = new Uint8Array(bytes);
  for(let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function pemToPkcs8(pem){
  const body = pem.replace(/-----BEGIN PRIVATE KEY-----/, '')
                  .replace(/-----END PRIVATE KEY-----/, '')
                  .replace(/\s+/g, '');
  const raw = atob(body);
  const out = new Uint8Array(raw.length);
  for(let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}

async function firebaseToken(env){
  const now = Math.floor(Date.now() / 1000);
  if(tokenCache.value && tokenCache.expires - 120 > now) return tokenCache.value;

  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const header = b64url(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = b64url(enc.encode(JSON.stringify({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.database ' +
           'https://www.googleapis.com/auth/userinfo.email',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  })));
  const unsigned = header + '.' + claim;

  const key = await crypto.subtle.importKey(
    'pkcs8', pemToPkcs8(sa.private_key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(unsigned));
  const jwt = unsigned + '.' + b64url(sig);

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' +
          encodeURIComponent(jwt)
  });
  if(!res.ok) throw new Error('firebase token exchange failed: ' + res.status);
  const data = await res.json();
  tokenCache = { value: data.access_token, expires: now + (data.expires_in || 3600) };
  return tokenCache.value;
}

async function dbFetch(env, path, method, body){
  const token = await firebaseToken(env);
  const url = env.FIREBASE_DB_URL.replace(/\/$/, '') + '/' + path + '.json';
  const res = await fetch(url, {
    method: method || 'GET',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if(!res.ok) throw new Error('db ' + method + ' ' + path + ' -> ' + res.status);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}
const dbGet   = (env, p)    => dbFetch(env, p, 'GET');
const dbPut   = (env, p, v) => dbFetch(env, p, 'PUT', v);
const dbPatch = (env, p, v) => dbFetch(env, p, 'PATCH', v);

/* ---------- pricing and validation, server side only ---------- */

function priceFor(req){
  if(req.kind === 'wholefair') return PRICES.wholeFair;
  if(req.tier === 'standard') return PRICES.standard;
  if(req.tier === 'late') return PRICES.late;
  const fd = fairDayNumber(req.date);
  return QUIET_DAYS.indexOf(fd) >= 0 ? PRICES.alldayQuiet : PRICES.alldayBusy;
}

function windowKey(req){
  if(req.kind === 'wholefair') return 'wholefair';
  if(req.tier === 'standard') return 'standard_' + req.shift;
  return req.tier;
}

/* Returns { ok:true, req } or { ok:false, why } */
function validate(raw, now){
  if(!raw || typeof raw !== 'object') return { ok:false, why:'malformed request' };

  const year = bookableYear(now);
  const g = raw.guest || {};
  const guest = {
    name:   clean(g.name, 80),
    phone:  digits(g.phone),
    arrive: clean(g.arrive, 5),
    car:    clean(g.car, 60),
    colour: clean(g.colour, 30)
  };
  if(!guest.name) return { ok:false, why:'name required' };
  if(!(guest.phone.length === 10 || (guest.phone.length === 11 && guest.phone[0] === '1'))){
    return { ok:false, why:'a 10-digit phone number is required' };
  }
  if(guest.phone.length === 11) guest.phone = guest.phone.slice(1);
  if(!guest.car) return { ok:false, why:'car make and model required' };
  if(!guest.colour) return { ok:false, why:'car colour required' };

  let req;
  if(raw.kind === 'wholefair'){
    const spot = clean(raw.spot, 20);
    if(WHOLE_FAIR_SPOTS.indexOf(spot) < 0) return { ok:false, why:'that spot is not offered for the whole fair' };
    if(String(raw.year) !== String(year)) return { ok:false, why:'wrong fair year' };
    req = { kind:'wholefair', spot, year: String(year), guest };
  }else if(raw.kind === 'day'){
    const tier = clean(raw.tier, 12);
    if(['standard','late','allday'].indexOf(tier) < 0) return { ok:false, why:'unknown option' };
    const date = clean(raw.date, 10);
    const fd = fairDayNumber(date);
    if(!fd) return { ok:false, why:'that date is not a day of the fair' };
    if(date.slice(0,4) !== String(year)) return { ok:false, why:'wrong fair year' };
    let shift = null;
    if(tier === 'standard'){
      shift = clean(raw.shift, 10);
      if(['morning','afternoon'].indexOf(shift) < 0) return { ok:false, why:'pick a morning or afternoon shift' };
    }
    req = { kind:'day', tier, date, shift, fairDay: fd, guest };
  }else{
    return { ok:false, why:'unknown request kind' };
  }

  const w = ARRIVAL_WINDOWS[windowKey(req)];
  const mins = toMinutes(guest.arrive);
  if(mins === null || mins < toMinutes(w[0]) || mins > toMinutes(w[1])){
    return { ok:false, why:'arrival time is outside the window for that option' };
  }
  return { ok:true, req };
}

/* ---------- availability ---------- */

async function availabilityPath(req){
  return req.kind === 'wholefair'
    ? 'public/wholefair/' + req.year + '/' + req.spot
    : 'public/availability/' + req.date + '/' + req.tier;
}

/* Counts confirmed reservations plus holds that have not expired. A hold is
   what stops two people buying the last space while both sit on Square's
   payment page. */
async function usedCount(env, req, now){
  const holds = (await dbGet(env, 'pending')) || {};
  const cutoff = now.getTime() - HOLD_MINUTES * 60000;
  let n = 0;
  Object.keys(holds).forEach(k=>{
    const h = holds[k];
    if(!h || h.status !== 'held') return;
    if((h.createdAt || 0) < cutoff) return;          // expired
    if(req.kind === 'wholefair'){
      if(h.kind === 'wholefair' && h.spot === req.spot && h.year === req.year) n++;
    }else if(h.kind === 'day' && h.date === req.date && h.tier === req.tier){
      n++;
    }
  });
  return n;
}

async function checkAvailable(env, req, now){
  if(req.kind === 'wholefair'){
    const state = await dbGet(env, 'public/wholefair/' + req.year + '/' + req.spot);
    if(state !== 'open') return 'that spot is no longer available';
    if(await usedCount(env, req, now) > 0) return 'someone is paying for that spot right now';
    return null;
  }
  const node = await dbGet(env, 'public/availability/' + req.date + '/' + req.tier);
  if(!node) return 'that option is not offered on that day';
  const cap = Number(node.cap) || 0;
  const sold = Number(node.sold) || 0;
  const held = await usedCount(env, req, now);
  if(sold + held >= cap) return 'that option is sold out for that day';
  return null;
}

/* ---------- Square ---------- */

function squareBase(env){
  return env.SQUARE_ENV === 'production'
    ? 'https://connect.squareup.com'
    : 'https://connect.squareupsandbox.com';
}

function describeOrder(req){
  if(req.kind === 'wholefair'){
    const label = { backtruck:'Back Truck', backgarden:'Back Garden', backdavid:'Back David' }[req.spot];
    return 'Whole fair - ' + label + ' - ' + req.year;
  }
  const tier = req.tier === 'standard'
    ? 'Standard (' + req.shift + ')'
    : (req.tier === 'late' ? 'Late Night' : 'All Day');
  return tier + ' - ' + req.date;
}

async function createPaymentLink(env, req, token){
  const parking = priceFor(req);
  const body = {
    idempotency_key: token,
    order: {
      location_id: env.SQUARE_LOCATION_ID,
      reference_id: token,                     // how the webhook finds this hold
      line_items: [
        {
          name: describeOrder(req),
          quantity: '1',
          base_price_money: { amount: parking * 100, currency: 'USD' },
          note: 'Includes Minnesota sales tax'
        },
        {
          name: 'Online booking fee',
          quantity: '1',
          base_price_money: { amount: BOOKING_FEE * 100, currency: 'USD' }
        }
      ]
    },
    checkout_options: {
      redirect_url: env.SUCCESS_URL,
      ask_for_shipping_address: false
    },
    pre_populated_data: {
      buyer_phone_number: '+1' + req.guest.phone
    },
    description: 'Text ' + (env.TEXT_NUMBER || '') +
                 ' when you are 10 minutes away. We meet you on the street.'
  };

  const res = await fetch(squareBase(env) + '/v2/online-checkout/payment-links', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + env.SQUARE_ACCESS_TOKEN,
      'Content-Type': 'application/json',
      'Square-Version': '2026-05-20'
    },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if(!res.ok) throw new Error('square: ' + JSON.stringify(data.errors || data));
  return data.payment_link;
}

async function squareGetOrder(env, orderId){
  const res = await fetch(squareBase(env) + '/v2/orders/' + orderId, {
    headers: {
      'Authorization': 'Bearer ' + env.SQUARE_ACCESS_TOKEN,
      'Square-Version': '2026-05-20'
    }
  });
  if(!res.ok) return null;
  const data = await res.json();
  return data.order || null;
}

/* Square signs (notification URL + raw body) with HMAC-SHA256 and sends the
   base64 result in x-square-hmacsha256-signature. If this does not match,
   the request did not come from Square and must be ignored. */
async function verifySquare(env, request, rawBody){
  const sent = request.headers.get('x-square-hmacsha256-signature') || '';
  if(!sent) return false;
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(env.SQUARE_WEBHOOK_SIGNATURE_KEY),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(env.SQUARE_WEBHOOK_URL + rawBody));
  let s = '';
  const arr = new Uint8Array(mac);
  for(let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return timingSafeEqual(btoa(s), sent);
}

/* ---------- handlers ---------- */

async function handleCheckout(env, request){
  const cors = corsHeaders(env, request);
  let raw;
  try{ raw = await request.json(); }
  catch(e){ return json({ error:'malformed request' }, 400, cors); }

  const now = new Date();
  const v = validate(raw, now);
  if(!v.ok) return json({ error: v.why }, 400, cors);
  const req = v.req;

  const unavailable = await checkAvailable(env, req, now);
  if(unavailable) return json({ error: unavailable }, 409, cors);

  const token = crypto.randomUUID();
  await dbPut(env, 'pending/' + token, {
    status: 'held',
    createdAt: now.getTime(),
    kind: req.kind,
    tier: req.tier || null,
    date: req.date || null,
    shift: req.shift || null,
    spot: req.spot || null,
    year: req.year || (req.date ? req.date.slice(0,4) : null),
    parking: priceFor(req),
    fee: BOOKING_FEE,
    total: priceFor(req) + BOOKING_FEE,
    guest: req.guest
  });

  let link;
  try{
    link = await createPaymentLink(env, req, token);
  }catch(e){
    await dbPatch(env, 'pending/' + token, { status:'failed', error: String(e).slice(0, 200) });
    return json({ error:'could not start checkout' }, 502, cors);
  }

  await dbPatch(env, 'pending/' + token, {
    paymentLinkId: link.id,
    orderId: link.order_id || null
  });
  return json({ url: link.url }, 200, cors);
}

async function handleWebhook(env, request){
  const rawBody = await request.text();
  if(!(await verifySquare(env, request, rawBody))){
    return new Response('bad signature', { status: 401 });
  }

  let evt;
  try{ evt = JSON.parse(rawBody); }
  catch(e){ return new Response('ok', { status: 200 }); }

  // Square retries on any non-2xx, so anything we cannot use returns 200.
  if(evt.type !== 'payment.updated') return new Response('ignored', { status: 200 });
  const payment = evt.data && evt.data.object && evt.data.object.payment;
  if(!payment || payment.status !== 'COMPLETED') return new Response('not completed', { status: 200 });

  let ref = payment.reference_id || null;
  if(!ref && payment.order_id){
    const order = await squareGetOrder(env, payment.order_id);
    ref = order && order.reference_id;
  }
  if(!ref) return new Response('no reference', { status: 200 });

  const hold = await dbGet(env, 'pending/' + ref);
  if(!hold) return new Response('unknown reference', { status: 200 });
  if(hold.status === 'confirmed') return new Response('already done', { status: 200 });

  const paidCents = (payment.amount_money && payment.amount_money.amount) || 0;
  if(paidCents < hold.total * 100){
    await dbPatch(env, 'pending/' + ref, { status:'underpaid', paidCents });
    return new Response('underpaid', { status: 200 });
  }

  const reservation = {
    id: ref,
    createdAt: hold.createdAt,
    confirmedAt: Date.now(),
    kind: hold.kind,
    tier: hold.tier,
    date: hold.date,
    shift: hold.shift,
    spot: hold.spot,
    year: hold.year,
    parking: hold.parking,
    fee: hold.fee,
    total: hold.total,
    guest: hold.guest,
    squarePaymentId: payment.id,
    squareOrderId: payment.order_id || null,
    status: 'confirmed'
  };
  await dbPut(env, 'reservations/' + ref, reservation);
  await dbPatch(env, 'pending/' + ref, { status:'confirmed' });

  if(hold.kind === 'wholefair'){
    await dbPut(env, 'public/wholefair/' + hold.year + '/' + hold.spot, 'sold');
  }else{
    const node = (await dbGet(env, 'public/availability/' + hold.date + '/' + hold.tier)) || {};
    await dbPatch(env, 'public/availability/' + hold.date + '/' + hold.tier, {
      cap: Number(node.cap) || 0,
      sold: (Number(node.sold) || 0) + 1
    });
  }
  return new Response('ok', { status: 200 });
}

/* Abandoned checkouts leave holds behind. Sweep them so the space frees up. */
async function expireHolds(env){
  const holds = (await dbGet(env, 'pending')) || {};
  const cutoff = Date.now() - HOLD_MINUTES * 60000;
  const updates = {};
  Object.keys(holds).forEach(k=>{
    const h = holds[k];
    if(h && h.status === 'held' && (h.createdAt || 0) < cutoff) updates[k + '/status'] = 'expired';
  });
  if(Object.keys(updates).length) await dbPatch(env, 'pending', updates);
  return Object.keys(updates).length;
}

export default {
  async fetch(request, env){
    const url = new URL(request.url);
    if(request.method === 'OPTIONS'){
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }
    if(request.method === 'POST' && url.pathname === '/checkout'){
      try{ return await handleCheckout(env, request); }
      catch(e){
        return json({ error:'server error' }, 500, corsHeaders(env, request));
      }
    }
    if(request.method === 'POST' && url.pathname === '/square-webhook'){
      try{ return await handleWebhook(env, request); }
      catch(e){
        // 500 makes Square retry, which is what we want on a transient fault.
        return new Response('error', { status: 500 });
      }
    }
    return new Response('not found', { status: 404 });
  },

  async scheduled(event, env){
    await expireHolds(env);
  }
};
