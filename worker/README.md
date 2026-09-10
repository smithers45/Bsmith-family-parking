# Reservation worker — setup

This folder is the server-side half of the reservation system. The public page
at `/reserve/` cannot take money on its own: it holds no credentials and cannot
write to the database. This worker is the only thing that can, and it only
creates a booking when Square confirms payment with a valid signature.

Nothing here runs until you provide four credentials. Everything below is a
step only you can do — I have no access to your Square or Firebase accounts.

---

## What you need to collect

| Value | Where to get it | Secret? |
|---|---|---|
| Square access token | Square Developer dashboard → your app → Credentials | **yes** |
| Square location ID | Same page, Locations section | no |
| Square webhook signature key | Square Developer dashboard → Webhooks → your subscription | **yes** |
| Firebase service account JSON | Firebase Console → Project Settings → Service accounts → Generate new private key | **yes** |

The three secrets never go in a file. They are set with `wrangler secret put`
and stored encrypted by Cloudflare.

---

## Steps

### 1. Install and log in
```
npm install -g wrangler
wrangler login
```

### 2. Fill in `wrangler.toml`
Set `SQUARE_LOCATION_ID`. Leave `SQUARE_ENV = "sandbox"` for now — you want to
test with fake cards before real ones.

### 3. Deploy once to get your URL
```
wrangler deploy
```
Wrangler prints something like
`https://asbury-parking.yourname.workers.dev`. Put that into
`SQUARE_WEBHOOK_URL` in `wrangler.toml`, with `/square-webhook` on the end.

**This has to match exactly.** Square computes the signature over the
notification URL plus the request body, so a trailing slash or an `http` vs
`https` mismatch will make every webhook fail verification.

### 4. Set the secrets
```
wrangler secret put SQUARE_ACCESS_TOKEN
wrangler secret put SQUARE_WEBHOOK_SIGNATURE_KEY
wrangler secret put FIREBASE_SERVICE_ACCOUNT
```
For the last one, paste the entire contents of the service account JSON file
as a single line when prompted.

### 5. Register the webhook in Square
Square Developer dashboard → Webhooks → Add subscription.
- URL: your `/square-webhook` address
- API version: 2026-05-20
- Event: **`payment.updated`** (that is the only one this worker uses)

### 6. Tighten the database rules
Firebase Console → Realtime Database → Rules. Paste the contents of
`firebase-rules.json` and publish.

Your rules are currently `auth != null` on everything, which means any
signed-in user can read and write the whole database. After this change:
- `public/` — anyone can read, nobody can write
- `reservations/` — the family app can read, no browser can write
- `pending/` — invisible to everything except this worker
- `days/`, `adjustments/`, `occupancy/`, `goals/` — unchanged, family app only

The worker uses a service account, which bypasses rules entirely. That is why
it can still write.

### 7. Deploy again
```
wrangler deploy
```

### 8. Set the caps
Nothing is bookable until you say how many of each option exist per day.
In Firebase Console, under `public/availability`, for each fair date:

```
public/availability/2027-08-26/standard = { cap: 8,  sold: 0 }
public/availability/2027-08-26/late     = { cap: 6,  sold: 0 }
public/availability/2027-08-26/allday   = { cap: 3,  sold: 0 }
```

And the three whole-fair spots:
```
public/wholefair/2027/backtruck  = "open"
public/wholefair/2027/backgarden = "open"
public/wholefair/2027/backdavid  = "open"
```

**Set these deliberately low to begin with.** Every online booking is a space
you must hold empty, and on a busy Saturday an empty held space is a cash
customer you turned away. Caps are how you keep that under control.

### 9. Point the page at the worker
In `reserve/index.html`, set:
```js
const CHECKOUT_ENDPOINT = "https://asbury-parking.yourname.workers.dev/checkout";
```

### 10. Open the doors
In Firebase Console:
```
public/config = { open: true, year: "2027", textNumber: "651-329-0846" }
```

`open` is your kill switch. Set it to `false` from your phone and the site
stops selling immediately, without a deploy.

---

## Test before going live

With `SQUARE_ENV = "sandbox"`, use Square's test card `4111 1111 1111 1111`,
any future expiry, any CVV. Then check:

1. A booking appears under `reservations/` with the right price and the guest's
   details.
2. `public/availability/<date>/<tier>/sold` went up by one.
3. Booking the same option until the cap is reached makes the button read
   "Sold out for this day".
4. Starting a checkout and abandoning it leaves a `held` entry that flips to
   `expired` within 20 minutes and frees the space.

Then switch `SQUARE_ENV` to `production`, swap in the live token and signature
key, re-register the webhook against the production app, and deploy.

---

## What this worker deliberately does not trust

- **Prices sent by the browser.** It recomputes every price itself. A request
  claiming $1 for a whole-fair spot is rejected because the amount charged is
  worked out here, not received.
- **Dates.** It verifies the date really is one of the twelve fair days of the
  sellable year, using the same Labor Day rule as the pages.
- **Arrival times.** A Late Night booking claiming a 9am arrival is rejected.
- **The webhook itself.** Nothing is written until the HMAC signature matches.
  An unsigned or wrongly signed POST gets a 401 and is ignored.
- **The payment amount.** If Square reports less than the expected total, the
  hold is marked underpaid and no reservation is created.

## Known limitations, stated plainly

- **Holds are counted, not locked.** Two simultaneous requests for the last
  space could in principle both pass the check. At your volume this is very
  unlikely; if it ever matters, the fix is a transaction rather than a read.
- **Refunds are manual.** Issue them in the Square dashboard, then delete the
  reservation and decrement `sold` in Firebase. Automating this was not worth
  the complexity for a twelve-day season.
- **No confirmation email beyond Square's receipt.** Square emails the buyer;
  the arrival instructions ride along in the payment link description.
- **Sales tax is not itemised in Square.** Prices are tax-inclusive by design,
  so each order is a single line at the advertised price plus the booking fee.
  Your own records carry the tax split — worth confirming that suits your
  accountant.
