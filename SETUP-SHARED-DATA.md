# Setting up shared data (so you and your wife see the same info)

This app now stores its data in a free Firebase Realtime Database instead of
only on one phone. You need to create your own free Firebase project (takes
about 5 minutes) and paste a small config snippet into index.html.

## 1. Create a free Firebase project
1. Go to https://console.firebase.google.com and sign in with any Google account.
2. Click "Add project," give it any name (e.g. "asbury-parking"), and finish
   the wizard. You can turn off Google Analytics — you don't need it.

## 2. Create the Realtime Database
1. In the left sidebar, go to Build → Realtime Database.
2. Click "Create Database."
3. Pick any region close to you.
4. Choose "Start in test mode" for now.

## 3. Open up the access rules (so both phones can read/write)
1. Still in Realtime Database, click the "Rules" tab.
2. Replace the contents with:
   ```json
   {
     "rules": {
       ".read": "auth != null",
       ".write": "auth != null"
     }
   }
   ```
3. Click "Publish."

   This requires anyone reading or writing data to be signed in — paired
   with the password screen set up below, this is what actually protects
   your data (a password check in the app's own code wouldn't, since
   anyone could view the page source and bypass it).

## 3b. Set up the app password
1. In the left sidebar, go to Build → Authentication.
2. Click "Get started."
3. Under "Sign-in method," enable "Email/Password."
4. Go to the "Users" tab, click "Add user."
5. For the email, enter exactly: `family@asbury-parking.app`
   (this is just an account label the app expects — it doesn't need to be
   a real inbox, and it's not secret, only the password is).
6. For the password, choose whatever you and your wife want to share.
7. Click "Add user."

Both of you will use this same password to unlock the app. If you ever
want to change it, come back to this Users tab, click the user, and reset
the password there.

## 4. Get your config snippet
1. Click the gear icon (top left) → "Project settings."
2. Scroll down to "Your apps" and click the </> (web) icon.
3. Give it any nickname, click "Register app." Skip the hosting step.
4. You'll see a code block with a `firebaseConfig` object — copy the four
   values: apiKey, authDomain, databaseURL, projectId.

## 5. Paste them into index.html
Near the top of the `<script>` tag in index.html, find this block:

```js
const firebaseConfig = {
  apiKey: "PASTE_YOUR_API_KEY_HERE",
  authDomain: "PASTE_YOUR_PROJECT.firebaseapp.com",
  databaseURL: "https://PASTE_YOUR_PROJECT-default-rtdb.firebaseio.com",
  projectId: "PASTE_YOUR_PROJECT"
};
```

Replace each placeholder with your real values, then save the file.

## 6. Upload and test
1. Upload the updated index.html to your existing host (GitHub Pages,
   Netlify, etc.), overwriting the old one.
2. Open the site on your phone. The first time it loads, it automatically
   copies any parking data you already had saved locally up into Firebase
   (you'll see a brief "Existing data moved to shared storage" toast).
3. Open the same URL on your wife's phone — she should see the exact same
   data. Anything either of you logs from now on shows up for both.

## Notes
- With the Email/Password sign-in and locked-down rules above, the app is
  now genuinely password-protected — the password is checked by Firebase's
  servers, not just by the app's own code, so it can't be bypassed by
  viewing the page source.
- Each phone needs an internet connection to log in the first time. After
  that, staying signed in doesn't require constant internet, but loading
  or saving parking data still does.
- If you're logging a car with no signal, the log button will show a
  "could not save" message — just try again once you have a bit of signal.
- The free Firebase tier is far more than enough for this — you'd need to
  be doing thousands of times the traffic of a two-house parking operation
  to hit any limit.
