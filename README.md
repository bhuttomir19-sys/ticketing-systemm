# Helpdesk (Netlify)
- **Requesters**: no login. Public form → ticket ID; track with ticket ID.
- **Team**: no login. Names added by admin, tickets assigned to them.
- **Admin**: the only login. Manages everything, sees activity log / CSV.

## Deploy
1. Create a free Redis DB at upstash.com → copy the **REST URL** and **REST Token**.
2. Push this folder to GitHub → Netlify: Add new site → Import from Git (settings are read from netlify.toml).
3. Site configuration → Environment variables:
   `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, `AUTH_SECRET` (long random), `ADMIN_EMAIL`, `ADMIN_PASSWORD`.
4. Deploys → Trigger deploy. Open the site → "Admin login".
