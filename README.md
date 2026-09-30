# Helpdesk (Netlify + Upstash Redis)
- **Requesters**: no login. Public form (picks a team) → ticket ID; track with the ID.
- **Team members**: separate logins per person, each belongs to one team; see only their team's tickets and logs.
- **Admin**: one login (env vars). Creates teams and logins, sees everything, deletes tickets/logs.

## Deploy
1. upstash.com → create Redis DB → copy REST URL + REST Token.
2. Push to GitHub → Netlify: Add new site → Import from Git.
3. Netlify env vars: `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, `AUTH_SECRET` (long random), `ADMIN_EMAIL`, `ADMIN_PASSWORD`.
4. Deploy. Staff login → Teams & logins → add teams, then add a login per member.

## Production checklist
- Use a strong `AUTH_SECRET` and admin password; never commit them.
- Add your custom domain in Netlify (HTTPS is automatic).
- Export the Activity log CSV monthly as a backup; Upstash data is the only copy.
