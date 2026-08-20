# TuffOS

TuffOS is a responsive web OS interface with a Node.js/Express backend, SQLite persistence, username sessions, Discord OAuth, browser workspace data, users and messaging APIs.

## Local development

Requirements: Node.js 20+

```bash
npm install
cp .env.example .env
npm run dev
```

Open `http://localhost:3000`.

## Discord OAuth setup

Create a Discord application and set its OAuth2 redirect URL to the value in `DISCORD_REDIRECT_URI`. Put the client ID and client secret in `.env`; never commit the real secret.

The backend uses Discord's authorization-code OAuth flow and requests only the `identify` scope for the TuffOS profile/avatar integration.

## Backend layout

- `backend/server.js` — Express server and REST API
- `backend/db.js` — SQLite schema and server-side sessions
- `data/tuffos.sqlite` — created automatically at runtime and ignored by Git
- `.env.example` — environment configuration template

## API foundation

- `GET /api/health`
- `GET /api/auth/me`
- `POST /api/auth/username`
- `GET /api/auth/discord`
- `GET /api/auth/discord/callback`
- `POST /api/auth/logout`
- `GET /api/users`
- `POST /api/conversations`
- `GET /api/conversations`
- `GET /api/conversations/:id/messages`
- `POST /api/conversations/:id/messages`
- `GET /api/tabs`
- `POST /api/tabs`
- `GET /api/favourites`
- `POST /api/favourites`

The frontend remains in the existing TuffOS folders so the current project can be upgraded incrementally rather than replaced wholesale.
