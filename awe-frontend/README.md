# AWE Frontend

React and TypeScript web client for AWE.

```bash
npm install
npm run dev
```

The frontend runs at `http://localhost:4000`. The Vite development server
proxies `/api` to the backend at `http://localhost:8001`.

## Browser E2E test

The Playwright suite runs against the local Docker Compose stack. From the
repository root, start the app with `docker compose up -d --build`. Install the
frontend dependencies and Chromium once, then run the browser test:

```bash
cd awe-frontend
npm ci
npx playwright install chromium
npm run test:e2e
```

The suite reads the ignored `../.env.e2e.local` file. Set `E2E_BASE_URL`
(default `http://localhost:4000`), `E2E_USERNAME`, and `E2E_PASSWORD` there.
The backend accepts that separate account when `AWE_E2E_USERNAME` and
`AWE_E2E_PASSWORD_HASH` are set in the ignored root `.env` file. Generate the
hash with `PYTHONPATH=awe-backend awe-backend/.venv/bin/python -m awe_backend.password`;
keep the password and hash out of Git. The test account
has the same access as the owner account, so use it only for trusted E2E runs.
