# Scam Report Hub

Simple web app for submitting and searching scam SMS, email, and call reports.

## Setup

1. Create a Postgres database.
2. Apply the schema:

```bash
psql "$DATABASE_URL" -f create_schema.psql
```

3. Install deps:

```bash
pip install -r requirements.txt
```

4. Run the app:

```bash
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

## Admin moderation

Set admin credentials in `.env`:

```
ADMIN_USER=admin
ADMIN_PASSWORD=change_me
```

Visit `/admin` and authenticate with HTTP Basic to flag or delete reports.

## Deployment (Neon + Render)

1. **Neon**: Create a Postgres database and copy the connection string.
2. **Set Render env vars**:
   - `DATABASE_URL` (use the Neon URL, with `sslmode=require`)
   - `ADMIN_USER`
   - `ADMIN_PASSWORD`
3. **Apply schema to Neon**:

```bash
psql "postgresql://USER:PASSWORD@HOST:PORT/DB?sslmode=require&channel_binding=require" -f create_schema.psql
```

4. **Render build/start**:

Build command:
```bash
pip install -r requirements.txt
```

Start command:
```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```
