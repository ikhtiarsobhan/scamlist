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
