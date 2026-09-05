Control-plane schema is created by SQLAlchemy metadata on API startup and by Alembic revision `0001_control_plane`.

Apply against the configured `BTOS_DATABASE_URL`:

```
python scripts/migrate.py
alembic upgrade head
```

Do not hand-edit production tables. Secrets stay in `.env.local`.
