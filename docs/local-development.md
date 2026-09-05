# Local development

1. Copy `.env.example` to `.env` and set `BTOS_SECRET_KEY` and `BTOS_DEV_PASSWORD`.
2. Install Python deps: `pip install -e ".[dev]"`
3. Start API: `python -m uvicorn app.main:app --app-dir services/api --port 8080`
4. Install web: `cd apps/web && npm install && npm run dev`
5. GET `http://127.0.0.1:8080/api/v1/health` must return `ai_required: false`
6. Run `pytest -q` before considering a change done
