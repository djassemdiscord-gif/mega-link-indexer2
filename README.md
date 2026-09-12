# MEGA Link Indexer - Render

This version runs as a normal FastAPI application on Render using CPython.
It does not use Cloudflare Workers, Pyodide, Python Workers, or Cloudflare FFI.

## Deploy on Render

1. Put this project in a GitHub repository.
2. In Render, choose **New -> Web Service**.
3. Connect the GitHub repository.
4. Render should detect Python.
5. Build command:
   `pip install -r requirements.txt`
6. Start command:
   `uvicorn main:app --host 0.0.0.0 --port $PORT`
7. Choose the **Free** plan for testing.

## Local test

```bash
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Then open http://127.0.0.1:8000/

## Notes

The original MEGA AES implementation is retained because normal CPython supports
PyCryptodome correctly; the Cloudflare-specific Python Workers code is not used.
