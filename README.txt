WP Prospect Scanner fix

Replace ONLY app.py in your GitHub repo with the supplied app.py.

Main fix:
- FastAPI endpoints now await scan_site_async() directly.
- Batch endpoint now awaits scan_many().
- Removed the asyncio.run() call from request handlers, which caused:
  RuntimeError: asyncio.run() cannot be called from a running event loop

Keep requirements.txt, render.yaml, and scanner.py unchanged.
