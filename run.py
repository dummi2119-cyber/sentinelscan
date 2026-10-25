"""Entry point: launch uvicorn.

The `app` object (app.main.app) already attaches the page and API routers at
import time, so this module only needs to import it and serve it.
"""
import os
import uvicorn

from app.main import app as application


def main():
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(application, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
