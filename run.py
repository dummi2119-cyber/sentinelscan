"""Entry point: initialize routers and launch uvicorn."""
import os
import sys
import uvicorn

from app import main, pages, api
from app.main import app as application

# attach the page and API routers to the app
main.include([pages.router, api.router])


def main():
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(application, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
