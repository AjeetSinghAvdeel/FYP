import uvicorn
import os

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=os.getenv("FYP_BIND_HOST", "127.0.0.1"), port=8000, reload=True)
