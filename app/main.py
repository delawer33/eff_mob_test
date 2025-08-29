import uvicorn
from fastapi import FastAPI

from app.api.v1.routers import router as v1_router

app = FastAPI()

app.include_router(v1_router)


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", reload=True)
