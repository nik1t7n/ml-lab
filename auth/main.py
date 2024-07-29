from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from starlette.middleware.cors import CORSMiddleware

from src.router import router as auth_router

app = FastAPI(default_response_class=ORJSONResponse) # default_response_class=ORJSONResponse

origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth_router)
