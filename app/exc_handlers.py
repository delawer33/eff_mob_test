from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

# def setup_exception_handlers(app):
#     @app.exception_handler(SQLAlchemyError)
#     async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
#         return JSONResponse(
#             status_code=500,
#             content={"detail": "Ошибка базы данных"}
#         )
    
#     @app.exception_handler(IntegrityError)
#     async def integrity_error_handler(request: Request, exc: IntegrityError):
#         return JSONResponse(
#             status_code=400,
#             content={"detail": "Нарушение целостности данных"}
#         )