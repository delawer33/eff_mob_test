from fastapi import APIRouter

from .auth import router as auth_router
from .products import router as product_router
from .permissions import router as permission_router
from .role import router as role_router

router = APIRouter(prefix="/api/v1")

router.include_router(auth_router)
router.include_router(product_router)
router.include_router(permission_router)
router.include_router(role_router)
