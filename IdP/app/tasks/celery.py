from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "worker",
    broker=settings.broker_url,
    backend=settings.result_backend
)

# celery_app.autodiscover_tasks(["app.core.tasks"])
celery_app.conf.update(
    task_routes={
        "core.tasks.*": {"queue": "default"},
    }
)

# 👇 Explicit import ensures registration
import app.core.tasks