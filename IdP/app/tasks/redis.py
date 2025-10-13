# redis.py
from redis.asyncio import Redis
from app.core.config import settings

async def get_redis():
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        yield redis
    finally:
        await redis.close()
