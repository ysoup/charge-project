import config
import redis
db_redis = redis.StrictRedis(host=config.BACKEND_REDIS[0], port=config.BACKEND_REDIS[1], db=config.BACKEND_REDIS[2])
