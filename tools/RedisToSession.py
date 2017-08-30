import redis
import pickle
from config import config
# 连接redis


class Session:
    pool = redis.ConnectionPool(
        host=config['default'].REDISHOST,
        port=config['default'].REDISPORT)
    conn = redis.Redis(connection_pool=pool)
    # Session类似于字典的set方法

    def __setitem__(self, key, value):
        """
        :param key: session信息中的key
        :param value: 对应的Value
        """
        pickleValue = pickle.dumps(value,)
        self.conn.set(key, pickleValue)
    # Session类似于字典的get方法

    def __getitem__(self, item):
        """
        :param item: Session信息中对应的Key
        :return: 获取的Session信息
        """
        # 获取对应的数据
        ResultData = self.conn.get(item)

        result = pickle.loads(ResultData)
        return result

    # Session类似于字典的del方法
    def __delitem__(self, key):
        """
        :param key: 要删除的Key
        """
        self.conn.delete(key)
    # 所有键

    def keys(self, token):
        # 获取Session中所有的信息，仅用于测试
        SessionData = self.conn.keys(token + '*')
        keys = [item.decode() for item in SessionData]
        return keys
    # 设置有效期键值

    def setEx(self, key, value, ex):
        self.conn.setex(key, value, ex)
    # 删除所有相关键

    def delAllKeys(self, token):
        keys = self.conn.keys(token + '*')
        self.conn.delete(*keys)
