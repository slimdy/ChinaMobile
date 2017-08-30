import os


class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    APP_ROOT = os.path.dirname(os.path.abspath(__file__)),

    @staticmethod
    def init_app(app):
        pass
# 配置开发环境


class DevelopmentConfig(Config):
    DEBUG = True
    HOSTNAME = '127.0.0.1'
    PORT = '5432'
    DATABASE = 'test'
    USERNAME = 'root'
    PASSWORD = 'root'
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://{}:{}@{}:{}/{}'.format(
        USERNAME, PASSWORD, HOSTNAME, PORT, DATABASE)
    REDISHOST = '127.0.0.1'
    REDISPORT = 6379
# 配置生产环境


class ProductionConfig(Config):
    DEBUG = False
    HOSTNAME = ''
    PORT = ''
    DATABASE = ''
    USERNAME = ''
    PASSWORD = ''
    REDISHOST = ''
    REDISPORT = ''
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://{}:{}@{}:{}/{}'.format(
        USERNAME, PASSWORD, HOSTNAME, PORT, DATABASE)


# 一般改默认的
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
