from flask import Flask
from config import config
from db import db
import json
# def is_json(myjson):
#     try:
#         json.loads(myjson)
#     except ValueError:
#         return False
#     return True
# def isCache(rv):
#     if is_json(rv):
#         rvDict = json.loads(rv)
#         if rvDict['data'] is None:
#             return False
#         else:
#             return True
def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    db.init_app(app)
    from app.token.getToken import token as token_blueprint
    from app.auth.auth import allAuth as auth_blueprint
    from app.data.data import getData as data_blueprint
    app.register_blueprint(token_blueprint,url_prefix = '/token')
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    app.register_blueprint(data_blueprint, url_prefix='/data')
    return app
