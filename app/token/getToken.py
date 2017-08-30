import base64
import hashlib
from flask import Blueprint, request
from db import db
import json
from models import yd_developer
import time
from ..common.constant import constant
from ..common.common import jsonEncode, LFLog, checkToken
import os
import random
import copy
import requests
import math

# md5加密
token = Blueprint('token', __name__)
seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=-"


# 随机加盐
def salt(seed, num):
    sa = []
    for i in range(num):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    return salt


# md5加密
def LF_Md5(str):
    m = hashlib.md5()
    m.update(str.encode('utf-8'))
    return m.hexdigest()


# 生成token
def createToken(loginName, expire):
    global seed
    randomToken = base64.b64encode(os.urandom(5)).decode('utf-8')
    timeStamp = int(time.time()) + expire
    preToken = randomToken + ':' + str(timeStamp) + ':' + loginName + ':'
    saltRange = 36 - len(preToken)
    if saltRange <= 0:
        saltRange = math.ceil(float(len(preToken)) / 3) * 3 - len(preToken)
    token = preToken + salt(seed, saltRange)
    token = base64.b64encode(token.encode('utf-8')).decode()
    return token


# 获取Token
@token.route('/getToken', methods=['GET'])
def getToken():
    if len(request.args) != 2:
        return jsonEncode('100000')
    loginName = request.args.get('loginName')
    loginPassword = request.args.get('loginPassword')
    if loginName == '' or loginPassword == '':
        return jsonEncode('100000')
    developer = yd_developer.query.filter(
        yd_developer.username == loginName.strip()).filter(
        yd_developer.password == LF_Md5(
            loginPassword.strip())).first()
    if developer is None:
        return jsonEncode('100015')
    if developer.token is not None and developer.isLogin == 1:
        return json.dumps({'code': '110009',
                           'Msg': constant['successCode']['110009'],
                           'token': developer.token},
                          ensure_ascii=False)
    token = createToken(loginName.strip(), constant['expireTime'])
    developer.token = token
    developer.isLogin = 1
    db.session.commit()
    constant['mySession'].setEx(
        token,
        loginName.strip(),
        constant['expireTime'])
    return json.dumps({'code': '110007',
                       'Msg': constant['successCode']['110007'],
                       'token': token},
                      ensure_ascii=False)


# 退出（包括，自身session清空和网络session的重置，如果登录，退出移动登录）
@token.route('/quitQuery', methods=['GET'])
def quitQuery():
    if len(request.args) != 1:
        return jsonEncode('100000')
    token = request.args.get('token')
    checkResult = checkToken(token)
    if checkResult is not True:
        LFLog(quitQuery.__name__ +
              '---------token的状态是:{}'.format(jsonEncode('100017')))
    selfHeaders = copy.deepcopy(constant['headers'])
    if token + '_isLogin' in constant['mySession'].keys(
            token) and constant['mySession'][token + '_isLogin'] == 1:
        playLoad = {'_': str(int(round(time.time() * 1000)))}
        selfHeaders['Referer'] = 'http://shop.10086.cn/i/?welcome=' + \
            str(int(round(time.time() * 1000)) - 1000)
        selfHeaders['User-Agent'] = constant['PCUA']
        response = constant['netSession'].get(constant['urls']['quitQuery'],
                                              params=playLoad,
                                              cookies=constant['mySession'][token + '_cookies'],
                                              headers=selfHeaders)
        # constant['mySession'][token + '_cookies'] = dict(constant['mySession'][token + '_cookies'],  **response.cookies.get_dict())
        LFLog(response.text)
    try:
        del constant['mySession'][token]
        constant['mySession'].delAllKeys(token)
    except Exception as error:
        LFLog(quitQuery.__name__ + '---------异常是:{}'.format(error))
        pass
    userInfo = base64.b64decode(token).decode()
    userInfoList = userInfo.split(':')
    developer = yd_developer.query.filter(
        yd_developer.username == userInfoList[2]).first()
    developer.token = None
    developer.isLogin = 0
    db.session.commit()
    constant['netSession'] = ''
    constant['netSession'] = requests.Session()
    return jsonEncode('110012')
