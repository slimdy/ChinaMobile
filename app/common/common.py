import json
import base64
import time
from models import yd_developer, yd_userinfo, yd_payRecord, yd_THXQ
from db import db
from .constant import constant
import datetime
from config import config
# 查询输入的startTime，endTime是否合法


def checkTime(startTime, endTime):
    if startTime == '' or endTime == '':
        return False
    today = time.strftime("%Y%m%d")
    try:
        startTimeDateTime = changeTimeStrToDateTime(startTime)
        endTimeDateTime = changeTimeStrToDateTime(endTime)
        todayDateTime = changeTimeStrToDateTime(today)
        oneYearAgo = changeTimeStrToDateTime(str(int(today) - 10000))
        if startTimeDateTime >= endTimeDateTime:
            return False
        if startTimeDateTime <= todayDateTime and startTimeDateTime >= oneYearAgo:
            if endTimeDateTime <= todayDateTime and endTimeDateTime >= oneYearAgo:
                return True
        return False
    except BaseException:
        return False
# 字符串时间转化成datetime格式


def changeTimeStrToDateTime(timeStr):
    r = time.strptime(timeStr, '%Y%m%d')
    y, m, d = r[0:3]
    return datetime.datetime(y, m, d)


def checkToken(token):
    if token == '':
        return False
    try:
        userInfo = base64.b64decode(token).decode()
        userInfoList = userInfo.split(':')
        developer = yd_developer.query.filter(
            yd_developer.username == userInfoList[2]).first()
        if developer is None:
            LFLog('token中的用户名 数据库不存在')
            return False
        if developer.token == token:
            timeStamp = int(userInfoList[1])
            if timeStamp <= int(time.time()):
                developer.token = None
                developer.isLogin = 0
                db.session.commit()
                try:
                    constant['mySession'].delAllKeys(token)
                except BaseException:
                    pass
                LFLog('token过期')
                return False
            else:
                return True
        else:
            LFLog('token不存在于数据库')
            return False
    except Exception as error:
        LFLog('发生异常：' + str(error))
        return False
# jsonEncode


def jsonEncode(code, realMsg='', data=None,):
    errorCode = constant['errorCode']
    successCode = constant['successCode']
    if code[0:2] == '10':
        if realMsg != '':
            return json.dumps({'code': code,
                               'errorMsg': errorCode[code],
                               'realMsg': realMsg},
                              ensure_ascii=False)
        else:
            return json.dumps({'code': code, 'errorMsg': errorCode[code]},
                              ensure_ascii=False)
    else:
        if data is None:
            return json.dumps(
                {'code': code, 'Msg': successCode[code]}, ensure_ascii=False)
        else:
            return json.dumps(
                {'code': code, 'Msg': successCode[code], 'data': data}, ensure_ascii=False)

# 存储个人信息


def savePersonInfo(data):
    user = yd_userinfo()
    return user.saveData(data)
# 存储缴费记录


def savePayRecords(data):
    payRecord = yd_payRecord()
    return payRecord.saveData(data)
# 存储通话详单数据


def saveTHXDData(data):
    THXD = yd_THXQ()
    return THXD.saveData(data)
# LFLog


def LFLog(self, *args, sep=' ', end='\n', file=None):
    if config['default'].DEBUG:
        print(self, *args, sep=' ', end='\n', file=None)
