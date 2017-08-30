# -*- coding:utf-8 -*-
from flask import Flask, session, url_for
from models import yd_developer
from db import db
from tools.RedisToSession import Session
# from tools.RedisToSession import conn
import config
import requests
import json
import base64
import time
import datetime
import os
import hashlib
# 创建项目
app = Flask(__name__)
app.config.from_object(config)
db.init_app(app)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
# 手机userAgent
mobileUA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1'
# 电脑userAgent
PCUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
# session flask的session 是写在客户端的
netSession = requests.session()
# redis实例
redisInstance = conn
# redisSession
mySession = Session()
# token过期时间
expireTime = 15 * 60
# 所有移动api
urls = {
    'getRdmdAndCaptchaCode': 'https://login.10086.cn/captchazh.htm?type=05',
    'checkNum': 'https://login.10086.cn/chkNumberAction.action',
    'sendRequestForVerifyTextCode': 'https://login.10086.cn/sendRandomCodeAction.action',
    'getNumArea': 'http://touch.10086.cn/i/v1/res/numarea/',
    'getPersonInfo': 'http://touch.10086.cn/i/v1/cust/info/',
    'getArtifact': 'https://login.10086.cn/login.htm',
    'getTHXDData': 'https://shop.10086.cn/i/v1/fee/detailbillinfojsonp/',
    'sendTemporaryIDRandomCode': 'https://shop.10086.cn/i/v1/fee/detbillrandomcodejsonp/',
    'sendTemporaryIDRandomImage': 'http://shop.10086.cn/i/authImg',
    'authTemporaryID': 'https://shop.10086.cn/i/v1/fee/detailbilltempidentjsonp/',
    'quitQuery': 'http://shop.10086.cn/i/v1/auth/userlogout',
    'getPaymentRecords': 'http://shop.10086.cn/i/v1/cust/his/'}
# 本项目错误映射
errorCode = {
    '100000': u'参数错误',
    '100001': u'非移动电话号码',
    '100002': u'验证码发送失败',
    '100003': u'获得assertAcceptURL，artifact失败',
    '100004': u'没有登录信息',
    '100005': u'cookies获取不全',
    '100006': u'无有效用户名',
    '100007': u'未登录,请完成之前登录步骤',
    '100008': u'rd和cc的session未写入',
    '100009': u'个人信息获取失败',
    '100010': u'号码信息获取失败',
    '100011': u'临时身份认证失败',
    '100012': u'短信验证码与图片验证码发送失败',
    '100013': u'获取通话详单失败',
    '100014': u'无有效服务密码',
    '100015': u'用户名或密码错误，请核实后重新输入',
    '100016': u'服务器错误',
    '100017': u'token验证失败',
    '100018': u'获取缴费记录失败'
}
# 成功代码映射
successCode = {
    '110001': u'发送成功，请等待接收',
    '110002': u'认证成功',
    '110003': u'获取成功',
    '110004': u'临时身份认证成功',
    '110005': u'短信验证码与图片验证码发送完毕，如未收到，请稍后刷新本页面',
    '110006': u'获取通话详单成功',
    '110007': u'获取token成功',
    '110008': u'获取缴费记录成功',
    '110009': u'token已存在'
}
# 其他可以汇编的参数
otherParams = {
    'channelID': '12014',
    'type': '01'
}
# 请求头
headers = {
    'accept': "application/json, text/javascript, */*; q=0.01",
    'accept-encoding': 'gzip,deflate,br',
    'accept-language': 'zh-CN, zh;q = 0.8',
    'Connection': 'keep-alive',
    # 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1',
    'user-agent': mobileUA,
    'referer': 'https://login.10086.cn/html/login/touch.html',
    'x-requested-With': 'XMLHttpRequest',
    'cache-control': "no-cache",
    'Upgrade-Insecure-Requests': '1',

}
# md5加密
# e10adc3949ba59abbe56e057f20f883e


def LF_Md5(str):
    m = hashlib.md5()
    m.update(str.encode('utf-8'))
    return m.hexdigest()
# 生成token


def createToken(loginName, expire):
    randomToken = base64.b64encode(os.urandom(24)).decode('utf-8')
    timeStamp = int(time.time()) + expire
    token = randomToken + ':' + str(timeStamp) + ':' + loginName
    token = base64.b64encode(token.encode('utf-8')).decode()
    if r'/' in token:
        token = token.replace(r'/', 'Lf')
    return token
# 检验token


def checkToken(token):
    if token == '':
        return False
    try:
        userInfo = base64.b64decode(token).decode()
        userInfoList = userInfo.split(':')
        developer = yd_developer.query.filter(
            yd_developer.username == userInfoList[2]).first()

        if developer is None:
            print('token中的用户名 数据库不存在')
            return False
        if developer.token == token:
            timeStamp = int(userInfoList[1])
            if timeStamp <= int(time.time()):
                developer.token = None
                developer.isLogin = 0
                db.session.commit()
                try:
                    mySession.delAllKeys(token)
                except BaseException:
                    pass
                print('过期')
                return False
            else:
                return True
        else:
            print('token不存在于数据库')
            return False
    except BaseException:
        print('发生异常')
        return False
# 获取Token


@app.route('/getToken/loginName/<loginName>/loginPassword/<loginPassword>')
def getToken(loginName, loginPassword):
    global redisInstance
    global expireTime
    if loginName == '' or loginPassword == '':
        # return json.dumps({'code': '100000', 'errorMsg':
        # errorCode['100000']}, ensure_ascii=False)
        return jsonEncode('100000')
    developer = yd_developer.query.filter(
        yd_developer.username == loginName.strip()).filter(
        yd_developer.password == LF_Md5(
            loginPassword.strip())).first()
    if developer is None and developer.isLogin == 0:
        # return json.dumps({'code': '100015', 'errorMsg':
        # errorCode['100015']}, ensure_ascii=False)
        return jsonEncode('100015')
    if developer.token is not None and developer.isLogin == 1:
        return json.dumps({'code': '110009',
                           'Msg': successCode['110009'],
                           'token': developer.token},
                          ensure_ascii=False)
    token = createToken(loginName.strip(), expireTime)
    developer.token = token
    developer.isLogin = 1
    db.session.commit()
    mySession.setEx(token, loginName.strip(), expireTime)
    return json.dumps({'code': '110007',
                       'Msg': successCode['110007'],
                       'token': token},
                      ensure_ascii=False)

# 获得captchaCode cookie  否则无法得到个人信息


def getRdmdAndCaptchaCode(netSession, headers):
    global urls
    netSession.get(urls['getRdmdAndCaptchaCode'], headers=headers)
    return netSession.cookies.get_dict()
# 检查电话号码是否为移动


def checkNum(userName, headers):
    global urls
    playload = {'userName': userName}
    response = requests.request(
        'POST',
        urls['checkNum'],
        data=playload,
        headers=headers)
    if response.text == 'true':
        cookies = response.cookies.get_dict()
        return {'code': 1, 'cookies': cookies}
    else:
        return {'code': 0, }
# 发送验证码


def sendRequestForVerifyTextCode(userName, headers, channelID, type):
    global urls
    playload = {'userName': userName, 'type': type, 'channelID': channelID}
    response = requests.request(
        'POST',
        urls['sendRequestForVerifyTextCode'],
        data=playload,
        headers=headers)
    print(response.text)
    if not bool(int(response.text)):
        return {'code': 1, 'cookies': response.cookies.get_dict()}
    else:
        return {'code': 0, }
# 获得jsessionid-echd-cpt-cmcc-jt和ssologinprovince cookie


def auth(artifact, assertAcceptURL, cookies, netSession):
    global headers
    playload = {
        'backUrl': 'http://touch.10086.cn/i/mobile/home.html',
        'artifact': artifact}
    response = netSession.get(
        assertAcceptURL,
        params=playload,
        headers=headers,
        cookies=cookies)
    response.encoding = 'utf-8'
    return netSession.cookies.get_dict()
# 移动的变态时间


def getTime():
    timeStamp = str(time.time()).split('.')[1][:3]
    return (time.strftime("%Y") +
            str(int(time.strftime('%m'))) +
            str(int(time.strftime('%d'))) +
            time.strftime('%H') +
            time.strftime('%M') +
            time.strftime('%S') +
            timeStamp)
# 获得手机号的信息


def getNumArea(netSession, cookies, headers, token):
    global urls
    getNumAreaUrl = urls['getNumArea'] + mySession[token + '_username']
    playload = {'time': getTime(), 'channel': '02'}
    response = netSession.get(
        getNumAreaUrl,
        params=playload,
        cookies=cookies,
        headers=headers)
    mySession[token + '_cookies'] = netSession.cookies.get_dict()
    return response.text
# 获得个人信息（包括手机号信息）


@app.route('/getPersonInfo/token/<token>')
def getPersonInfo(token):
    global netSession
    global successCode
    global errorCode
    global headers
    global urls
    checkResult = checkToken(token)
    if checkResult is not True:
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
        return jsonEncode('100017')
    if token + '_username' not in mySession.keys(token):
        # return
        # json.dumps({'code':'100006','errorMsg':errorCode['100006']},ensure_ascii=False)
        return jsonEncode('100006')
    if token + '_cookies' not in mySession.keys(token):
        # return
        # json.dumps({'code':'100007','errorMsg':errorCode['100007']},ensure_ascii=False)
        return jsonEncode('100007')
    getPInfoUrl = urls['getPersonInfo'] + mySession[token + '_username']
    if mySession[token + '_isLogin'] and token + \
            '_cookies' in mySession.keys(token):
        playload = {'time': getTime(), 'channel': '02'}
        response = netSession.get(getPInfoUrl,
                                  params=playload,
                                  headers=headers,
                                  cookies=mySession[token + '_cookies'])
        response.encoding = 'utf-8'
        pInfo = json.loads(response.text)
        if 'retCode' not in pInfo.keys() and pInfo['reCode'] != '000000':
            # return
            # json.dumps({'code':'100009','errorMsg':errorCode['100009'],'realMsg':response.text},ensure_ascii=False)
            return jsonEncode('100009', realMsg=response.text)
        numInfoText = getNumArea(
            netSession, mySession[token + '_cookies'], headers, token)
        numInfo = json.loads(numInfoText)
        if 'retCode' not in numInfo.keys() and numInfo['reCode'] != '000000':
            # return
            # json.dumps({'code':'100010','errorMsg':errorCode['100010'],'realMsg':numInfoText},ensure_ascii=False)
            return jsonEncode('100010', realMsg=numInfoText)
        personInfo = dict(pInfo['data'], **numInfo['data'])
        # return
        # json.dumps({'code':'110003','Msg':successCode['110003'],'data':personInfo},ensure_ascii=False)
        return jsonEncode('110003', data=personInfo)
    else:
        # return
        # json.dumps({'code':'100007','errorMsg':errorCode['100007']},ensure_ascii=False)
        return jsonEncode('100007')
# 退出（包括，自身session清空和网络session的重置，如果登录，退出移动登录）


@app.route('/quitQuery/token/<token>')
def quitQuery(token):
    global headers
    global PCUA
    global errorCode
    global netSession
    global account
    selfHeaders = headers
    checkResult = checkToken(token)
    if checkResult is not True:
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
        return jsonEncode('100017')
    if token + \
            '_isLogin' in mySession.keys(token) and mySession[token + '_isLogin'] == 1:
        playLoad = {'_': str(int(round(time.time() * 1000)))}
        selfHeaders['Referer'] = 'http://shop.10086.cn/i/?welcome=' + \
            str(int(round(time.time() * 1000)) - 1000)
        selfHeaders['User-Agent'] = PCUA
        response = netSession.get(urls['quitQuery'],
                                  params=playLoad,
                                  cookies=mySession[token + '_cookies'],
                                  headers=selfHeaders)
        print(response.text)
    #mainKey = base64.b64encode(token.encode('utf-8')).decode()
    del mySession[token]
    mySession.delAllKeys(token)
    userInfo = base64.b64decode(token).decode()
    userInfoList = userInfo.split(':')
    developer = yd_developer.query.filter(
        yd_developer.username == userInfoList[2]).first()
    developer.token = ''
    developer.isLogin = 0
    db.session.commit()
    netSession = ''
    netSession = requests.session()
    return '退出成功'
# 通过用户名给客户发送验证码


@app.route('/giveBackTextCode/token/<token>/phoneNum/<userName>')
def giveBackTextCode(token, userName):
    global headers
    global errorCode
    global successCode
    global otherParams
    global netSession
    checkResult = checkToken(token)
    if checkResult is not True:
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
        return jsonEncode('100017')
    cookies = getRdmdAndCaptchaCode(netSession, headers=headers)
    if 'CaptchaCode' not in cookies.keys() and 'rdmdmd5' not in cookies.keys():
        # return json.dumps({'code': '100008', 'errorMsg':
        # errorCode['100008']}, ensure_ascii=False)
        return jsonEncode('100008')
    if userName == '':
        # return
        # json.dumps({'code':'100000','errorMsg':errorCode['100000']},ensure_ascii=False)
        return jsonEncode('100000')
    mySession[token + '_username'] = userName.strip()
    mySession[token + '_cookies'] = netSession.cookies.get_dict()
    isNum = checkNum(userName, headers)
    if not bool(int(isNum['code'])):
        del mySession[token + '_username']
        # return
        # json.dumps({'code':'100001','errorMsg':errorCode['100001']},ensure_ascii=False)
        return jsonEncode('100001')

    isSend = sendRequestForVerifyTextCode(
        userName,
        headers,
        otherParams['channelID'],
        otherParams['type'])

    if not bool(int(isSend['code'])):  # 2是短信下发已到达上限
        # return
        # json.dumps({'code':'100002','errorMsg':errorCode['100002']},ensure_ascii=False)
        return jsonEncode('100002')
    # return
    # json.dumps({'code':'110001','Msg':successCode['110001']},ensure_ascii=False)
    return jsonEncode('110001')
# 通过随机短信码和服务密码，去移动进行验证


@app.route(
    '/authLogin/token/<token>/servicePassword/<servicepassword>/textCode/<textCode>')
def getArtifact(token, servicepassword, textCode):
    global errorCode
    global successCode
    global headers
    global otherParams
    global netSession
    global urls
    checkResult = checkToken(token)
    if checkResult is not True:
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
        return jsonEncode('100017')
    if servicepassword == '' or textCode == '':
        return jsonEncode('100000')
        # return json.dumps({'code':'100000','errorMsg':errorCode['100000']})
    if token + '_username' not in mySession.keys(token):
        return jsonEncode('100006')
        # return
        # json.dumps({'code':'100006','errorMsg':errorCode['100006']},ensure_ascii=False)
    if token + '_cookies' not in mySession.keys(token):
        return jsonEncode('100007')
        # return
        # json.dumps({'code':'100007','errorMsg':errorCode['100007']},ensure_ascii=False)
    mySession[token + '_servicepassword'] = servicepassword
    playload = {
        'accountType': otherParams['type'],
        'account': mySession[token + '_username'],
        'password': servicepassword,
        'pwdType': '01',
        'smsPwd': textCode,
        'inputCode': '',
        'backUrl': '',
        'rememberMe': 0,
        'channelID': otherParams['channelID'],
        'protocol': 'https:',
        'timestamp': str(int(round(time.time() * 1000)))
    }
    response = netSession.get(
        urls['getArtifact'],
        params=playload,
        headers=headers)
    responseDic = json.loads(response.text)
    if 'artifact' in responseDic.keys() and 'assertAcceptURL' in responseDic.keys():

        mySession[token + '_cookies'] = netSession.cookies.get_dict()
        assertAcceptURL = responseDic['assertAcceptURL']
        artifact = responseDic['artifact']
        authUrl = assertAcceptURL + \
            '?backUrl=http://touch.10086.cn/i/mobile/home.html&artifact=' + artifact
        print(authUrl)
        print(netSession.cookies.get_dict())
        cookie = auth(artifact, assertAcceptURL,
                      mySession[token + '_cookies'], netSession)
        if 'jsessionid-echd-cpt-cmcc-jt' in cookie.keys() and 'ssologinprovince' in cookie.keys():
            print(netSession.cookies.get_dict())
            mySession[token + '_isLogin'] = 1
            mySession[token + '_cookies'] = cookie
            # return
            # json.dumps({'code':'110002','Msg':successCode['110002'],'realMsg':responseDic['desc']},ensure_ascii=False)
            return jsonEncode('110002')
        else:
            mySession[token + '_isLogin'] = 0
            # return json.dumps({'code': '100005', 'errorMsg':
            # errorCode['100005']},ensure_ascii=False)
            return jsonEncode('100005')
    else:
        del mySession[token + '_servicepassword']
        return jsonEncode('100003', realMsg=responseDic['desc'])
        # return
        # json.dumps({'code':'100003','errorMsg':errorCode['100003'],'realMsg':responseDic['desc']},ensure_ascii=False)

# 临时身份验证


@app.route(
    '/temporaryPIAuth/token/<token>/randomCode/<randomCode>/randomImage/<randomImage>')
def authTemporaryID(token, randomCode, randomImage):
    global netSession
    global headers
    global PCUA
    global successCode
    global errorCode
    checkResult = checkToken(token)
    if checkResult is not True:
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
        return jsonEncode('100017')
    if randomCode == '' or randomImage == '':
        return jsonEncode('100000')
        # return json.dumps({'code': '100000', 'errorMsg':
        # errorCode['100000']}, ensure_ascii=False)
    if token + '_username' not in mySession.keys(token):
        return jsonEncode('100006')
        # return
        # json.dumps({'code':'100006','errorMsg':errorCode['100006']},ensure_ascii=False)
    if token + '_cookies' not in mySession.keys(token):
        return jsonEncode('100007')
        # return
        # json.dumps({'code':'100007','errorMsg':errorCode['100007']},ensure_ascii=False)
    if token + '_servicepassword' not in mySession.keys(token):
        return jsonEncode('100014')
        # return json.dumps({'code': '100014', 'errorMsg':
        # errorCode['100014']}, ensure_ascii=False)
    servicePasswordBase64 = base64.b64encode(
        mySession[token + '_servicepassword'].encode(encoding='utf-8')).decode()
    randomCodeBase64 = base64.b64encode(
        randomCode.encode(encoding='utf-8')).decode()
    playLoad = {
        'pwdTempSerCode': servicePasswordBase64,
        'pwdTempRandCode': randomCodeBase64,
        'captchaVal': randomImage,
        '_': str(int(round(time.time() * 1000))),
    }
    response = netSession.get(urls['authTemporaryID'] + mySession[token + '_username'],
                              params=playLoad, headers=headers, cookies=mySession[token + '_cookies'])
    #null({"data": null, "retCode": "000000", "retMsg": "认证成功!", "sOperTime": null})
    try:
        result = response.text[4:].lstrip('(').rstrip(')')
        resultDic = json.loads(result)
        if resultDic['retCode'] == '000000':
            mySession[token + '_cookies'] = netSession.cookies.get_dict()
            return jsonEncode('110004')
            # return json.dumps({'code': '110004', 'Msg':
            # successCode['110004'],'realMsg':resultDic['retMsg']},
            # ensure_ascii=False)
        else:
            return jsonEncode('100011', realMsg=resultDic['retMsg'])
            # return json.dumps({'code': '100011', 'errorMsg':
            # errorCode['100011'],'realMsg':resultDic['retMsg']},
            # ensure_ascii=False)
    except BaseException:
        return jsonEncode('100011', realMsg=response.text)
        # return json.dumps({'code': '100011', 'errorMsg': errorCode['100011'],
        # 'realMsg': response.text},ensure_ascii=False)

# 发送临时身份验证码和图片


@app.route('/prepareAuth/token/<token>')
def prepareAuth(token):
    global urls
    global headers
    global netSession
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
    if token + '_username' not in mySession.keys(token):
        return jsonEncode('100006')
        # return
        # json.dumps({'code':'100006','errorMsg':errorCode['100006']},ensure_ascii=False)
    if token + '_cookies' not in mySession.keys(token):
        return jsonEncode('100007')
        # return
        # json.dumps({'code':'100007','errorMsg':errorCode['100007']},ensure_ascii=False)
    userName = mySession[token + '_username']
    code = sendTemporaryIDRandomCode(netSession,
                                     urls['sendTemporaryIDRandomCode'],
                                     userName,
                                     headers,
                                     mySession[token + '_cookies'])
    image = sendTemporaryIDRandomImage(netSession,
                                       urls['sendTemporaryIDRandomImage'],
                                       headers,
                                       mySession[token + '_cookies'])
    if code is True and image is True:
        # return json.dumps({'code': '110005', 'Msg':
        # successCode['110005'],},ensure_ascii=False)
        return jsonEncode('110005')
    else:
        # return json.dumps({'code': '100012', 'errorMsg':
        # errorCode['100012'],},ensure_ascii=False)
        return jsonEncode('100012')
# 发送临时身份验证短信码


def sendTemporaryIDRandomCode(netSession, url, userName, headers, cookies):
    global PCUA
    playLoad = {'_': str(int(round(time.time() * 1000)))}
    headers['referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    headers['user-agent'] = PCUA
    response = netSession.get(
        url + userName,
        params=playLoad,
        headers=headers,
        cookies=cookies)
    result = response.text[4:].lstrip('(').rstrip(')')
    resultDic = json.loads(result)
    if resultDic['retCode'] == '000000':
        return True
    else:
        print(resultDic['retMsg'])
        return False
# 发送验证图片


def sendTemporaryIDRandomImage(netSession, url, headers, cookies):
    global PCUA
    playLoad = {'t': '0.646509821274071'}
    headers['referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    headers['user-agent'] = PCUA
    response = netSession.get(
        url,
        params=playLoad,
        headers=headers,
        cookies=cookies,
        stream=True)
    # print(response.text)
    try:
        verifyCodePath = APP_ROOT + '/static/code.png'
        f = open(verifyCodePath, 'wb')
        for chunk in response.iter_content(chunk_size=1024):
            f.write(chunk)
            f.flush()
        f.close()
        return True
    except Exception as e:
        print(str(e))
        return False

 # 获取详单数据


def getTHXDData(url, netSession, headers, timeStr, curor, step, token):
    playLoad = {
        'curCuror': curor,
        'qryMonth': timeStr,
        'step': step,
        'billType': '02',
        '_': str(int(round(time.time() * 1000)) + 1000)
    }
    response = netSession.get(url + mySession[token + '_username'],
                              params=playLoad,
                              headers=headers,
                              cookies=mySession[token + '_cookies'])
    try:
        resultStr = response.text[4:].lstrip('(').rstrip(')')
        result = json.loads(resultStr)
        if result['retCode'] != '000000':
            print(result['retMsg'])
            return {'data': None, 'msg': result['retMsg']}
        else:
            return {'data': result, 'msg': 'success'}
    except BaseException:
        print(response.text)
        return {'data': None, 'msg': response.text}
# 获得近六个月的通话详单数据


@app.route('/getTHXD/token/<token>')
def getAllTHXDData(token):
    global headers
    global urls
    global PCUA
    global errorCode
    global successCode
    checkResult = checkToken(token)
    if checkResult is not True:
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
        return jsonEncode('100017')
    if token + '_username' not in mySession.keys(token):
        return jsonEncode('100006')
        # return
        # json.dumps({'code':'100006','errorMsg':errorCode['100006']},ensure_ascii=False)
    if token + '_cookies' not in mySession.keys(token):
        return jsonEncode('100007')
        # return
        # json.dumps({'code':'100007','errorMsg':errorCode['100007']},ensure_ascii=False)
    thisHeaders = headers
    thisHeaders['referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    thisHeaders['user-agent'] = PCUA
    currentTime = int(time.strftime('%Y%m'))
    timeList = []
    for i in range(6):
        timeList .append(str(currentTime - i))
    allData = {}
    errMsg = {}
    for item in timeList:
        result = getTHXDData(
            urls['getTHXDData'],
            netSession,
            thisHeaders,
            item,
            1,
            500,
            token)
        if result['data'] is not None:
            if int(result['data']['totalNum']) > 500:
                moreData = getTHXDData(
                    urls['getTHXDData'], netSession, thisHeaders, item, 501, int(
                        result['data']['totalNum']) - 500)
                if moreData['data'] is not None:
                    result['data']['data'].extend(moreData['data']['data'])
            allData[item] = result['data']['data']
        else:
            errMsg[item] = result['msg']
    if allData == {}:
        return jsonEncode('100013', realMsg=str(errMsg))
        # return
        # json.dumps({'code':'100013','data':allData,'errorMsg':errorCode['100013'],'realMsg':errMsg},ensure_ascii=False)
    else:
        return jsonEncode('110006', data=allData)
        # return json.dumps({'code':'110006','data':allData,'Msg':successCode['110006']},ensure_ascii=False)
# 号码（仅限移动 归属地查询）


def getMobileTelSegment():
    pass
# 缴费记录查询
# http://shop.10086.cn/i/v1/cust/his/13919856898?startTime=20170801&endTime=20170811&_=1502414463510


@app.route(
    '/getPaymentRecords/token/<token>/startTime/<startTime>/endTime/<endTime>')
def getPaymentRecords(token, startTime, endTime):
    global urls
    global headers
    global errorCode
    global successCode
    global netSession
    global mySession
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
    if token + '_username' not in mySession.keys(token):
        return jsonEncode('100006')
        # return json.dumps({'code': '100006', 'errorMsg':
        # errorCode['100006']}, ensure_ascii=False)
    if token + '_cookies' not in mySession.keys(token):
        return jsonEncode('100007')
        # return json.dumps({'code': '100007', 'errorMsg':
        # errorCode['100007']}, ensure_ascii=False)
    if checkTime(startTime, endTime) is False:
        return jsonEncode('100000')
        # return json.dumps({'code': '100000', 'errorMsg':
        # errorCode['100000']}, ensure_ascii=False)
    playLoad = {'startTime': startTime, 'endTime': endTime,
                '_': str(int(round(time.time() * 1000)))}
    selfHeaders = headers
    selfHeaders['Referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    selfHeaders['User-Agent'] = PCUA
    response = netSession.get(urls['getPaymentRecords'] + mySession[token + '_username'],
                              params=playLoad, headers=selfHeaders, cookies=mySession[token + '_cookies'])
    responseDict = json.loads(response.text)
    if responseDict['retCode'] == '000000':
        return jsonEncode('110008', data=responseDict['data'])
        # return json.dumps({'code': '110008', 'Msg':
        # successCode['110008'],'data':responseDict['data']},
        # ensure_ascii=False)
    else:
        return jsonEncode('100018', realMsg=responseDict['retMsg'])
        # return json.dumps({'code': '100018', 'errorMsg': errorCode['100018'],'realMsg':responseDict['retMsg']}, ensure_ascii=False)
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
# jsonEncode


def jsonEncode(code, realMsg='', data=None,):
    global errorCode
    global successCode
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


# 开启项目
if __name__ == '__main__':
    app.run()
