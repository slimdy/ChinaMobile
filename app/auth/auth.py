import base64
from flask import Blueprint, current_app, request, Response
import json
import time
import copy
from ..common.constant import constant
from ..common.common import jsonEncode, checkToken, LFLog
import os
# flask 蓝本
allAuth = Blueprint('auth', __name__)
# 获得captchaCode cookie  否则无法得到个人信息


def getRdmdAndCaptchaCode(netSession, headers):
    netSession.get(constant['urls']['getRdmdAndCaptchaCode'], headers=headers)
    return netSession.cookies.get_dict()
# 检查电话号码是否为移动


def checkNum(userName, headers, token):
    playload = {'userName': userName}
    response = constant['netSession'].post(constant['urls']['checkNum'],
                                           data=playload,
                                           headers=headers,
                                           cookies=constant['mySession'][token + '_cookies'])
    if response.text == 'true':
        constant['mySession'][token +
                              '_cookies'] = dict(constant['mySession'][token +
                                                                       '_cookies'], **response.cookies.get_dict())
        return {'code': 1, }
    else:
        return {'code': 0, }
# 发送验证码


def sendRequestForVerifyTextCode(userName, headers, channelID, type, token):
    playload = {'userName': userName, 'type': type, 'channelID': channelID}
    response = constant['netSession'].post(constant['urls']['sendRequestForVerifyTextCode'],
                                           data=playload, headers=headers, cookies=constant['mySession'][token + '_cookies'])
    if not bool(int(response.text)):
        constant['mySession'][token +
                              '_cookies'] = dict(constant['mySession'][token +
                                                                       '_cookies'], **response.cookies.get_dict())
        return {'code': 1, 'cookies': response.cookies.get_dict()}
    else:
        return {'code': 0, }
# 获得jsessionid-echd-cpt-cmcc-jt和ssologinprovince cookie


def auth(artifact, assertAcceptURL, cookies, netSession):
    playload = {
        'backUrl': 'http://touch.10086.cn/i/mobile/home.html',
        'artifact': artifact}
    response = netSession.get(
        assertAcceptURL,
        params=playload,
        headers=constant['headers'],
        cookies=cookies)
    firstCookies = response.history[0].cookies.get_dict()
    secondCookies = response.cookies.get_dict()
    LFLog(auth.__name__ + '------第一次的cookie{}'.format(firstCookies))
    LFLog(auth.__name__ + '------第二次的cookie{}'.format(secondCookies))
    return dict(firstCookies, **secondCookies)
# 通过用户名给客户发送验证码


@allAuth.route('/giveBackTextCode', methods=['GET'])
def giveBackTextCode():
    if len(request.args) != 2:
        return jsonEncode('100000')
    token = request.args.get('token')
    userName = request.args.get('phoneNum')
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
    cookies = getRdmdAndCaptchaCode(
        constant['netSession'],
        headers=constant['headers'])
    if 'CaptchaCode' not in cookies.keys() and 'rdmdmd5' not in cookies.keys():
        return jsonEncode('100008')
    if userName == '':
        # return
        # json.dumps({'code':'100000','errorMsg':errorCode['100000']},ensure_ascii=False)
        return jsonEncode('100000')
    constant['mySession'][token + '_username'] = userName.strip()
    constant['mySession'][token + '_cookies'] = cookies
    isNum = checkNum(userName, constant['headers'], token)
    if not bool(int(isNum['code'])):
        del constant['mySession'][token + '_username']
        LFLog(giveBackTextCode.__name__ + '------{}'.format(isNum))
        return jsonEncode('100001')
    isSend = sendRequestForVerifyTextCode(
        userName,
        constant['headers'],
        constant['otherParams']['channelID'],
        constant['otherParams']['type'],
        token)
    if not bool(int(isSend['code'])):  # 2是短信下发已到达上限
        LFLog(giveBackTextCode.__name__ + '------{}'.format(isSend))
        return jsonEncode('100002')
    LFLog(giveBackTextCode.__name__ + '------{}'.format('发送成功'))
    return jsonEncode('110001')
# 通过随机短信码和服务密码，去移动进行验证


@allAuth.route('/authLogin', methods=['GET'])
def getArtifact():
    if len(request.args) != 3:
        return jsonEncode('100000')
    token = request.args.get('token')
    servicepassword = request.args.get('servicepassword')
    textCode = request.args.get('textCode')
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
    if servicepassword == '' or textCode == '':
        return jsonEncode('100000')
    if token + '_username' not in constant['mySession'].keys(token):
        return jsonEncode('100006')
    if token + '_cookies' not in constant['mySession'].keys(token):
        return jsonEncode('100007')
    constant['mySession'][token + '_servicepassword'] = servicepassword
    playload = {
        'accountType': constant['otherParams']['type'],
        'account': constant['mySession'][token + '_username'],
        'password': servicepassword,
        'pwdType': '01',
        'smsPwd': textCode,
        'inputCode': '',
        'backUrl': '',
        'rememberMe': 0,
        'channelID': constant['otherParams']['channelID'],
        'protocol': 'https:',
        'timestamp': str(int(round(time.time() * 1000)))
    }
    response = constant['netSession'].get(constant['urls']['getArtifact'],
                                          params=playload,
                                          headers=constant['headers'],
                                          cookies=constant['mySession'][token + '_cookies'])
    responseDic = json.loads(response.text)
    LFLog(getArtifact.__name__ + '------{}'.format(response.text))
    if 'artifact' in responseDic.keys() and 'assertAcceptURL' in responseDic.keys():
        constant['mySession'][token +
                              '_cookies'] = dict(constant['mySession'][token +
                                                                       '_cookies'], **response.cookies.get_dict())
        assertAcceptURL = responseDic['assertAcceptURL']
        artifact = responseDic['artifact']
        LFLog(getArtifact.__name__ +
              '------assertAcceptUrl:{}------artifact:{}'.format(assertAcceptURL, artifact))
        #authUrl = assertAcceptURL+'?backUrl=http://touch.10086.cn/i/mobile/home.html&artifact='+artifact
        cookie = auth(artifact,
                      assertAcceptURL,
                      constant['mySession'][token + '_cookies'],
                      constant['netSession'])
        LFLog(getArtifact.__name__ + '------登录权限认证cookies：{}'.format(cookie))
        if 'jsessionid-echd-cpt-cmcc-jt' in cookie.keys() and 'ssologinprovince' in cookie.keys():
            constant['mySession'][token + '_isLogin'] = 1
            constant['mySession'][token +
                                  '_cookies'] = dict(constant['mySession'][token +
                                                                           '_cookies'], **cookie)
            return jsonEncode('110002')
        else:
            constant['mySession'][token + '_isLogin'] = 0
            return jsonEncode('100005')
    else:
        del constant['mySession'][token + '_servicepassword']
        try:
            return jsonEncode('100003', realMsg=responseDic['desc'])
        except BaseException:
            return jsonEncode('100019')

# 临时身份验证


@allAuth.route('/temporaryPIAuth', methods=['GET'])
def authTemporaryID():
    if len(request.args) != 3:
        return jsonEncode('100000')
    token = request.args.get('token')
    randomCode = request.args.get('randomCode')
    randomImage = request.args.get('randomImage')
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
    if randomCode == '' or randomImage == '':
        return jsonEncode('100000')
    if token + '_username' not in constant['mySession'].keys(token):
        return jsonEncode('100006')
    if token + '_cookies' not in constant['mySession'].keys(token):
        return jsonEncode('100007')
    if token + '_servicepassword' not in constant['mySession'].keys(token):
        return jsonEncode('100014')
    servicePasswordBase64 = base64.b64encode(
        constant['mySession'][token + '_servicepassword'].encode(encoding='utf-8')).decode()
    randomCodeBase64 = base64.b64encode(
        randomCode.encode(encoding='utf-8')).decode()
    playLoad = {
        'pwdTempSerCode': servicePasswordBase64,
        'pwdTempRandCode': randomCodeBase64,
        'captchaVal': randomImage,
        '_': str(int(round(time.time() * 1000))),
    }
    response = constant['netSession'].get(constant['urls']['authTemporaryID'] +
                                          constant['mySession'][token +
                                                                '_username'], params=playLoad, headers=constant['headers'], cookies=constant['mySession'][token +
                                                                                                                                                          '_cookies'])
    try:
        result = response.text[4:].lstrip('(').rstrip(')')
        resultDic = json.loads(result)
        if resultDic['retCode'] == '000000':
            constant['mySession'][token +
                                  '_cookies'] = dict(constant['mySession'][token +
                                                                           '_cookies'], **response.cookies.get_dict())
            LFLog(authTemporaryID.__name__ +
                  '------临时身份验证完后的cookies{}'.format(constant['mySession'][token +
                                                                          '_cookies']))
            return jsonEncode('110004')
        else:
            return jsonEncode('100011', realMsg=resultDic['retMsg'])
    except BaseException:
        return jsonEncode('100011', realMsg=response.text)

# 发送临时身份验证码和图片
#@allAuth.route('/prepareAuth',methods=['GET'])


def prepareAuth():
    if len(request.args) != 1:
        return jsonEncode('100000')
    token = request.args.get('token')
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
    if token + '_username' not in constant['mySession'].keys(token):
        return jsonEncode('100006')
    if token + '_cookies' not in constant['mySession'].keys(token):
        return jsonEncode('100007')
    userName = constant['mySession'][token + '_username']
    selfHeaders = copy.deepcopy(constant['headers'])
    image = sendTemporaryIDRandomImage(constant['netSession'],
                                       constant['urls']['sendTemporaryIDRandomImage'],
                                       selfHeaders,
                                       constant['mySession'][token + '_cookies'],
                                       token)
    code = sendTemporaryIDRandomCode(constant['netSession'],
                                     constant['urls']['sendTemporaryIDRandomCode'],
                                     userName,
                                     selfHeaders,
                                     constant['mySession'][token + '_cookies'],
                                     token)
    if image is not False and code is True:
        return jsonEncode('110005', data=image)
    else:
        return jsonEncode('100012')
# 发送临时身份验证短信码


def sendTemporaryIDRandomCode(
        netSession,
        url,
        userName,
        headers,
        cookies,
        token):
    playLoad = {'_': str(int(round(time.time() * 1000)))}
    headers['referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    headers['user-agent'] = constant['PCUA']
    response = netSession.get(
        url + userName,
        params=playLoad,
        headers=headers,
        cookies=cookies)
    result = response.text[4:].lstrip('(').rstrip(')')
    resultDic = json.loads(result)
    if resultDic['retCode'] == '000000':
        constant['mySession'][token +
                              '_cookies'] = dict(constant['mySession'][token +
                                                                       '_cookies'], **response.cookies.get_dict())
        return True
    else:
        print(resultDic['retMsg'])
        return False
# 单独发送临时身份验证短信码


@allAuth.route('/getTemporaryRandomCode', methods=['GET'])
def getTemporaryRandomCode():
    if len(request.args) != 1:
        return jsonEncode('100000')
    token = request.args.get('token')
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
        # return json.dumps({'code': '100017', 'errorMsg':
        # errorCode['100017']}, ensure_ascii=False)
    if token + '_username' not in constant['mySession'].keys(token):
        return jsonEncode('100006')
        # return
        # json.dumps({'code':'100006','errorMsg':errorCode['100006']},ensure_ascii=False)
    if token + '_cookies' not in constant['mySession'].keys(token):
        return jsonEncode('100007')
        # return
        # json.dumps({'code':'100007','errorMsg':errorCode['100007']},ensure_ascii=False)
    playLoad = {'_': str(int(round(time.time() * 1000)))}
    selfHeaders = copy.deepcopy(constant['headers'])
    selfHeaders['referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    selfHeaders['user-agent'] = constant['PCUA']
    response = constant['netSession'].get(constant['urls']['sendTemporaryIDRandomCode'] +
                                          constant['mySession'][token +
                                                                '_username'], params=playLoad, headers=selfHeaders, cookies=constant['mySession'][token +
                                                                                                                                                  '_cookies'])
    result = response.text[4:].lstrip('(').rstrip(')')
    resultDic = json.loads(result)
    if resultDic['retCode'] == '000000':
        constant['mySession'][token +
                              '_cookies'] = dict(constant['mySession'][token +
                                                                       '_cookies'], **response.cookies.get_dict())
        return jsonEncode('110011')
    else:
        print(resultDic['retMsg'])
        return jsonEncode('100002')
# 单独发送验证图片


@allAuth.route('/getTemporaryRandomImage', methods=['GET'])
def getTemporaryRandomImage():
    if len(request.args) != 1:
        return jsonEncode('100000')
    token = request.args.get('token')
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
    if token + '_cookies' not in constant['mySession'].keys(token):
        return jsonEncode('100007')
    playLoad = {'t': '0.646509821274071'}
    selfHeaders = copy.deepcopy(constant['headers'])
    selfHeaders['referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    selfHeaders['user-agent'] = constant['PCUA']
    response = constant['netSession'].get(constant['urls']['sendTemporaryIDRandomImage'],
                                          params=playLoad,
                                          headers=selfHeaders,
                                          cookies=constant['mySession'][token + '_cookies'],
                                          stream=True)
    print(constant['netSession'].cookies.get_dict())
    if response.status_code == 200:
        try:
            verifyCodePath = current_app.config.get(
                'APP_ROOT')[0] + '/static/code-' + token + '.png'
            f = open(verifyCodePath, 'wb')
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)
                f.flush()
            f.close()
            constant['mySession'][token +
                                  '_cookies'] = dict(constant['mySession'][token +
                                                                           '_cookies'], **response.cookies.get_dict())
            with open(verifyCodePath, 'rb') as f:
                pngImage = f.read()
                os.remove(verifyCodePath)
                return Response(pngImage, mimetype='image/png')
        except Exception as e:
            print(str(e))
            return jsonEncode('100020')
    else:
        return jsonEncode('100020')
# 发送验证图片


def sendTemporaryIDRandomImage(netSession, url, headers, cookies, token):
    playLoad = {'t': '0.646509821274071'}
    headers['referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    headers['user-agent'] = constant['PCUA']
    response = netSession.get(
        url,
        params=playLoad,
        headers=headers,
        cookies=cookies,
        stream=True)
    try:
        verifyCodePath = current_app.config.get(
            'APP_ROOT')[0] + '/static/code-' + token + '.png'
        f = open(verifyCodePath, 'wb')
        for chunk in response.iter_content(chunk_size=1024):
            f.write(chunk)
            f.flush()
        f.close()
        constant['mySession'][token +
                              '_cookies'] = dict(constant['mySession'][token +
                                                                       '_cookies'], **response.cookies.get_dict())
        with open(verifyCodePath, 'rb') as f:
            imageStream = f.read()
            os.remove(verifyCodePath)
            return imageStream
    except Exception as e:
        print(str(e))
        return False
