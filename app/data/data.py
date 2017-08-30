from flask import Blueprint, request
import json
import time
import copy
import traceback
from ..common.constant import constant, ydMap
from ..common.common import LFLog, jsonEncode, checkToken, checkTime, savePersonInfo, savePayRecords, saveTHXDData
getData = Blueprint('getData', __name__)
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
    getNumAreaUrl = constant['urls']['getNumArea'] + \
        constant['mySession'][token + '_username']
    playload = {'time': getTime(), 'channel': '02'}
    response = netSession.get(
        getNumAreaUrl,
        params=playload,
        cookies=cookies,
        headers=headers)
    constant['mySession'][token +
                          '_cookies'] = dict(constant['mySession'][token +
                                                                   '_cookies'], **response.cookies.get_dict())
    return response.text
# 获得手机套餐的信息


def getMeal(netSession, cookies, headers, token):
    getMealUrl = constant['urls']['getMeal'] + \
        constant['mySession'][token + '_username']
    playload = {'time': getTime(), 'channel': '02'}
    response = netSession.get(
        getMealUrl,
        params=playload,
        cookies=cookies,
        headers=headers)
    constant['mySession'][token +
                          '_cookies'] = dict(constant['mySession'][token +
                                                                   '_cookies'], **response.cookies.get_dict())
    return response.text
# 获得个人信息（包括手机号信息）


@getData.route('/getPersonInfo', methods=['GET'])
def getPersonInfo():
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
    getPInfoUrl = constant['urls']['getPersonInfo'] + \
        constant['mySession'][token + '_username']
    if constant['mySession'][token + '_isLogin'] and token + \
            '_cookies' in constant['mySession'].keys(token):
        playload = {'time': getTime(), 'channel': '02'}
        response = constant['netSession'].get(getPInfoUrl,
                                              params=playload,
                                              headers=constant['headers'],
                                              cookies=constant['mySession'][token + '_cookies'])
        response.encoding = 'utf-8'
        pInfo = json.loads(response.text)
        if 'retCode' not in pInfo.keys() or pInfo['retCode'] != '000000':
            return jsonEncode('100009', realMsg=response.text)
        constant['mySession'][token +
                              '_cookies'] = dict(constant['mySession'][token +
                                                                       '_cookies'], **response.cookies.get_dict())
        numInfoText = getNumArea(constant['netSession'],
                                 constant['mySession'][token + '_cookies'],
                                 constant['headers'],
                                 token)
        numInfo = json.loads(numInfoText)
        if 'retCode' not in numInfo.keys() or numInfo['retCode'] != '000000':
            return jsonEncode('100010', realMsg=numInfoText)
        personInfo = dict(pInfo['data'], **numInfo['data'])
        mealInfoText = getMeal(constant['netSession'],
                               constant['mySession'][token + '_cookies'],
                               constant['headers'],
                               token)
        mealInfo = json.loads(mealInfoText)
        print(mealInfo)
        if 'retCode' not in mealInfo.keys() or mealInfo['retCode'] != '000000':
            return jsonEncode('100021', realMsg=mealInfoText)
        mealinfoDic = {
            'brandName': mealInfo['data']['brandName'],
            'curPlanName': mealInfo['data']['curPlanName'],
            'nextPlanName': mealInfo['data']['nextPlanName']}
        personInfo = dict(personInfo, **mealinfoDic)
        # 修饰数据
        personInfo['userPhoneNum'] = constant['mySession'][token + '_username']
        personInfo['servicepassword'] = constant['mySession'][token +
                                                              '_servicepassword']
        personInfo['status'] = ydMap['status'][personInfo['status']]
        personInfo['level'] = ydMap['level'][personInfo['level']]
        personInfo['realNameInfo'] = ydMap['realNameInfo'][personInfo['realNameInfo']]
        if personInfo['starLevel'] is None:
            personInfo['starLevel'] = ydMap['starLevel']['0']
        else:
            personInfo['starLevel'] = ydMap['starLevel'][personInfo['starLevel']]
        result = savePersonInfo(personInfo)
        if result:
            print('存储成功')
        else:
            print('存储失败')
        LFLog(getPersonInfo.__name__ + '--------获得的个人信息是{}'.format(personInfo))
        return jsonEncode('110003', data=personInfo)
    else:

        return jsonEncode('100007')

# 获取详单数据


def getTHXDData(url, netSession, headers, timeStr, curor, step, token):
    playLoad = {
        'curCuror': curor,
        'qryMonth': timeStr,
        'step': step,
        'billType': '02',
        '_': str(int(round(time.time() * 1000)) + 1000)
    }
    try:
        response = netSession.get(url + constant['mySession'][token + '_username'],
                                  params=playLoad,
                                  headers=headers,
                                  cookies=constant['mySession'][token + '_cookies'])
        LFLog(getTHXDData.__name__ +
              '--------获得的通话详单信息是{}'.format(response.text))
        LFLog('*******************************')
        resultStr = response.text[4:].lstrip('(').rstrip(')')
        result = json.loads(resultStr)
        if result['retCode'] != '000000':
            return {'data': None, 'msg': result['retMsg']}
        else:
            constant['mySession'][token +
                                  '_cookies'] = dict(constant['mySession'][token +
                                                                           '_cookies'], **response.cookies.get_dict())
            for item in result['data']:
                item['phoneNum'] = constant['mySession'][token + '_username']
                item['startTime'] = timeStr[0:4] + ' ' + item['startTime']
                isSuccess = saveTHXDData(item)
                if isSuccess is False:
                    LFLog(getTHXDData.__name__ + '--------------存储失败')
            return {'data': result, 'msg': 'success'}
    except Exception as e:
        # traceback.print_exc()
        LFLog(getTHXDData.__name__ + '-------------发生的异常是' + str(e))
        return {'data': None, 'msg': str(e)}
# 获得近六个月的通话详单数据


@getData.route('/getTHXD', methods=['GET'])
def getAllTHXDData():
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
    thisHeaders = copy.deepcopy(constant['headers'])
    thisHeaders['referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    thisHeaders['user-agent'] = constant['PCUA']
    currentTime = int(time.strftime('%Y%m'))
    timeList = []
    for i in range(6):
        timeList .append(str(currentTime - i))
    allData = {}
    errMsg = {}
    for item in timeList:
        result = getTHXDData(
            constant['urls']['getTHXDData'],
            constant['netSession'],
            thisHeaders,
            item,
            1,
            500,
            token)
        LFLog(
            getAllTHXDData.__name__ +
            '---------' +
            item +
            '{}'.format(result))
        if result['data'] is not None:
            if 'totalNum'in result['data'].keys():
                if int(result['data']['totalNum']) > 500:
                    moreData = getTHXDData(
                        constant['urls']['getTHXDData'], constant['netSession'], thisHeaders, item, 501, int(
                            result['data']['totalNum']) - 500)
                    if moreData['data'] is not None:
                        result['data']['data'].extend(moreData['data']['data'])
            allData[item] = result['data']['data']
        else:
            errMsg[item] = result['msg']
    if allData == {}:
        return jsonEncode('100013', realMsg=str(errMsg))
    else:
        LFLog(
            getAllTHXDData.__name__ +
            '----------近六个月的通话详单是：{}'.format(allData))
        return jsonEncode('110006', data=allData)
# 号码（仅限移动 归属地查询）


def getMobileTelSegment():
    pass
# 缴费记录查询


@getData.route('/getPaymentRecords', methods=['GET'])
def getPaymentRecords():
    if len(request.args) != 3:
        return jsonEncode('100000')
    token = request.args.get('token')
    startTime = request.args.get('startTime')
    endTime = request.args.get('endTime')
    checkResult = checkToken(token)
    if checkResult is not True:
        return jsonEncode('100017')
    if token + '_username' not in constant['mySession'].keys(token):
        return jsonEncode('100006')
    if token + '_cookies' not in constant['mySession'].keys(token):
        return jsonEncode('100007')
    if checkTime(startTime, endTime) is False:
        return jsonEncode('100000')
    playLoad = {'startTime': startTime, 'endTime': endTime,
                '_': str(int(round(time.time() * 1000)))}
    selfHeaders = copy.deepcopy(constant['headers'])
    selfHeaders['Referer'] = 'http://shop.10086.cn/i/?welcome=' + \
        str(int(round(time.time() * 1000)) - 1000)
    selfHeaders['User-Agent'] = constant['PCUA']
    response = constant['netSession'].get(constant['urls']['getPaymentRecords'] +
                                          constant['mySession'][token +
                                                                '_username'], params=playLoad, headers=selfHeaders, cookies=constant['mySession'][token +
                                                                                                                                                  '_cookies'])
    responseDict = json.loads(response.text)
    if responseDict['retCode'] == '000000':
        constant['mySession'][token +
                              '_cookies'] = dict(constant['mySession'][token +
                                                                       '_cookies'], **response.cookies.get_dict())
        paymentRecords = responseDict['data']
        for item in paymentRecords:
            item['payChannel'] = ydMap['payChannel'][item['payChannel']]
            item['payType'] = ydMap['payType'][item['payType']]
            item['phoneNum'] = constant['mySession'][token + '_username']
            result = savePayRecords(item)
            if result is False:
                LFLog(getPaymentRecords.__name__ + '---------存储失败')
        return jsonEncode('110008', data=paymentRecords)
    else:
        return jsonEncode('100018', realMsg=responseDict['retMsg'])
