from tools.RedisToSession import Session
import requests
constant = {
    # token过期时间
    'expireTime': 60 * 60,
    'mySession': Session(),
    # 手机userAgent
    'mobileUA': 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1',
    # 电脑userAgent
    'PCUA': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
    # session flask的session 是写在客户端的
    'netSession': requests.session(),
    # 其他可以汇编的参数
    'otherParams': {
                'channelID': '12014',
                'type': '01'
    },
    # 请求头
    'headers': {
        'accept': "application/json, text/javascript, */*; q=0.01",
        'accept-encoding': 'gzip,deflate,br',
        'accept-language': 'zh-CN, zh;q = 0.8',
        'Connection': 'keep-alive',
        'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1',
        #'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1',
        'referer': 'https://login.10086.cn/html/login/touch.html',
        'x-requested-With': 'XMLHttpRequest',
        'cache-control': "no-cache",
        'Upgrade-Insecure-Requests': '1',

    },
    # 所有移动api
    'urls': {
        'getRdmdAndCaptchaCode': 'https://login.10086.cn/captchazh.htm?type=05',
        'checkNum': 'https://login.10086.cn/chkNumberAction.action',
                    'sendRequestForVerifyTextCode': 'https://login.10086.cn/sendRandomCodeAction.action',
                    'getNumArea': 'http://touch.10086.cn/i/v1/res/numarea/',
                    'getMeal': 'http://touch.10086.cn/i/v1/busi/plan/',
                    'getPersonInfo': 'http://touch.10086.cn/i/v1/cust/info/',
                    'getArtifact': 'https://login.10086.cn/login.htm',
                    'getTHXDData': 'https://shop.10086.cn/i/v1/fee/detailbillinfojsonp/',
                    'sendTemporaryIDRandomCode': 'https://shop.10086.cn/i/v1/fee/detbillrandomcodejsonp/',
                    'sendTemporaryIDRandomImage': 'http://shop.10086.cn/i/authImg',
                    'authTemporaryID': 'https://shop.10086.cn/i/v1/fee/detailbilltempidentjsonp/',
                    'quitQuery': 'http://shop.10086.cn/i/v1/auth/userlogout',
                    'getPaymentRecords': 'http://shop.10086.cn/i/v1/cust/his/'
    },
    # 本项目错误映射
    'errorCode': {
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
        '100018': u'获取缴费记录失败',
        '100019': u'未知错误',
        '100020': u'验证图片发送失败',
        '100021': u'套餐信息获取失败'
    },
    # 成功代码映射
    'successCode': {
        '110001': u'发送成功，请等待接收',
        '110002': u'认证成功',
        '110003': u'获取成功',
        '110004': u'临时身份认证成功',
        '110005': u'短信验证码与图片验证码发送完毕，如未收到，请稍后刷新本页面',
        '110006': u'获取通话详单成功',
        '110007': u'获取token成功',
        '110008': u'获取缴费记录成功',
        '110009': u'token已存在',
        '110010': u'验证图片发送成功',
        '110011': u'验证码发送成功，如未收到请稍后再试',
        '110012': u'退出成功'
    },
}
ydMap = {
    'status': {
        '00': '正常',
        '01': '单向停机',
        '02': '停机',
        '03': '预销户 ',
        '04': '销户',
        '05': '过户',
        '06': '改号',
        '99': '此号码不存在',
    },
    'level': {
        '000': '保留',
        '100': '普通客户',
        '300': '普通大客户',
        '301': '钻石卡大客户',
        '302': '金卡大客户',
        '303': '银卡大客户',
        '304': '贵宾卡大客户',
    },
    'realNameInfo': {
        '1': '未登记',
        '2': '已登记',
        '3': '已审核',
    },
    'starLevel': {
        '0': '0星级用户',
        '1': '1星级用户',
        '2': '2星级用户',
        '3': '3星级用户',
        '4': '4星级用户',
        '5': '5星级用户',
        '6': '五星金',
        '7': '五星钻',
    },
    'payType': {
        '01': '现金交费',
        '02': '充值卡充值',
        '03': '银行托收',
        '04': '营销活动预存受理',
        '05': '积分换话费业务受理',
        '06': '第三方支付',
        '07': '手机钱包',
        '08': '空中充值',
        '09': '代理商渠道办理',
        '10': '批量冲销',
        '11': '调账',
        '12': '其他',
    },
    'payChannel': {
        '01': '营业厅',
        '02': '网上营业厅',
        '03': '掌上营业厅',
        '04': '短信营业厅',
        '05': '手机营业厅',
        '06': '第三方支付',
        '07': '银行',
        '08': '空中充值',
        '09': '移动商城',
        '99': '其他',
    },

}
