from db import db
import traceback
# 登录用户数据


class yd_developer(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(50), nullable=False, unique=False)
    token = db.Column(db.String(100), nullable=True, unique=True)
    isLogin = db.Column(db.Integer, nullable=False, default=0)
# 缴费记录


class yd_payRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    payDate = db.Column(db.String(20), nullable=False, unique=True)
    payFee = db.Column(db.String(20), nullable=False, unique=False)
    payChannel = db.Column(db.String(10), nullable=True, unique=False)
    payAddr = db.Column(db.String(10), nullable=True, unique=False)
    payFlag = db.Column(db.String(10), nullable=True, unique=False)
    payType = db.Column(db.String(10), nullable=True, unique=False)
    payTypeName = db.Column(db.String(10), nullable=True, unique=False)
    payStaffCode = db.Column(db.String(10), nullable=True, unique=False)
    phoneNum = db.Column(db.String(20), nullable=True)
    __tablename__ = 'yd_payRecord'

    def saveData(self, dataDict):
        print(dataDict)
        if not isinstance(dataDict, dict):
            raise TypeError('{} is not dict'.format(dataDict))
        try:
            theLastPayRecord = self.query.filter_by(
                phoneNum=dataDict['phoneNum']).filter_by(
                payDate=dataDict['payDate']).first()
            if theLastPayRecord is None:
                for key, value in dataDict.items():
                    setattr(self, key, value)
                db.session.add(self)
                db.session.commit()
            else:
                for key, value in dataDict.items():
                    setattr(self, key, value)
                db.session.commit()
        except Exception as error:
            traceback.print_exc()
            print(str(error))
            return False
# 通话记录


class yd_THXQ(db.Model):
    # "remark": null, "startTime": "07-01 10:35:56", "commPlac": "兰州", "commMode": "被叫", "anotherNm": "18709422065", "commTime": "10秒", "commType": "本地", "mealFavorable": "", "commFee": "0.00"}
    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True,
        unique=True)
    startTime = db.Column(db.String(20), nullable=False, unique=False)
    commPlac = db.Column(db.String(10), nullable=True, unique=False)
    commMode = db.Column(db.String(10), nullable=True, unique=False)
    anotherNm = db.Column(db.String(20), nullable=True, unique=False)
    commTime = db.Column(db.String(10), nullable=True, unique=False)
    commType = db.Column(db.String(10), nullable=True, unique=False)
    mealFavorable = db.Column(db.String(20), nullable=True, unique=False)
    commFee = db.Column(db.String(10), nullable=True, unique=False)
    remark = db.Column(db.String(50), nullable=True)
    phoneNum = db.Column(db.String(20), nullable=True)
    __tablename__ = 'yd_THXD'

    def saveData(self, dataDict):
        if not isinstance(dataDict, dict):
            raise TypeError('{} is not dict'.format(dataDict))
        try:
            THXD = self.query.filter_by(
                phoneNum=dataDict['phoneNum']).filter_by(
                startTime=dataDict['startTime']).first()
            if THXD is None:
                for key, value in dataDict.items():
                    setattr(self, key, value)
                db.session.add(self)
                db.session.commit()
            else:
                for key, value in dataDict.items():
                    setattr(self, key, value)
                db.session.commit()
            return True
        except Exception as error:
            # traceback.print_exc()
            print(str(error))
            return False
# 移动用户


class yd_userinfo(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(20), nullable=False, unique=False)
    status = db.Column(db.String(20), nullable=True, unique=False)
    level = db.Column(db.String(20), nullable=True, unique=False)
    brandName = db.Column(db.String(20), nullable=True, unique=False)
    curPlanName = db.Column(db.String(20), nullable=True, unique=False)
    inNetDate = db.Column(db.String(20), nullable=True, unique=False)
    netAge = db.Column(db.String(20), nullable=True, unique=False)
    realNameInfo = db.Column(db.String(20), nullable=True, unique=False)
    starLevel = db.Column(db.String(20), nullable=True, unique=False)
    starScore = db.Column(db.String(20), nullable=True, unique=False)
    starTime = db.Column(db.String(20), nullable=True, unique=False)
    contactNum = db.Column(db.String(20), nullable=True, unique=False)
    email = db.Column(db.String(20), nullable=True, unique=False)
    zipCode = db.Column(db.String(20), nullable=True, unique=False)
    address = db.Column(db.String(20), nullable=True, unique=False)
    servicepassword = db.Column(db.String(20), nullable=True, unique=False)
    id_name_cd = db.Column(db.String(20), nullable=True, unique=False)
    vipInfo = db.Column(db.String(20), nullable=True, unique=False)
    prov_cd = db.Column(db.String(20), nullable=True, unique=False)
    id_area_cd = db.Column(db.String(20), nullable=True, unique=False)
    brand = db.Column(db.String(20), nullable=True, unique=False)
    remark = db.Column(db.String(20), nullable=True, unique=False)
    num_type = db.Column(db.String(20), nullable=True, unique=False)
    userPhoneNum = db.Column(db.String(20), nullable=False, unique=True)
    nextPlanName = db.Column(db.String(20), nullable=True, unique=False)
    __tablename__ = 'yd_userinfo'

    def saveData(self, dataDict):
        if not isinstance(dataDict, dict):
            raise TypeError('{} is not dict'.format(dataDict))
        try:
            user = self.query.filter_by(
                userPhoneNum=dataDict['userPhoneNum']).first()
            if user is None:
                for key, value in dataDict.items():
                    setattr(self, key, value)
                db.session.add(self)
                db.session.commit()

            else:
                for key, value in dataDict.items():
                    setattr(user, key, value)
                db.session.commit()
            return True
        except IndexError:
            return False
