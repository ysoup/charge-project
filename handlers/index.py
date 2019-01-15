# coding:utf-8

import requests
import uuid
import hmac
from backend.mysql_model.charge import *
from playhouse.shortcuts import model_to_dict
from handlers.basehandlers.basehandler import BaseRequestHandler
from .auth import Auth
from utils.util import *
from utils.pay import *
from utils.send_sms import *
import config
import json
from backend.redis_db import *
from decimal import *
import logging
import datetime
import time
import decimal
from backend.mysql_model import db_mysql
import traceback

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='my.log', level=logging.DEBUG, format=LOG_FORMAT)
# class LoginHandler(BaseRequestHandler):
#
#     def get(self, *args, **kwargs):
#         self.render('login.html')
#
#     def post(self, *args, **kwargs):
#         post_data=get_cleaned_post_data(self,['username','password'])
#         #try:
#         #    post_data=get_cleaned_post_data(self,['username','password'])
#         #except RequestArgumentError as e:
#         #    self.write(json_result(e.code,e.msg))
#         #    return
#         user=User.auth(post_data['username'],post_data['password'])
#         if user:
#             self.set_secure_cookie('uuid',user.username)
#             result=json_result(0,'login success!')
#             self.redirect('/')
#         else:
#             result=json_result(-1,'login failed!')
#             self.redirect('/login')
#         # write as json
#         #self.write(result)


# 微信登录
class ChatLoginHandler(BaseRequestHandler):
    def post(self, *args, **kwargs):
        data = get_cleaned_query_data(self, ['code', 'encryptedData', 'iv'])

        # 获取openid，session_key
        # Appid为小程序id
        openid_url = "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code" % (
            config.APP_ID, config.APP_KEY, data["code"]
        )
        req = requests.get(openid_url)
        rep = req.json()
        session_key = rep.get("session_key")

        pc = WXBizDataCrypt(config.APP_ID, session_key.encode())

        print(pc.decrypt(data["encryptedData"].encode(), data["iv"].encode()))

        # 判断该用户是否微信授权
        use_info = UseInfo.select().where(UseInfo.mobile_no == data["mobile_no"], UseInfo.use_type == 0).first()
        if use_info:
            user_no = use_info.user_no
        else:
            unique = uuid.uuid4()
            user_no = hmac.new(unique.bytes, digestmod="sha1").hexdigest()
            UseInfo.create(
                user_no=user_no,
                mobile_no=data["mobile_no"],
                use_type=0
            )
        result = json_result(0, {"user_no": user_no})
        self.write(result)


# 用户注册登录
class LoginHandler(BaseRequestHandler):
    def post(self, *args, **kwargs):
        data = get_cleaned_query_data(self, ['code', 'encryptedData', 'iv'])

        # 获取openid，session_key
        # Appid为小程序id
        openid_url = "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code" % (
            config.APP_ID, config.APP_KEY, data["code"]
        )
        req = requests.get(openid_url)
        rep = req.json()
        session_key = rep.get("session_key")

        pc = WXBizDataCrypt(config.APP_ID, session_key.encode())

        print(pc.decrypt(data["encryptedData"].encode(), data["iv"].encode()))

        # 判断该用户是否微信授权
        use_info = UseInfo.select().where(UseInfo.mobile_no == data["mobile_no"], UseInfo.use_type == 0).first()
        if use_info:
            user_no = use_info.user_no
        else:
            unique = uuid.uuid4()
            user_no = hmac.new(unique.bytes, digestmod="sha1").hexdigest()
            UseInfo.create(
                user_no=user_no,
                mobile_no=data["mobile_no"],
                use_type=0
            )
        result = json_result(0, {"user_no": user_no})
        self.write(result)


# 发送短信
class SmsHandler(BaseRequestHandler):
    def get(self, *args, **kwargs):
        data = get_cleaned_query_data(self, ['mobile_no'])

        business_id = uuid.uuid1()
        phone_numbers = data["mobile_no"]
        template_code = "SMS_153725691"
        smscode = str(generate_number_code())
        param = "{\"code\":\"%s\"}" % smscode

        result = send_sms_code(business_id=business_id,
                               phone_numbers=phone_numbers,
                               template_code=template_code,
                               template_param=param)
        result = json.loads(result)
        if result["Message"] == "OK":
            info = MobileCheckCode.select().where(MobileCheckCode.mobile_no == data["mobile_no"]).first()
            if info:
                MobileCheckCode.update(code=smscode).where(MobileCheckCode.mobile_no == data["mobile_no"]).execute()
            else:
                MobileCheckCode.create(
                    mobile_no=data["mobile_no"],
                    code=smscode
                )
            result = json_result(0, "发送成功")
        else:
            result = json_result(1, "发送失败")
        self.write(result)

    def post(self, *args, **kwargs):
        data = get_cleaned_post_data(self, ['mobile_no', "code"])
        info = MobileCheckCode.select().where(MobileCheckCode.mobile_no == data["mobile_no"],
                                              MobileCheckCode.code == data["code"]).first()
        if info:
            result = json_result(0, "校验成功")
        else:
            result = json_result(1, "校验失败")
        self.write(result)


# 用户登录
class UserLoginHandler(BaseRequestHandler):
    def post(self, *args, **kwargs):
        data = get_cleaned_post_data(self, ['mobile_no'])

        use_info = UseInfo.select().where(UseInfo.mobile_no == data["mobile_no"], UseInfo.use_type == 0).first()
        if use_info:
            user_no = use_info.user_no
        else:
            unique = uuid.uuid4()
            user_no = hmac.new(unique.bytes, digestmod="sha1").hexdigest()
            UseInfo.create(
                user_no=user_no,
                mobile_no=data["mobile_no"],
                use_type=0
            )
        # token 生成
        token = Auth.encode_auth_token(user_no, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        self.set_header("Authorization", token)
        db_redis.set("user_token_info_%s" % user_no, token)

        result = json_result(0, {"user_no": user_no})
        self.write(result)


# 用户登出
class LoginOutHandler(BaseRequestHandler):
    @login_required
    def post(self, *args, **kwargs):
        data = get_cleaned_post_data(self, ['user_no'])
        db_redis.delete("user_token_info_%s" % data["user_no"])
        result = json_result(0, "退出成功")
        self.write(result)


# 用户基本信息
class UserInfoHandler(BaseRequestHandler):
    @login_required
    def get(self, *args, **kwargs):
        data = get_cleaned_query_data(self, ['user_no'])
        use_info = UseInfo.select().where(UseInfo.user_no == data["user_no"]).first()
        dic = {}
        if use_info:
            dic = model_to_dict(use_info)
            account_info = AccountInfo.select().where(AccountInfo.user_no == data["user_no"]).first()
            if account_info:
                dic["total_amount"] = account_info.total_amount
            else:
                dic["total_amount"] = "0"
        result = json_result(0, dic)
        self.write(result)


# 微信支付
class WeChatPayHandler(BaseRequestHandler):
    @login_required
    def post(self, *args, **kwargs):
        data = get_cleaned_post_data(self, ['fee', "code", "user_no"])
        logging.info("威信支付:ip %s" % self.request.headers["X-Real-Ip"])

        client_ip = self.request.headers["X-Real-Ip"]
        # 获取小程序openid

        openid_url = "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code" % (
            config.APP_ID, config.APP_KEY, data["code"])
        req = requests.get(openid_url)
        rep = req.json()
        openid = rep["openid"]
        # openid = "ofutN5WvOP4O5YPxrPOf-Iz9wHuA"
        # 请求微信的url
        url = "https://api.mch.weixin.qq.com/pay/unifiedorder"

        # 生成订单编号
        order_id = getWxPayOrdrID()

        # 拿到封装好的xml数据
        body_data = get_bodyData(openid, client_ip, data["fee"], order_id)

        # 获取时间戳
        timeStamp = str(int(time.time()))

        # 请求微信接口下单
        respone = requests.post(url, body_data.encode("utf-8"), headers={'Content-Type': 'application/xml'})

        # 回复数据为xml,将其转为字典
        content = trans_xml_to_dict(respone.content)

        if content["return_code"] == 'SUCCESS':
            PayOrderDetails.create(
                user_no=data["user_no"],
                order_no=order_id,
                pay_fee=str(data["fee"]),
                pay_type=0,
                pay_status=0
            )
            # 获取预支付交易会话标识
            prepay_id = content.get("prepay_id")
            # 获取随机字符串
            nonceStr = content.get("nonce_str")

            # 获取paySign签名，这个需要我们根据拿到的prepay_id和nonceStr进行计算签名
            paySign = get_paysign(prepay_id, timeStamp, nonceStr)

            # 封装返回给前端的数据
            data = {"package": 'prepay_id={0}'.format(prepay_id), "nonceStr": nonceStr, "paySign": paySign, "timeStamp": timeStamp}
            result = json_result(0, data)
            logging.info("微信支付返回值:%s" % result)
            self.write(result)
        else:
            PayOrderDetails.create(
                user_no=data["user_no"],
                order_no=order_id,
                pay_fee=str(data["fee"]),
                pay_type=0,
                pay_status=0
            )
            result = json_result(-1, "请求支付失败")
            logging.info("微信支付返回值:%s" % result)
            self.write(result)


# 微信支付通知
class PayNotifyHandler(BaseRequestHandler):
    def post(self, *args, **kwargs):
        data = self.request.body
        data = str(data, encoding="utf-8")
        logging.info("微信支付通知")
        dic = trans_xml_to_dict(data)
        if dic.__contains__("out_trade_no"):
            order_id = dic["out_trade_no"]
            logging.info("微信支付订单号:%s" % order_id)
            order_info = PayOrderDetails.select().where(PayOrderDetails.order_no == order_id).first()
            if order_info:
                # 更新订单
                logging.info("微信支付修改支付状态")
                PayOrderDetails.update(pay_status=1).where(PayOrderDetails.order_no == order_id).execute()
                # 更新账户
                logging.info("微信支付当前用户:%s" % order_info.user_no)
                account_info = AccountInfo.select().where(AccountInfo.user_no == order_info.user_no).first()
                total_fee = Decimal(dic["total_fee"])
                if account_info:
                    total_amount = total_fee + account_info.total_amount
                    AccountInfo.update(total_amount=total_amount).where(AccountInfo.id == account_info.id).execute()
                else:
                    AccountInfo.create(
                        user_no=order_info.user_no,
                        total_amount=total_fee
                    )
                ret_dict = {
                    'return_code': 'SUCCESS',
                    'return_msg': 'OK',
                }
                ret_xml = trans_dict_to_xml(ret_dict)
                self.write(ret_xml)
        else:
            ret_dict = {
                'return_code': 'FAIL',
                'return_msg': 'verify error',
            }

            ret_xml = trans_dict_to_xml(ret_dict)
            self.write(ret_xml)


# 获取电桩信息
class ChargeStationHandler(BaseRequestHandler):
    # @login_required
    def get(self, *args, **kwargs):
        try:
            data = get_cleaned_query_data(self, ["qr_code"])
            qr_code = data["qr_code"].split("_")[0]
            station_info = ChargeStation.select().where(ChargeStation.qr_code == qr_code).first()
            dic = {}
            if station_info:
                dic = model_to_dict(station_info)
            result = json_result(0, dic)
            self.write(result)
        except Exception as e:
            logging.error(traceback.format_exc())

    @login_required
    def post(self, *args, **kwargs):
        try:
            data = get_cleaned_post_data(self, ["stake_no", "spear_no", "qr_code", "user_no"])
            # 查询账余额
            account_info = AccountInfo.select().where(AccountInfo.user_no == data["user_no"]).first()
            amount = account_info.total_amount
            # 查询当前用户编号
            user_info = UseInfo.select().where(UseInfo.user_no == data["user_no"]).first()
            uid = user_info.id
            t = time.time()
            current_time = int(round(t * 1000))
            current_date = datetime.datetime.now().strftime('%Y%m%d')
            calcno = "calcno" + "_" + current_date + str(current_time)
            # 发送充电队列
            for x in range(0, 2):
                charge_data = {
                    "stake_no": data["stake_no"],
                    "spear_no": data["spear_no"],
                    "uid": uid,
                    "calcno": calcno,
                    "user_no": data["user_no"],
                    "amount": str(amount).split(".")[0],
                    "price": "150"
                }
                db_redis.lpush("query_charge_6104", json.dumps(charge_data))
            UserCalcnoInfo.create(
                calc_no=calcno,
                user_no=data["user_no"],
                spear_no=data["spear_no"],
                stake_no=data["stake_no"]
            )
            result = json_result(0, {"calcno": calcno, "uid": uid, "user_no": data["user_no"]})
            self.write(result)
        except Exception as e:
            logging.error(traceback.format_exc())


# 获取电桩是否可以充电状态
class ChargeStatusHandler(BaseRequestHandler):
    @login_required
    def post(self, *args, **kwargs):
        try:
            data = get_cleaned_post_data(self, ["calcno", "user_no", "uid"])
            catch_data = db_redis.get("gun_status_%s" % data["calcno"])
            dic = {}
            if catch_data:
                # catch_data = json.loads(catch_data)
                gun_status = catch_data.decode("utf-8")
                if gun_status == "1":
                    # 可以充电
                    dic["status"] = 1
                    # 查询该用户充电
                    calcno_info = UserCalcnoInfo.select().where(UserCalcnoInfo.user_no == data["user_no"],
                                                                UserCalcnoInfo.calc_no == data["calcno"]).first()
                    if calcno_info:
                        # 创建充电订单
                        t = time.time()
                        current_time = int(round(t * 1000))
                        current_date = datetime.datetime.now().strftime('%Y%m%d')
                        order_no = current_date + str(current_time) + calcno_info.spear_no + calcno_info.stake_no + \
                                   data["uid"]
                        dic["order_no"] = order_no
                        with db_mysql.atomic() as transaction:
                            ChargeOrderInfo.create(
                                order_no=order_no,
                                user_no=data["user_no"],
                                pay_status=0,
                                spear_no=calcno_info.spear_no,
                                stake_no=calcno_info.stake_no
                            )
                        # 发送充电命令
                        for x in range(0, 4):
                            charge_data = {
                                "order_no": order_no,
                                "spear_no": calcno_info.spear_no,
                                "stake_no": calcno_info.stake_no,
                                "uid": data["uid"],
                                "is_can_begin": "1"
                            }
                            db_redis.lpush("query_charge_6105", json.dumps(charge_data))
                else:
                    # 不可以充电
                    dic["status"] = 2
            else:
                # 没有返回消息
                dic["status"] = 0
            result = json_result(0, dic)
            self.write(result)
        except Exception as e:
            logging.error(traceback.format_exc())


# 获取充电详情
class ChargeDetailsHandler(BaseRequestHandler):
    @login_required
    def post(self, *args, **kwargs):
        try:
            data = get_cleaned_post_data(self, ["user_no", "order_no"])
            cache_data = db_redis.lpop("6103_charge_details_%s" % data["order_no"])
            charge_details = {}
            if cache_data:
                details_data = str(cache_data, encoding="utf-8")
                charge_details = json.loads(details_data)
            result = json_result(0, charge_details)
            self.write(result)
        except Exception as e:
            logging.error(traceback.format_exc())


# 充电结束
class ChargeEndHandler(BaseRequestHandler):
    @login_required
    def post(self, *args, **kwargs):
        try:
            data = get_cleaned_post_data(self, ["user_no", "order_no"])
            # 发送充电结束指令
            order_info = ChargeOrderInfo.select().where(ChargeOrderInfo.order_no == data["order_no"]).first()
            dic = {}
            dic["status"] = 0
            if order_info:
                charge_data = {
                    "order_no": data["order_no"],
                    "spear_no": order_info.spear_no,
                    "stake_no": order_info.stake_no,
                }
                db_redis.lpush("query_charge_6106", json.dumps(charge_data))
                dic["status"] = 1
            result = json_result(0, dic)
            self.write(result)
        except Exception as e:
            logging.error(traceback.format_exc())


# 充电结帐
class ChargeBalanceHandler(BaseRequestHandler):
    @login_required
    def post(self, *args, **kwargs):
        try:
            # charge_data = {
            #     "spear_no": "10001",
            #     "stake_no": "1",
            #     "order_no": "2019011615475708662411000116",
            #     "is_ok": "1"
            #
            # }
            # db_redis.lpush("query_charge_6107", json.dumps(charge_data))
            data = get_cleaned_post_data(self, ["user_no", "order_no"])

            # 获取结算6106队列数据
            cache_data = db_redis.lpop("6106_charge_balance_%s" % data["order_no"])
            if cache_data:
                blance_data = str(cache_data, encoding="utf-8")
                blance_data = json.loads(blance_data)
                order_info = ChargeOrderInfo.select().where(ChargeOrderInfo.order_no == data["order_no"]).first()
                if order_info:
                    # 结帐
                    # 查询账户
                    account_info = AccountInfo.select().where(AccountInfo.user_no == data["user_no"]).first()
                    if account_info:
                        amount = account_info.total_amount - decimal.Decimal(blance_data["purchase"])
                        # 更新账户及订单状态
                        with db_mysql.atomic() as transaction:
                            AccountInfo.update(total_amount=amount).where(AccountInfo.user_no == data["user_no"]).execute()
                            ChargeOrderInfo.update(pay_status=1, amount=blance_data["purchase"],
                                                   power=blance_data["power"]).where(
                                ChargeOrderInfo.order_no == data["order_no"]).execute()
                    # 发送结帐信息
                    charge_data = {
                        "order_no": data["order_no"],
                        "spear_no": order_info.spear_no,
                        "stake_no": order_info.stake_no,
                        "is_ok": 1
                    }
                    db_redis.lpush("query_charge_6107", json.dumps(charge_data))
                result = json_result(0, {"amount": order_info.amount, "power": blance_data["power"], "status": 1})
            else:
                result = json_result(0, {"status": 2})
            self.write(result)
        except Exception as e:
            logging.error(traceback.format_exc())
            result = json_result(0, {"status": 0})
            self.write(result)






















