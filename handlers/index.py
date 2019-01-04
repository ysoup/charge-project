# coding:utf-8

import requests
import uuid
import hmac
from backend.mysql_model.charge import *
from playhouse.shortcuts import model_to_dict
from handlers.basehandlers.basehandler import BaseRequestHandler

from utils.util import *
from utils.pay import *
from utils.send_sms import *
import config
import json

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
        data = get_cleaned_query_data(self, ['mobile_no', "code"])
        info = MobileCheckCode.select().where(MobileCheckCode.mobile_no == data["mobile_no"],
                                              MobileCheckCode["code"] == data["code"]).first()
        if info:
            result = json_result(0, "校验成功")
        else:
            result = json_result(1, "校验失败")
        self.write(result)


# 用户登录
class LoginHandler(BaseRequestHandler):
    def post(self, *args, **kwargs):
        data = get_cleaned_query_data(self, ['mobile_no'])


# 用户基本信息
class UserInfoHandler(BaseRequestHandler):
    def get(self, *args, **kwargs):
        data = get_cleaned_query_data(self, ['user_no'])
        use_info = UseInfo.select().where(UseInfo.user_no == data["user_no"]).first()
        if use_info:
            data = model_to_dict(use_info)
        result = json_result(0, data)
        self.write(result)


# 微信支付
class WeChatPayHandler(BaseRequestHandler):
    def post(self, *args, **kwargs):
        data = get_cleaned_query_data(self, ['fee'])

        client_ip, port = self.request.host.split(":")
        # 获取小程序openid

        # openid_url = "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code" % (
        #     APP_ID, APP_KEY, "033IIAzP0ZK0E42bexxP0LYLzP0IIAzW")
        # req = requests.get(openid_url)
        # rep = req.json()
        # openid = rep["openid"]
        openid = "ofutN5WvOP4O5YPxrPOf-Iz9wHuA"
        # 请求微信的url
        url = "https://api.mch.weixin.qq.com/pay/unifiedorder"

        # 拿到封装好的xml数据
        body_data = get_bodyData(openid, client_ip, data["fee"])

        # 获取时间戳
        timeStamp = str(int(time.time()))

        # 请求微信接口下单
        respone = requests.post(url, body_data.encode("utf-8"), headers={'Content-Type': 'application/xml'})

        # 回复数据为xml,将其转为字典
        content = trans_xml_to_dict(respone.content)

        if content["return_code"] == 'SUCCESS':
            # 获取预支付交易会话标识
            prepay_id = content.get("prepay_id")
            # 获取随机字符串
            nonceStr = content.get("nonce_str")

            # 获取paySign签名，这个需要我们根据拿到的prepay_id和nonceStr进行计算签名
            paySign = get_paysign(prepay_id, timeStamp, nonceStr)

            # 封装返回给前端的数据
            data = {"package": 'prepay_id={0}'.format(prepay_id), "nonceStr": nonceStr, "paySign": paySign, "timeStamp": timeStamp}
            result = json_result(0, data)
            self.write(result)
        else:
            result = json_result(-1, "请求支付失败")
            self.write(result)








