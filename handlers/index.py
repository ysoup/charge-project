# coding:utf-8

import requests
import uuid
import hmac
from backend.mysql_model.charge import *
from playhouse.shortcuts import model_to_dict
from handlers.basehandlers.basehandler import BaseRequestHandler

from utils.util import json_result, login_required
from utils.util import get_cleaned_post_data, get_cleaned_query_data
from utils.pay import *


APP_ID = "wx59e6ab7b485f9926"
APP_KEY = "55c1b38012f7eeaa062b9ca1c889b36d"


class LoginHandler(BaseRequestHandler):

    def get(self, *args, **kwargs):
        self.render('login.html')

    def post(self, *args, **kwargs):
        post_data=get_cleaned_post_data(self,['username','password'])
        #try:
        #    post_data=get_cleaned_post_data(self,['username','password'])
        #except RequestArgumentError as e:
        #    self.write(json_result(e.code,e.msg))
        #    return
        user=User.auth(post_data['username'],post_data['password'])
        if user:
            self.set_secure_cookie('uuid',user.username)
            result=json_result(0,'login success!')
            self.redirect('/')
        else:
            result=json_result(-1,'login failed!')
            self.redirect('/login')
        # write as json
        #self.write(result)


# 微信登录
class ChatLoginHandler(BaseRequestHandler):
    def post(self, *args, **kwargs):
        data = get_cleaned_query_data(self, ['code', 'encryptedData', 'iv'])

        # 获取openid，session_key
        # Appid为小程序id
        openid_url = "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code" % (
            APP_ID, APP_KEY, data["code"]
        )
        req = requests.get(openid_url)
        rep = req.json()
        session_key = rep.get("session_key")

        pc = WXBizDataCrypt(APP_ID, session_key.encode())

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
        client_ip, port = self.request.host.split(":")
        # 获取小程序openid
        openid = MyUser.objects.get(id=user_id).openid

        # 请求微信的url
        url = configuration.order_url

        # 拿到封装好的xml数据
        body_data = get_bodyData(openid, client_ip, price)

        # 获取时间戳
        timeStamp = str(int(time.time()))

        # 请求微信接口下单
        respone = requests.post(url, body_data.encode("utf-8"), headers={'Content-Type': 'application/xml'})





