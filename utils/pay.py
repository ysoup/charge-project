# coding:utf-8
import hashlib
import base64
import json
from Crypto.Cipher import AES


class WXBizDataCrypt:
    def __init__(self, appId, sessionKey):
        self.appId = appId
        self.sessionKey = sessionKey

    def decrypt(self, encryptedData, iv):
        # base64 decode
        sessionKey = base64.b64decode(self.sessionKey)
        print(sessionKey)
        encryptedData = base64.b64decode(encryptedData)
        print(encryptedData)
        iv = base64.b64decode(iv)
        print(iv)
        cipher = AES.new(b'\x83=\x01\x97\xcdV\xda\xa8eR\x9dQ6\xf8\xbb\xb8', AES.MODE_CBC, b'\xcd6C\xa7\xf4\x14uF\xef\xc0\xf3\xbd\x95\x06s\xe0')
        data = cipher.decrypt(b'\x1feD\xde,+]\xcf\x1c\xa8\xae\xc3H\xabb\xb5\x0c@\xc3\xf2\xffQ\x85\x8a\xad\xd4\x9b\x17@\x85r\x8c\x11\xf47\rJy\\\xde:\xbb\xedri"kp\xc8\x8a+\xae\x80\x90b\xee\xa4cg\x9e\x17D\x7f\xdf\xb2\xd5\x1f\x83\x98\x06.\x19\xd9\x9cJ\xf2\x95\xd6\xa8\xdbo-U\xe9\x05\xba\xc0K\x9fs3\xa4\xf0\xbf\xd9,T\xa9\xeaB\xa2\x13\xb7\xba/@\xf1U\x9eQ\xf6q\x08\x88w\x99\xa6\xa0\x183\xa4@\xb8\x95\x0f0Xf\xb2\x08\x07\x1a<\xca\xdfvc\xa5\xed\xc0y\xc1\x93\x05\x1bv\xa6\xddm)\xe4\xd4$\xeb\xf9\xf0')

        decrypted = json.loads(self._unpad(data))

        if decrypted['watermark']['appid'] != self.appId:
            raise Exception('Invalid Buffer')

        return decrypted

    def _unpad(self, s):
        val = s[:-ord(s[len(s) - 1:])]
        if isinstance(val, bytes):
            val = val.decode()
        return val


def main():
    appId = 'wx4f4bc4dec97d474b'
    sessionKey = 'tiihtNczf5v6AKRyjwEUhQ=='
    encryptedData = 'CiyLU1Aw2KjvrjMdj8YKliAjtP4gsMZMQmRzooG2xrDcvSnxIMXFufNstNGTyaGS9uT5geRa0W4oTOb1WT7fJlAC+oNPdbB+3hVbJSRgv+4lGOETKUQz6OYStslQ142dNCuabNPGBzlooOmB231qMM85d2/fV6ChevvXvQP8Hkue1poOFtnEtpyxVLW1zAo6/1Xx1COxFvrc2d7UL/lmHInNlxuacJXwu0fjpXfz/YqYzBIBzD6WUfTIF9GRHpOn/Hz7saL8xz+W//FRAUid1OksQaQx4CMs8LOddcQhULW4ucetDf96JcR3g0gfRK4PC7E/r7Z6xNrXd2UIeorGj5Ef7b1pJAYB6Y5anaHqZ9J6nKEBvB4DnNLIVWSgARns/8wR2SiRS7MNACwTyrGvt9ts8p12PKFdlqYTopNHR1Vf7XjfhQlVsAJdNiKdYmYVoKlaRv85IfVunYzO0IKXsyl7JCUjCpoG20f0a04COwfneQAGGwd5oa+T8yO5hzuyDb/XcxxmK01EpqOyuxINew=='
    iv = 'r7BXXKkLb8qrSNn05n0qiA=='

    pc = WXBizDataCrypt(appId, sessionKey.encode())

    print(pc.decrypt(encryptedData.encode(), iv.encode()))


if __name__ == '__main__':
    main()


def getNonceStr():
    import random
    data = "123456789zxcvbnmasdfghjklqwertyuiopZXCVBNMASDFGHJKLQWERTYUIOP"
    nonce_str = ''.join(random.sample(data, 30))
    return nonce_str


def get_nonce_str():
    import uuid

    return str(uuid.uuid4()).replace('-', '')


# 生成签名的函数
def paysign(app_id, body, mch_id, nonce_str, notify_url, openid, out_trade_no, spbill_create_ip, total_fee):
    ret = {
        "appid": app_id,
        "body": body,
        "mch_id": mch_id,
        "nonce_str": nonce_str,
        "notify_url": notify_url,
        "openid": openid,
        "out_trade_no": out_trade_no,
        "spbill_create_ip": spbill_create_ip,
        "total_fee": total_fee,
        "trade_type": 'JSAPI'
    }

    # 处理函数，对参数按照key=value的格式，并按照参数名ASCII字典序排序
    stringA = '&'.join(["{0}={1}".format(k, ret.get(k)) for k in sorted(ret)])
    stringSignTemp = '{0}&key={1}'.format(stringA, Mch_key)
    sign = hashlib.md5(stringSignTemp.encode("utf-8")).hexdigest()
    return sign.upper()


# 生成商品订单号，方式一：
def getWxPayOrdrID():
    import datetime

    date = datetime.datetime.now()
    # 根据当前系统时间来生成商品订单号。时间精确到微秒
    payOrdrID = date.strftime("%Y%m%d%H%M%S%f")
    return payOrdrID


# 获取返回给小程序的paySign
def get_paysign(prepay_id, timeStamp, nonceStr):
    pay_data = {
        'appId': client_appid,
        'nonceStr': nonceStr,
        'package': "prepay_id="+prepay_id,
        'signType': 'MD5',
        'timeStamp': timeStamp
    }
    stringA = '&'.join(["{0}={1}".format(k, pay_data.get(k))for k in sorted(pay_data)])
    stringSignTemp = '{0}&key={1}'.format(stringA, Mch_key)
    sign = hashlib.md5(stringSignTemp.encode("utf-8")).hexdigest()
    return sign.upper()


# 获取全部参数信息，封装成xml,传递过来的openid和客户端ip，和价格需要我们自己获取传递进来
def get_bodyData(openid, client_ip, price):
    body = 'Mytest'  # 商品描述
    notify_url = 'https:/.../'  # 填写支付成功的回调地址，微信确认支付成功会访问这个接口
    nonce_str = getNonceStr()  # 随机字符串
    out_trade_no = getWxPayOrdrID()  # 商户订单号
    total_fee = str(price)  # 订单价格，单位是 分
    # 获取签名
    sign = paysign(client_appid, body, Mch_id, nonce_str, notify_url, openid, out_trade_no, client_ip, total_fee)

    bodyData = '<xml>'
    bodyData += '<appid>' + client_appid + '</appid>'  # 小程序ID
    bodyData += '<body>' + body + '</body>'  # 商品描述
    bodyData += '<mch_id>' + Mch_id + '</mch_id>'  # 商户号
    bodyData += '<nonce_str>' + nonce_str + '</nonce_str>'  # 随机字符串
    bodyData += '<notify_url>' + notify_url + '</notify_url>'  # 支付成功的回调地址
    bodyData += '<openid>' + openid + '</openid>'  # 用户标识
    bodyData += '<out_trade_no>' + out_trade_no + '</out_trade_no>'  # 商户订单号
    bodyData += '<spbill_create_ip>' + client_ip + '</spbill_create_ip>'  # 客户端终端IP
    bodyData += '<total_fee>' + total_fee + '</total_fee>'  # 总金额 单位为分
    bodyData += '<trade_type>JSAPI</trade_type>'  # 交易类型 小程序取值如下：JSAPI

    bodyData += '<sign>' + sign + '</sign>'
    bodyData += '</xml>'

    return bodyData



