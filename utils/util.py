import json
from hashlib import md5
import random
from tornado.web import MissingArgumentError
from tornado.web import HTTPError

import functools
from urllib.parse import urlencode
import urllib.parse as urlparse
from backend.redis_db import *
import logging


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='my.log', level=logging.DEBUG, format=LOG_FORMAT)


class RequestArgumentError(Exception):
    def __init__(self, msg='Unknown', code=233):
        self.msg = msg
        self.code = code
        super(RequestArgumentError, self).__init__(code, msg)
        
    def __str__(self):
        return self.msg


def random_str(random_length=16):
    strs = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    for i in range(len(chars)):
        strs += random.choice(chars)
    return strs


def clean_data(value):
    return value


def get_cleaned_post_data_httperror(handler, *args):
    '''
    获取post参数，在这个过程进行参数净化，如果缺少参数则raise HTTPError到BaseHandler的write_error()处理函数
    '''
    data={}
    for k in args:
        try:
            data[k]=handler.get_body_argument(k)
        except MissingArgumentError:
            raise HTTPError(400)
    return data


def get_cleaned_query_data_httperror(handler, *args):
    '''
    同上
    '''
    data = {}
    for k in args:
        try:
            data[k] = handler.get_query_argument(k)
        except MissingArgumentError:
            raise HTTPError(400)
    return data


def get_cleaned_query_data(handler, args, blank=False):
    '''
    这个是自定义异常的，然后到get/post去catch然后异常处理，不如raise HTTPError来的通用.
    '''
    data={}
    for k in args:
        try:
            data[k] = handler.get_query_argument(k)
        except MissingArgumentError:
            if blank:
                data[k] = None
            else:
                raise RequestArgumentError(k+'arg not found')
    return data


def get_cleaned_post_data(handler, args, blank=False):
    '''
    这个是自定义异常的，然后到get/post去catch然后异常处理，不如raise HTTPError来的通用.
    '''
    data = {}
    for k in args:
        try:
            data[k] = handler.get_body_argument(k)
        except MissingArgumentError:
            if blank:
                data[k] = None
            else:
                raise RequestArgumentError(k+' arg not found')
    return data


def login_required(method):
    from tornado.httpclient import HTTPError
    '''
    from "tornado.web.authenticated"
    `self.current_user`是一个@property
    '''
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        headers = self.request.headers
        logging.info("请求headers:%s" % headers)
        if headers.__contains__("Authorization"):
            authorization = headers["Authorization"]
            data = self.request.arguments
            logging.info("请求data:%s" % data)
            if data.__contains__("user_no"):
                cache_auth = db_redis.get("user_token_info_%s" % (str(data["user_no"][0], encoding="utf-8")))
                cache_auth = str(cache_auth, encoding="utf-8") if cache_auth else None
                logging.info("缓存:%s" % cache_auth)
                if cache_auth != authorization:
                    logging.info("缓存Authorization和请求头Authorization不一致:%s" % authorization)
                    return self.write("You have no access!")
                else:
                    return method(self, *args, **kwargs)
            else:
                return self.write("You have no access!")
        else:
            return self.write("You have no access!")
        # if not self.current_user:
        #     if self.request.method in ("GET", "HEAD"):
        #         url = self.get_login_url()
        #         if "?" not in url:
        #             if urlparse.urlsplit(url).scheme:
        #                 # if login url is absolute, make next absolute too
        #                 next_url = self.request.full_url()
        #             else:
        #                 next_url = self.request.uri
        #             url += "?" + urlencode(dict(next=next_url))
        #         self.redirect(url)
        #         return
        #     raise HTTPError(403)
    return wrapper


def set_api_header(request):
    request.set_header('Access-Control-Allow-Origin', '*')
    request.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
    request.set_header('Access-Control-Max-Age', 1000)
    request.set_header('Access-Control-Allow-Headers', '*')
    request.set_header('Content-type', 'application/json')


def json_result(code, data):
    if isinstance(data, str):
        result = {'code': code, 'txt': data}
    else:
        result = {'code': code, 'data': data}
    return json.dumps(result, default=str)


def generate_number_code(len = 4):
    ''' 随机生成4位的验证码 '''
    verification_code = ''
    for i in range(len):
        verification_code = verification_code + str(random.randint(1, 9))
    return verification_code


def trans_xml_to_dict(xml):
    """
    将微信支付交互返回的 XML 格式数据转化为 Python Dict 对象

    :param xml: 原始 XML 格式数据
    :return: dict 对象
    """

    soup = BeautifulSoup(xml, features='xml')
    xml = soup.find('xml')
    if not xml:
        return {}

    # 将 XML 数据转化为 Dict
    data = dict([(item.name, item.text) for item in xml.find_all()])
    return data