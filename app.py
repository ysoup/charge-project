#!/usr/bin/env python
# coding:utf-8

import tornado.web
import tornado.ioloop
from os import path
from sys import argv

import config
from handlers.basehandlers.basehandler import ErrorHandler
from handlers.index import *

handlers = [
    (r'/login', LoginHandler),
    (r'/chat_login', ChatLoginHandler),
    (r'/user_info', UserInfoHandler),
    (r'/chat_pay', WeChatPayHandler),
    (r'/sms', SmsHandler),
    (r'/user_login', UserLoginHandler),
    (r'/login_out', LoginOutHandler),
    (r'/notify', PayNotifyHandler),
    (r'/charge', ChargeStationHandler),
    (r'/charge_status', ChargeStatusHandler)
]

application = tornado.web.Application(
    handlers=handlers,
    default_handler_class=ErrorHandler,
    debug=config.DEBUG,
    static_path=path.join(path.dirname(path.abspath(__file__)), 'static'),
    template_path="templates",
    login_url='/login',
    cookie_secret=config.COOKIE_SECRET,
)

config.app = application

if __name__ == "__main__":
    if len(argv) > 1 and argv[1][:6] == '-port=':
        config.PORT = int(argv[1][6:])

    application.listen(config.PORT)
    print('Server started at port %s' % config.PORT)
    tornado.ioloop.IOLoop.instance().start()
