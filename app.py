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
    (r'/charge_status', ChargeStatusHandler),
    (r'/charge_details', ChargeDetailsHandler),
    (r'/charge_end', ChargeEndHandler),
    (r'/charge_balance', ChargeBalanceHandler),
    (r'/charge_map_list', ChargeMapList),
    # (r'/charge_station_details', ChargeStationDetailsHandler),
    (r'/charge_mind', MindRechargeHandler),
    (r'/charge_station_details', ChargeDetails),
    (r'/pay_order_list', PayOrderList),
    (r'/charge_order_list', ChargeOrderList),
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
