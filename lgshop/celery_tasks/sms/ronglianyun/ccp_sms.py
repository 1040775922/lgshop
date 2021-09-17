# @ Time    : 2021/1/27 20:02
# @ Author  : JuRan
from ronglian_sms_sdk import SmsSDK
import json

accId = '8a216da85741a1b901574fb0b1210982'
accToken = '15fb1a43ed5c4ddb83531b7e544448c5'
appId = '8a216da85741a1b901574fb0b17d0987'


# 单例设计模式
class CCP(object):
    def __new__(cls, *args, **kwargs):
        # 如果是第一次实例化,应该返回实例化后的对象,如果是第二次实例化,应该返回上一次实例化后的对象
        # 判断是否存在类属性 _instance
        if not hasattr(cls, "_instance"):
            # cls._instance => CCP()
            cls._instance = super(CCP, cls).__new__(cls, *args, **kwargs)
            # print(cls._instance)
            cls._instance.sdk = SmsSDK(accId, accToken, appId)
        return cls._instance

    def send_message(self, mobile, datas, tid):
        sdk = self._instance.sdk
        # tid = '1'
        # mobile = mobile
        # datas = ('1234', '5')
        resp = sdk.sendMessage(tid, mobile, datas)
        # print(resp)
        # print(type(resp))
        result = json.loads(resp)
        if result['statusCode'] == '000000':
            return 0
        else:
            return -1


# class A:
#     pass
#
# a = A()
# a.name = 'juran'
# print(dir(a))

if __name__ == '__main__':
    c = CCP()
    c.send_message('18646175116', ('1234', '5'), 1)
    # print(id(c))
    # c1 = CCP()
    # print(id(c1))
    # c2 = CCP()
    # print(id(c2))

