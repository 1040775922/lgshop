from django.shortcuts import render
from django.views import View
from verifications.libs.captcha.captcha import captcha
from django_redis import get_redis_connection
from django import http
from utils.response_code import RETCODE
import random
from verifications.libs.ronglianyun.ccp_sms import CCP
from celery_tasks.sms.tasks import send_sms_code
from . import constants


class ImageCodeView(View):
    """图形验证码"""

    def get(self, request, uuid):
        """
        :param uuid: 通用唯一识别符,用于标识唯一图片验证码属于哪个用户的
        :return: image/jpg
        """

        # 生成图片验证码
        text, image = captcha.generate_captcha()
        # print(text, image)

        # 保存图像验证码,保存到redis
        redis_conn = get_redis_connection('verify_code')

        # name time value
        redis_conn.setex('img_%s' % uuid, constants.IMAGE_CODE_REDIS_EXPIRES, text)

        # 响应图形验证码
        return http.HttpResponse(image, content_type='image/png')


class SMSCodeView(View):
    """短信验证码"""

    def get(self, request, mobile):
        """
        :param mobile: 手机号
        :return: JSON
        """
        # http://127.0.0.1:8000/sms_codes/18646175116/?uuid=cea94f82-4329-41e4-80df-cca815875a43&image_code=XQDI
        # 接收参数，校验参数
        uuid = request.GET.get('uuid')
        image_code_client = request.GET.get('image_code')
        if not all([uuid, image_code_client]):
            return http.HttpResponseForbidden('缺少必传参数')

        # 提取图形验证码
        redis_conn = get_redis_connection('verify_code')

        # 判断用户是否频繁发生短信验证码
        send_flag = redis_conn.get('send_flag_%s' % mobile)
        if send_flag:
            return http.JsonResponse({'code': RETCODE.THROTTLINGERR, 'errmsg': '发送短信过于频繁'})

        image_code_server = redis_conn.get('img_%s' % uuid)
        # 提取图形验证码失效了
        if image_code_server is None:
            return http.JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图形验证码已失效'})

        # 删除图形验证码
        redis_conn.delete('img_%s' % uuid)

        # 对比图形验证码
        # print(image_code_client)    # kl5X
        # print(image_code_server)
        image_code_server = image_code_server.decode()
        if image_code_client.lower() != image_code_server.lower():
            return http.JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '输入图形验证码有误'})

        # 生成短信验证码
        # 生成6位的随机数  %6d
        sms_code = "%06d" % random.randint(0, 999999)

        # 保存短信验证码
        # redis_conn.setex('sms_%s' % mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code)
        # 保存发送短信验证码的标记
        # redis_conn.setex('send_flag_%s' % mobile, constants.SEND_SMS_CODE_TIMES, 1)

        # 创建管道
        pl = redis_conn.pipeline()
        # 将命令添加到队列
        # 保存短信验证码
        pl.setex('sms_%s' % mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code)
        # 保存发送短信验证码的标记
        pl.setex('send_flag_%s' % mobile, constants.SEND_SMS_CODE_TIMES, 1)
        # 执行
        pl.execute()

        # 发送短信 send_message(self, mobile, datas, tid): 300/60 浮点数
        # CCP().send_message(mobile, (sms_code, constants.SMS_CODE_REDIS_EXPIRES//60), constants.SEND_SMS_TEMPLATE_ID)
        # send_sms_code(mobile, sms_code)   错误的写法
        send_sms_code.delay(mobile, sms_code)
        # 响应结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '发送短信验证码成功'})


class CodeView(View):
    def get(self, request, uuid):
        text, image = captcha.generate_captcha()
        print(uuid)

        return http.HttpResponse(image, content_type='image/png')
