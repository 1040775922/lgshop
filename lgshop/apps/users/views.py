from django.shortcuts import render, redirect, reverse
from django.views import View
from django import http
from .forms import RegisterForm, LoginForm
from .models import User, Address
# from users.models import User
from django.contrib.auth import login, authenticate, logout
from utils.response_code import RETCODE
from django_redis import get_redis_connection
from django.contrib.auth.hashers import check_password
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.mixins import LoginRequiredMixin
from utils.views import LoginRequiredJSONMixin
import json, re
from django.core.mail import send_mail
from django.conf import settings
from celery_tasks.email.tasks import send_verify_email
from .utils import generate_verify_email_url, check_verify_email_token
from . import constants
import logging
from contents.models import Content

logger = logging.getLogger('django')


class ChangePasswordView(LoginRequiredMixin, View):
    """修改密码"""

    def get(self, request):
        """展示修改密码界面"""
        return render(request, 'user_center_pass.html')

    def post(self, request):
        """实现修改密码逻辑"""
        # 接收参数
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        new_password2 = request.POST.get('new_password2')

        # 校验参数
        if not all([old_password, new_password, new_password2]):
            return http.HttpResponseForbidden('缺少必传参数')
        try:
            result = request.user.check_password(old_password)
            if not result:
                return render(request, 'user_center_pass.html', {'origin_pwd_errmsg': '原始密码错误'})
        except Exception as e:
            logger.error(e)
            return render(request, 'user_center_pass.html', {'origin_pwd_errmsg':'原始密码错误'})
        if not re.match(r'^[0-9A-Za-z]{8,20}$', new_password):
            return http.HttpResponseForbidden('密码最少8位，最长20位')
        if new_password != new_password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')

        # 修改密码
        try:
            request.user.set_password(new_password)
            request.user.save()
        except Exception as e:
            logger.error(e)
            return render(request, 'user_center_pass.html', {'change_pwd_errmsg': '修改密码失败'})

        # 清理状态保持信息
        logout(request)
        response = redirect(reverse('users:login'))
        response.delete_cookie('username')

        # 响应密码修改结果：重定向到登录界面
        return response


class UpdateTitleAddressView(LoginRequiredJSONMixin, View):
    """设置地址标题"""

    def put(self, request, address_id):
        """设置地址标题"""
        # 接收参数：地址标题
        json_dict = json.loads(request.body.decode())
        title = json_dict.get('title')

        try:
            # 查询地址
            address = Address.objects.get(id=address_id)

            # 设置新的地址标题
            address.title = title
            address.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '设置地址标题失败'})

        # 4.响应删除地址结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '设置地址标题成功'})


class DefaultAddressView(View):
    """设置默认地址"""
    def put(self, request, address_id):
        # 用户表 default_address
        try:
            # , user=request.user
            address = Address.objects.get(id=address_id)
            request.user.default_address = address
            request.user.save()
        except Exception as e:
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '设置默认地址失败'})

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '设置默认地址成功'})


class UpdateDestoryAddressView(LoginRequiredJSONMixin, View):
    """更新和删除地址"""

    def put(self, request, address_id):
        # 接收参数
        print(request.COOKIES)
        print(request.body)
        print(request.COOKIES.get('sessionid'))
        json_str = request.body.decode()
        print(json_str)
        json_dict = json.loads(json_str)
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')

        # 校验参数
        if not all([receiver, province_id, city_id, district_id, place, mobile]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')

        # 更新数据
        # address = Address.objects.get(id=address_id)
        # address.title = receiver
        # address.save()
        try:
            # update 返回受影响的行数
            Address.objects.filter(id=address_id).update(
                user=request.user,
                title=receiver,
                receiver=receiver,
                province_id=province_id,
                city_id=city_id,
                district_id=district_id,
                place=place,
                mobile=mobile,
                tel=tel,
                email=email,
            )
        except Exception as e:
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '修改地址失败'})

        address = Address.objects.get(id=address_id)

        address_dict = {
            'id': address.id,
            'receiver': address.title,
            'province': address.province.name,
            'city': address.city.name,
            'district': address.district.name,
            'place': address.place,
            'mobile': address.mobile,
            'tel': address.tel,
            'email': address.email
        }
        # 响应新的地址给前端渲染
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '修改地址成功', 'address': address_dict})

    def delete(self, request, address_id):
        """删除地址"""
        # 逻辑删除(修改 is_deleted=True) 还是 物理删除
        try:
            address = Address.objects.get(id=address_id)
            address.is_deleted = True
            address.save()
        except Exception as e:
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '删除地址失败'})

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '删除地址成功'})


class AddressCreateView(LoginRequiredJSONMixin, View):
    """新增地址"""

    def post(self, request):
        """新增地址逻辑"""

        # 判断用户地址是否超过上限:查询当前登录用户的地址数量
        count = Address.objects.filter(user=request.user).count()
        if count > constants.USER_ADDRESS_COUNTS_LIMIT:
            return http.JsonResponse({'code': RETCODE.THROTTLINGERR, 'errmsg': '超出用户地址上限'})

        # 接收参数
        json_str = request.body.decode()
        json_dict = json.loads(json_str)
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')

        # 校验参数
        if not all([receiver, province_id, city_id, district_id, place, mobile]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')

        # 保存用户传入的数据
        try:
            address = Address.objects.create(
                user=request.user,
                title=receiver,
                receiver=receiver,
                province_id=province_id,
                city_id=city_id,
                district_id=district_id,
                place=place,
                mobile=mobile,
                tel=tel,
                email=email,
            )
            # 设置默认的收获地址
            if not request.user.default_address:
                request.user.default_address = address
                request.user.save()

        except Exception as e:
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '新增地址失败'})


        address_dict = {
            'id': address.id,
            'receiver': address.title,
            'province': address.province.name,
            'city': address.city.name,
            'district': address.district.name,
            'place': address.place,
            'mobile': address.mobile,
            'tel': address.tel,
            'email': address.email
        }

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '新增地址成功', 'address': address_dict})


class AddressView(LoginRequiredMixin, View):
    """用户收货地址"""

    def get(self, request):
        """提供收货地址界面"""

        login_user = request.user
        # 查询登录用户的地址
        addresses = Address.objects.filter(user=login_user, is_deleted=False)

        address_list = []
        for address in addresses:
            address_dict = {
                'id': address.id,
                'title': address.title,
                'receiver': address.receiver,
                'province': address.province.name,
                'city': address.city.name,
                'district': address.district.name,
                'place': address.place,
                'mobile': address.mobile,
                'tel': address.tel,
                'email': address.email
            }
            address_list.append(address_dict)
        context = {
            'addresses': address_list,
            'default_address_id': login_user.default_address_id
        }


        return render(request, 'user_center_site.html', context)


class VerifyEmailView(View):
    """验证邮箱"""

    def get(self, request):
        # 接收
        token = request.GET.get('token')

        if not token:
            return http.HttpResponseForbidden('缺少token')
        # 解密 token => user {'user_id': 1, 'email': 'xxxx@qq.com'}
        # 查询用户
        user = check_verify_email_token(token)
        if user.email_active == 0:
            # 没有激活 email_active 设置为true
            user.email_active = True
            user.save()
        else:
            # email_active 是否已经激活
            return http.HttpResponseForbidden('邮箱已经被激活')

        # 响应结果
        return redirect(reverse('users:info'))


class EmailView(LoginRequiredJSONMixin, View):
    """添加邮箱"""

    # 没有登录就可以访问

    def put(self, request):
        # 接收参数
        json_str = request.body.decode()
        json_dict = json.loads(json_str)
        email = json_dict.get('email')

        # 校验参数
        if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return http.HttpResponseForbidden('参数邮箱有误')

        # 存数据
        try:
            request.user.email = email
            request.user.save()
        except Exception as e:
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '添加邮箱失败'})
        # 发送邮件
        # subject = "商城邮箱验证"
        # html_message = '<p>尊敬的用户您好！</p>' \
        #                '<p>感谢您使用商城。</p>' \
        #                '<p>您的邮箱为：%s 。请点击此链接激活您的邮箱：</p>' \
        #                '<p><a href="%s">%s<a></p>' % (email, 'www.baidu.com', 'www.baidu.com')
        #
        # send_mail(subject, '', from_email=settings.EMAIL_FROM, recipient_list=[email], html_message=html_message)
        verify_url = generate_verify_email_url(request.user)
        # 发送邮件
        send_verify_email.delay(email, verify_url)

        # 响应结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})


class UserInfoView(LoginRequiredMixin, View):
    """用户个人中心"""

    # login_url = '/users/login/'

    def get(self, request):
        """提供用户个人页面"""
        # print(request)
        # 优化的地方
        # if request.user.is_authenticated:
        #     # 已经登录
        #     return render(request, 'user_center_info.html')
        # else:
        #     # 未登陆
        #     return redirect(reverse('users:login'))
        # http://127.0.0.1:8000/users/login/?next=/users/info/
        # LOGIN_URL = '/accounts/login/'    # 没有登录跳转的链接
        # REDIRECT_FIELD_NAME = 'next'      #  没有登录要访问的链接的参数
        # login_url = '/users/login/'
        context = {
            "username": request.user.username,
            "mobile": request.user.mobile,
            "email": request.user.email,
            "email_active": request.user.email_active,
        }
        return render(request, 'user_center_info.html', context=context)


class LogoutView(View):
    """用户退出登录"""

    def get(self, request):
        """实现用户退出登录的逻辑"""
        # 清除状态保持信息
        logout(request)

        # 重定向
        response = redirect(reverse('contents:index'))

        # 删除cookie
        response.delete_cookie('username')

        return response


class LoginView(View):
    """用户名登录"""

    def get(self, request):
        """
        提供登录页面
        :return: 登录页面
        """
        return render(request, 'login.html')

    def post(self, request):
        """
        实现登录业务逻辑
        :return: 登录结果
        """
        # 接收请求,提取参数
        login_form = LoginForm(request.POST)
        if login_form.is_valid():
            username = login_form.cleaned_data.get('username')
            password = login_form.cleaned_data.get('password')
            remembered = login_form.cleaned_data.get('remembered')

            if not all([username, password]):
                print('1213')
                return http.HttpResponseForbidden('缺少必传参数')

            # 认证登录用户
            # user = User.objects.get(username=username)
            # pwd = user.password  # 密文
            # user.check_password()
            # if check_password(password, pwd):
            #     print('密码正确')
            # else:
            #     print('密码错误')
            user = authenticate(username=username, password=password)
            # print(user)
            if user is None:
                return render(request, 'login.html', {'account_errmsg': '账号或密码错误'})
            # 状态保持
            login(request, user)

            if remembered != True:
                # 没有记住登录  浏览器关闭就销毁
                request.session.set_expiry(0)
            else:
                # 记住登录  状态保持默认为2周
                request.session.set_expiry(None)

            next = request.GET.get('next')
            print(next)
            if next:
                response = redirect(next)
            else:
                # 为了实现在首页显示用户名 需要将用户设置到cookie中
                response = reverse('contents:index')
                print(response)
                response = redirect(reverse('contents:index'))
                print(response)

            # response.set_cookie('key', 'value', 'expiry')
            # print(type(user))
            # print(user)   __str__
            response.set_cookie('username', user.username, max_age=3600 * 24)

            # 响应结果 重定向到首页
            return response
        else:
            # print(login_form.errors)
            # print(login_form.errors.get_json_data())
            context = {
                'forms_errors': login_form.errors
            }
            return render(request, 'login.html', context=context)


class RegisterView(View):

    def get(self, request):
        """提供用户注册页面"""
        return render(request, 'register.html')

    def post(self, request):
        """提供用户注册逻辑"""
        # 校验参数
        register_form = RegisterForm(request.POST)

        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password = register_form.cleaned_data.get('password')
            mobile = register_form.cleaned_data.get('mobile')

            # 短信验证码
            sms_code_client = register_form.cleaned_data.get('sms_code')

            # 判断短信验证码输入是否正确
            redis_conn = get_redis_connection('verify_code')
            sms_code_server = redis_conn.get('sms_%s' % mobile)

            if sms_code_server.decode() is None:
                return render(request, 'register.html', {'sms_code_errmsg': '短信验证码已失效'})
            # print(sms_code_server.decode())
            # print(sms_code_client)

            if sms_code_server.decode() != sms_code_client:
                return render(request, 'register.html', {'sms_code_errmsg': '输入短信验证码有误'})

            # 保存到数据库中
            try:
                user = User.objects.create_user(username=username, password=password, mobile=mobile)
            except Exception as e:
                return render(request, 'register.html', {'register_errmsg': '注册失败'})

            # 状态保持
            login(request, user)

            # response.set_cookie('username', user.username, max_age=3600 * 24)

            # 响应结果
            # return http.HttpResponse('注册成功, 重定向到首页')
            return redirect(reverse('contents:index'))
        else:
            print(register_form.errors.get_json_data())
            context = {
                'forms_errors': register_form.errors
            }
            return render(request, 'register.html', context=context)


class UsernameCountView(View):
    """判断用户名是否重复注册"""

    def get(self, request, username):
        """
        :param username: 用户名
        :return: 返回用户名是否重复  JSON
        """

        count = User.objects.filter(username=username).count()
        print(username)

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'count': count})

class Check(View):
    def get(self, request):
        id = request.GET.get('id')
        prices = Content.objects.filter(id = id)
        for price in prices:
            p = {
                'id':price.id,
                'title':price.title,
            }
            print(p)
        redis_conn = get_redis_connection('verify_code')

        # name time value
        redis_conn.setex('id' , '300' , 555 )
        send_flag = redis_conn.get('id')
        print(send_flag)

        request.session['id'] = '1234'
        reponse = http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'count':'1'})
        reponse.set_cookie('username', '5555', max_age=3600 * 24)
        return reponse


    def post(self, request):
        id = request.session.get('id','12345')
        print(id)

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'count':'2'})
"""
    

"""
