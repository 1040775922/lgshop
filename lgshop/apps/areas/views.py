from django.shortcuts import render
from django.views import View
from .models import Area,Areal
from django import http
from utils.response_code import RETCODE
from django.core.cache import cache


class AreasView(View):
    """省市区三级联动"""
    def get(self, request):
        # 判断当前是要查询省份数据还是市区数据
        area_id = request.GET.get('area_id')

        if not area_id:
            # r = get_redis_connection('xxxx')
            # r.setex
            province_list = cache.get('province_list')
            if not province_list:
                try:
                    # 查询省级数据   parent_id null
                    province_model_list = Area.objects.filter(parent_id__isnull=True)
                    province_list = []
                    for province_model in province_model_list:
                        province_dict = {
                            "id": province_model.id,
                            "name": province_model.name
                        }
                        province_list.append(province_dict)

                    # 将数据缓存到redis中
                    cache.set('province_list', province_list, 3600)
                    # return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'province_list': province_list})
                except Exception as e:
                    return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '查询省份数据错误'})
            # else:
            return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'province_list': province_list})

        else:
            sub_data = cache.get('sub_area_' + area_id)
            if not sub_data:
                try:
                    # 查询市区数据
                    # 一查多  area_id = 1300000
                    # print(Area.objects.filter(parent_id=area_id))
                    parent_model = Area.objects.get(id=area_id)
                    # parent_model.area_set.all()
                    sub_model_list = parent_model.subs.all()

                    subs = []
                    for sub_model in sub_model_list:
                        sub_dict = {
                            'id': sub_model.id,
                            'name': sub_model.name
                        }
                        subs.append(sub_dict)

                    sub_data = {
                        'id': parent_model.id,
                        'name': parent_model.name,
                        'subs': subs
                    }
                    cache.set('sub_area_' + area_id, sub_data, 3600)
                    # return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'sub_data': sub_data})
                except Exception as e:
                    return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '查询市区数据错误'})
            return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'sub_data': sub_data})




    def post(self,request):
        province_model_list = Areal.objects.filter(id = 110000)
        province_list = []
        for province_model in province_model_list:
            province_dict = {
                "id": province_model.id,
                "name": province_model.name
            }
            province_list.append(province_dict)
            print(province_dict)
        return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '查询市区数据错误','sub_data': province_list})