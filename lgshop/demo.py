# @ Time    : 2021/2/3 21:26
# @ Author  : JuRan
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

# serializer = Serializer('xasd2343wrewrwe', 600)
#
# data = {'openid':  '1234'}
#
# # token bytes
# token = serializer.dumps(data)
#
# print(token)
#
#
# print(serializer.loads(token.decode()))


try:
    print(1)
except Exception as e:
    print(e)
else:
    print(2)
finally:
    print(3)
