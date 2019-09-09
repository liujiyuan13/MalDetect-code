# import re
# import os
#
# a = dict()
# a["hello"] = 1
# a["b"] = 1
# print("b" in a)
# a.pop("b")
# print(a)
# for i in a.keys():
#     print(i)
# print(3/9)
#
# print(float("0.12")==0.12)
# print(type(str(1.23)))
# print("a",2)
#
# str = str(2)  + '\t' + str(3)
# print(str)
# print(type(str))
#
#
# def checkip(ip):
#     p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
#     if p.match(ip):
#         return True
#     else:
#         return False
#
# print(checkip("192.168.12.12"))
# print(checkip("19.12.12"))
# print(checkip("dafjk"))
#
# print("adffas".split(','))
#
#
# a = ['1','2']
# print(3*['1', '2'])
# print(3*'1,3')
# d = {'1':'2','4':'5'}
# for a in d:
#     print(a)
#
# class Dog:
#     id = 0
#     a = []
#     b = []
#     def __init__(self, p):
#         self.id = p
#         self.a = []
#         self.b = []
#     def output(self):
#         print(self.a, self.b)
#     def adda(self, word):
#         self.a.append(word)
#     def addb(self,word):
#         self.b.append(word)
#
# dog1 = Dog(1)
# dog1.adda('fdaf')
# dog1.addb('dafdf')
#
# dog2 = Dog(2)
# dog2.adda('jlkj')
# dog2.addb('dhg')
#
# dog1.output()
# dog2.output()
#
# print( ((63158399.0 **2) *20)**0.5)
#
# print(['1']*3+['2'])
#
# path = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
# downloaded_datasets = os.listdir(path)
# print(downloaded_datasets)
#
# with open("temp.txt", 'w') as f:
#     line = ""
#     for i in ['1','2']:
#         line += (i + '\t')
#     f.write(line[:-1])
#     f.close()
#
# a = "abcd"
# b = "ab"
# print(a.replace(b,""))

a = [0,1,2,3,4]
print(a[0:2])
s = set()
s.add(5)
print(set)