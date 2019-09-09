import numpy as np


a = [[1,2],[3,4]]
b = np.array(a)
print(b[:,0])

a = ["a","b","c","d"]
b = "haha"
c = [i+b for i in a]
print(c)
print([b]*10)

a = range(1, 20, 2)
print(a)

a = np.array([1,2,3])
b = np.array([4,5,6])
print(np.max(a+b))