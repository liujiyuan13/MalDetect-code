import glob
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import cross_val_score
from sklearn import svm
from sklearn.linear_model import SGDClassifier
from sklearn import tree
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn import linear_model
from sklearn.model_selection import StratifiedKFold, GridSearchCV
from sklearn import metrics
import numpy

def read_features(feature_set_path):
    """
    read feature data into a list
    :param feature_set_path: the folder which keeps feature files
    :return: list
    """
    features = list()
    target = list()
    feature_paths = glob.glob(feature_set_path + "\\*")

    for path in feature_paths:
        with open(path) as f:
            for line in f:
                feature = list()
                split = line.split('\t')
                for cof in split:
                    if 'normal' in cof:
                        target.append('normal')
                    elif 'botnet' in cof:
                        target.append('botnet')
                    else:
                        feature.append(float(cof))
                features.append(feature)
            f.close()

    return features, target

def cal_index(test_target, predict):
    res = []
    test = []
    for i in range(0, len(test_target)):
        if test_target[i] == 'normal':
            test.append(0)
        else:
            test.append(1)
        if predict[i] == 'normal':
            res.append(0)
        else:
            res.append(1)

    accuracy = metrics.accuracy_score(test, res)
    average_precision = metrics.average_precision_score(test, res)
    recall = metrics.recall_score(test, res)

    return accuracy, average_precision, recall

def SVM_method(train_features, trian_target, test_features, test_target):

    print(">>>applying SVM method")

    clf = svm.SVC(C=2.0)
    clf.fit(train_features, trian_target)
    predict = clf.predict(test_features)

    return cal_index(test_target, predict)

def DT_method(train_features, train_target, test_features, test_target):

    print(">>>applying DT method")

    clf = tree.DecisionTreeClassifier()
    clf.fit(train_features, train_target)
    predict = clf.predict(test_features)

    return cal_index(test_target, predict)


def RF_method(train_features, train_target, test_features, test_target):

    print(">>>applying RF method")

    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(train_features, train_target)
    predict = clf.predict(test_features)

    return cal_index(test_target, predict)


def AdaBoost_method(train_features, train_target, test_features, test_target):

    print(">>>applying AdaBoost method")

    clf = AdaBoostClassifier(n_estimators=100)
    clf.fit(train_features, train_target)
    predict = clf.predict(test_features)

    return cal_index(test_target, predict)


def GradientTreeBoost_method(train_features, train_target, test_features, test_target):

    print(">>>applying Gradient Tree method")

    clf = GradientBoostingClassifier(n_estimators=100)
    clf.fit(train_features, train_target)
    predict = clf.predict(test_features)

    return cal_index(test_target, predict)


def NN_method(train_features, train_target, test_features, test_target):

    print(">>>applying Neural Network method")

    clf = MLPClassifier()
    clf.fit(train_features, train_target)
    predict = clf.predict(test_features)

    return cal_index(test_target, predict)

def LR_method(features, target):

    print(">>>applying Linear Regression method")

    label =  []
    for i in target:
        if i in 'normal':
            label.append(0)
        else:
            label.append(1)
    clf = linear_model.LinearRegression()
    clf.fit(features[:int(len(features)*4/5)], label[:int(len(features)*4/5)])
    predict = clf.predict(features[int(len(features)*4/5):]).tolist()
    test = label[int(len(features)*4/5):]
    # n = 0
    # for i in range(0, len(test)):
    #     if (res[i]<0.5 and test[i]==0) or (res[i]>0.5 and test[i]==1):
    #         n += 1
    res = []
    for i in predict:
        if i>0.5:
            res.append(1)
        else:
            res.append(0)
    return metrics.accuracy_score(test, res), metrics.average_precision_score(test, res), metrics.recall_score(test, res)


feature_set_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\features"
features, target = read_features(feature_set_path)

normal_featuers = []
botnet_features = []
num = len(target)
for i in range(0, num):
    if target[i] == 'normal':
        normal_featuers.append(features[i])
    else:
        botnet_features.append(features[i])

train_features = normal_featuers[0:int(len(normal_featuers)*4/5)]
test_features = normal_featuers[int(len(normal_featuers)*4/5):]
train_target = ['normal']*len(train_features)
test_target = ['normal']*len(test_features)

seg = int(len(normal_featuers)*4/5)
train_features = train_features + botnet_features[0:seg]
test_features = test_features + botnet_features[seg:len(normal_featuers)]
train_target = train_target + ['botnet']*seg
test_target = test_target + ['botnet']*(len(normal_featuers)-seg)


print("features number:", len(train_features)+len(test_features))
print("train number: ", len(train_features))
print("test number: ", len(test_features))

res = SVM_method(numpy.array(train_features), numpy.array(train_target), numpy.array(test_features), numpy.array(test_target))
print(res)
res = DT_method(train_features, train_target, test_features, test_target)
print(res)

res = RF_method(train_features, train_target, test_features, test_target)
print(res)

res = AdaBoost_method(train_features, train_target, test_features, test_target)
print(res)


res = GradientTreeBoost_method(train_features, train_target, test_features, test_target)
print(res)

res = NN_method(train_features, train_target, test_features, test_target)
print(res)


res = LR_method(features, target)
print(res)