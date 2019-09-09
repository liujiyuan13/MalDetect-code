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

def SVM_method(features, target):

    print(">>>applying SVM method")

    clf = svm.SVC()
    k_fold = StratifiedKFold(n_splits=10)
    scores = cross_val_score(clf, features, target, cv=k_fold)
    print(scores.mean())

    # svc = svm.SVC()
    # k_fold = StratifiedKFold(n_splits=10)
    # c = np.linspace(0.01, 3, 100)
    # tuned_param = [{'C':c}]
    #
    # clf = GridSearchCV(estimator=svc, param_grid=tuned_param ,cv=k_fold)
    #
    # clf.fit(features, target)
    #
    # scores = clf.cv_results_['mean_test_score']
    # scores_std = clf.cv_results_['std_test_score']
    # plt.figure().set_size_inches(8,6)
    # plt.plot(c, scores)
    #
    # # plot error lines showing +/- std. errors of the scores
    # std_error = scores_std / np.sqrt(clf.n_splits_)
    #
    # plt.plot(c, scores + std_error, 'b--')
    # plt.plot(c, scores - std_error, 'b--')
    #
    # # alpha=0.2 controls the translucency of the fill color
    # plt.fill_between(c, scores + std_error, scores - std_error, alpha=0.2)
    #
    # plt.title('SVC method')
    # plt.ylabel('CV score +/- std error')
    # plt.xlabel('C')
    # plt.axhline(np.max(scores), linestyle='--', color='.5')
    # plt.xlim([c[0], c[-1]])
    #
    # plt.show()

def SGD_method(features, target):

    print(">>>applying SGD method")

    clf = SGDClassifier(loss="hinge")
    k_fold = StratifiedKFold(n_splits=10)
    scores = cross_val_score(clf, features, target, cv=k_fold)
    print(scores.mean())


def DT_method(features, target):

    print(">>>applying DT method")

    clf = tree.DecisionTreeClassifier()
    k_fold = StratifiedKFold(n_splits=10)
    scores = cross_val_score(clf, features, target, cv=k_fold)
    print(scores.mean())


def RF_method(features, target):

    print(">>>applying RF method")

    clf = RandomForestClassifier(n_estimators=100)
    k_fold = StratifiedKFold(n_splits=10)
    scores = cross_val_score(clf, features, target, cv=k_fold)
    print(scores.mean())


def AdaBoost_method(features, target):

    print(">>>applying AdaBoost method")

    clf = AdaBoostClassifier(n_estimators=100)
    k_fold = StratifiedKFold(n_splits=10)
    scores = cross_val_score(clf, features, target, cv=k_fold)
    print(scores.mean())


def GradientTreeBoost_method(features, target):

    print(">>>applying Gradient Tree method")

    clf = GradientBoostingClassifier(n_estimators=100)
    k_fold = StratifiedKFold(n_splits=10)
    scores = cross_val_score(clf, features, target, cv=k_fold)
    print(scores.mean())


def NN_method(features, target):

    print(">>>applying Neural Network method")

    clf = MLPClassifier()
    k_fold = StratifiedKFold(n_splits=10)
    scores = cross_val_score(clf, features, target, cv=k_fold)
    print(scores.mean())



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
    res = clf.predict(features[int(len(features)*4/5):]).tolist()
    test = label[int(len(features)*4/5):]
    n = 0
    for i in range(0, len(test)):
        if (res[i]<0.5 and test[i]==0) or (res[i]>0.5 and test[i]==1):
            n += 1
    print(n/len(test))


feature_set_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\features"
features, target = read_features(feature_set_path)

print("features number:", len(features))
SVM_method(features, target)
# SGD_method(features, target)
DT_method(features, target)
RF_method(features, target)
AdaBoost_method(features, target)
GradientTreeBoost_method(features, target)
NN_method(features, target)

LR_method(features, target)