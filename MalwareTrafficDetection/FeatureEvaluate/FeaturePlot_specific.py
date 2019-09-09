
import glob
import numpy as np
import matplotlib.pyplot as plt

def read_features(feature_set_path):
    """
    read feature data into a list
    :param feature_set_path: the folder which keeps feature files
    :return: list: features, target
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

def get_xy(min, max, list):

    x = np.arange(min, max, (max - min) / 1000)
    x = x.tolist()
    x.append(x[-1]+(max - min) / 1000)
    y = [0] * len(x)
    for i in list:
        y[int((i - min) * 1000 / (max - min))] += 1
    return x, y

feature_set_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\features"
features, target = read_features(feature_set_path)
target_botnet = []
target_normal = []
features_botnet = []
features_normal = []
for i in range(0,len(target)):
    if target[i]=='botnet':
        target_botnet.append(target[i])
        features_botnet.append(features[i])
    else:
        target_normal.append(target[i])
        features_normal.append(features[i])

features_botnet = np.array(features_botnet)
features_normal = np.array(features_normal)


def config_plot(pltconfig, title, xlabel, ylabel, features_normal, features_botnet ):
    pltconfig.title(title)
    pltconfig.xlabel(xlabel)
    pltconfig.ylabel(ylabel)
    minx = min(features_normal+features_botnet)
    maxx = max(features_normal+features_botnet)
    x, y_normal = get_xy(minx, maxx, features_normal)
    x, y_botnet = get_xy(minx, maxx, features_botnet)
    line1, = pltconfig.plot(x, y_normal, 'b')
    line2, = pltconfig.plot(x, y_botnet, 'r')
    scale = max(y_botnet+y_normal)
    pltconfig.plot(features_botnet, [-scale/5]*len(features_botnet), 'r.')
    pltconfig.plot(features_normal, [-scale/10]*len(features_normal), 'b.')
    pltconfig.legend((line1, line2), ('botnet', 'normal'))

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#-----------------------------------------------------------------
#conn_duration: mean/standard deviation/standard deviation range
plt.figure(1)

plt.subplot(5,1,1)
config_plot(plt, 'CONN Duration Mean', 'time/ms', 'connection number', features_normal[:,0].tolist(), features_botnet[:,0].tolist())
plt.subplot(5,1,3)
config_plot(plt, 'CONN Duration Standard Deviation', 'time/ms', '', features_normal[:,1].tolist(), features_botnet[:,1].tolist())
plt.subplot(5,1,5)
config_plot(plt, 'CONN Duration Standard Deviation Range', 'percentage', '', features_normal[:,2].tolist(), features_botnet[:,2].tolist())


plt.show()
