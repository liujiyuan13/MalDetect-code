
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

##print the dataset information
print(">>>Total traffic number is : ", len(target_normal)+len(target_botnet))
print(">>>In them, normal/malware is : ", len(target_normal), "/", len(target_botnet))


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#-----------------------------------------------------------------
#conn_duration: mean/standard deviation/standard deviation range
plt.figure(1)

plt.subplot(5,1,1)
plt.title('CONN Duration Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,0], target_normal, '.')
plt.plot(features_botnet[:,0], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CONN Duration Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,1], target_normal, '.')
plt.plot(features_botnet[:,1], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CONN Duration Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,2], target_normal, '.')
plt.plot(features_botnet[:,2], target_botnet, '.')

plt.savefig("Figures/conn_duration_mean.pdf")


#-----------------------------------------------------------------
#conn_orig_bytes: mean/standard deviation/standard deviation range
plt.figure(2)

plt.subplot(5,1,1)
plt.title('CONN Original Bytes Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,3], target_normal, '.')
plt.plot(features_botnet[:,3], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CONN Original Bytes Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,4], target_normal, '.')
plt.plot(features_botnet[:,4], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CONN Original Bytes Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,5], target_normal, '.')
plt.plot(features_botnet[:,5], target_botnet, '.')

#-----------------------------------------------------------------
#conn_resp_bytes: mean/standard deviation/standard deviation range
plt.figure(3)

plt.subplot(5,1,1)
plt.title('CONN Response Bytes Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,6], target_normal, '.')
plt.plot(features_botnet[:,6], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CONN Response Bytes Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,7], target_normal, '.')
plt.plot(features_botnet[:,7], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CONN Response Bytes Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,8], target_normal, '.')
plt.plot(features_botnet[:,8], target_botnet, '.')

#-----------------------------------------------------------------
#conn_orig_bytes_ratio
plt.figure(4)

plt.subplot()
plt.title('CONN Original Bytes Ratio (OB/OB+RB)')
plt.xlabel('percentage')
plt.plot(features_normal[:,9], target_normal, '.')
plt.plot(features_botnet[:,9], target_botnet, '.')

#-----------------------------------------------------------------
#conn_orig_pkts: mean/standard deviation/standard deviation range
plt.figure(5)

plt.subplot(5,1,1)
plt.title('CONN Original Packets Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,10], target_normal, '.')
plt.plot(features_botnet[:,10], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CONN Original Packets Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,11], target_normal, '.')
plt.plot(features_botnet[:,11], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CONN Original Packets Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,12], target_normal, '.')
plt.plot(features_botnet[:,12], target_botnet, '.')

#-----------------------------------------------------------------
#conn_resp_pkts: mean/standard deviation/standard deviation range
plt.figure(6)

plt.subplot(5,1,1)
plt.title('CONN Response Packets Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,13], target_normal, '.')
plt.plot(features_botnet[:,13], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CONN Response Packets Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,14], target_normal, '.')
plt.plot(features_botnet[:,14], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CONN Response Packets Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,15], target_normal, '.')
plt.plot(features_botnet[:,15], target_botnet, '.')

#-----------------------------------------------------------------
#conn_orig_pkts_ratio
plt.figure(7)

plt.subplot()
plt.title('CONN Original Packets Ratio (OP/OP+RP)')
plt.xlabel('percentage')
plt.plot(features_normal[:,16], target_normal, '.')
plt.plot(features_botnet[:,16], target_botnet, '.')

#-----------------------------------------------------------------
#conn_periodicity: mean/standard deviation/standard deviation range
plt.figure(8)

plt.subplot(5,1,1)
plt.title('CONN Periodicity Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,17], target_normal, '.')
plt.plot(features_botnet[:,17], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CONN Periodicity Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,18], target_normal, '.')
plt.plot(features_botnet[:,18], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CONN Periodicity Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,19], target_normal, '.')
plt.plot(features_botnet[:,19], target_botnet, '.')

#-----------------------------------------------------------------
#conn_state_ratio: [S0 S1 SF REJ S2 S3 RSTO RSTR RSTOS0 RSTRH SH SHR OTH]
plt.figure(9)

plt.subplot()
plt.title('CONN State Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,20], ['Normal_S0']*len(target_normal), 'b.')
plt.plot(features_botnet[:,20], ['Botnet_S0']*len(target_botnet), 'b.')
plt.plot(features_normal[:,21], ['Normal_S1']*len(target_normal), 'cx')
plt.plot(features_botnet[:,21], ['Botnet_S1']*len(target_botnet), 'cx')
plt.plot(features_normal[:,22], ['Normal_SF']*len(target_normal), 'go')
plt.plot(features_botnet[:,22], ['Botnet_SF']*len(target_botnet), 'go')
plt.plot(features_normal[:,23], ['Normal_REJ']*len(target_normal), 'k1')
plt.plot(features_botnet[:,23], ['Botnet_REJ']*len(target_botnet), 'k1')
plt.plot(features_normal[:,24], ['Normal_S2']*len(target_normal), 'm2')
plt.plot(features_botnet[:,24], ['Botnet_S2']*len(target_botnet), 'm2')
plt.plot(features_normal[:,25], ['Normal_S3']*len(target_normal), 'r3')
plt.plot(features_botnet[:,25], ['Botnet_S3']*len(target_botnet), 'r3')
plt.plot(features_normal[:,26], ['Normal_RSTO']*len(target_normal), 'y4')
plt.plot(features_botnet[:,26], ['Botnet_RSTO']*len(target_botnet), 'y4')
plt.plot(features_normal[:,27], ['Normal_RSTR']*len(target_normal), 'ys')
plt.plot(features_botnet[:,27], ['Botnet_RSTR']*len(target_botnet), 'ys')
plt.plot(features_normal[:,28], ['Normal_RSTOS0']*len(target_normal), 'bp')
plt.plot(features_botnet[:,28], ['Botnet_RSTOS0']*len(target_botnet), 'bp')
plt.plot(features_normal[:,29], ['Normal_RSTRH']*len(target_normal), 'c*')
plt.plot(features_botnet[:,29], ['Botnet_RSTRH']*len(target_botnet), 'c*')
plt.plot(features_normal[:,30], ['Normal_SH']*len(target_normal), 'gh')
plt.plot(features_botnet[:,30], ['Botnet_SH']*len(target_botnet), 'gh')
plt.plot(features_normal[:,31], ['Normal_SHR']*len(target_normal), 'kd')
plt.plot(features_botnet[:,31], ['Botnet_SHR']*len(target_botnet), 'kd')
plt.plot(features_normal[:,32], ['Normal_OTH']*len(target_normal), 'm+')
plt.plot(features_botnet[:,32], ['Botnet_OTH']*len(target_botnet), 'm+')


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#-----------------------------------------------------------------
#ssl_ratio
plt.figure(10)

plt.subplot()
plt.title('SSL Ratio (SLL/CONN)')
plt.xlabel('percentage')
plt.plot(features_normal[:,33], target_normal, '.')
plt.plot(features_botnet[:,33], target_botnet, '.')

#-----------------------------------------------------------------
#ssl_version_ratio: ['-', 'TLSv10', 'SSLv3', 'SSLv2']
plt.figure(11)

plt.subplot()
plt.title('SSL Version Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,34], ['Normal_NOT_KOWN']*len(target_normal), 'b.')
plt.plot(features_botnet[:,34], ['Botnet_NOT_KOWN']*len(target_botnet), 'b.')
plt.plot(features_normal[:,35], ['Normal_TLSv10']*len(target_normal), 'cx')
plt.plot(features_botnet[:,35], ['Botnet_TLSv10']*len(target_botnet), 'cx')
plt.plot(features_normal[:,36], ['Normal_SSLv3']*len(target_normal), 'go')
plt.plot(features_botnet[:,36], ['Botnet_SSLv3']*len(target_botnet), 'go')
plt.plot(features_normal[:,37], ['Normal_SSLv2']*len(target_normal), 'k1')
plt.plot(features_botnet[:,37], ['Botnet_SSLv2']*len(target_botnet), 'k1')

#-----------------------------------------------------------------
#ssl_cipher_ratio: ['-', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_DH_ANON_WITH_RC4_128_MD5', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_RC4_128_MD5', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'SSLv20_CK_RC4_128_WITH_MD5', 'SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5']
#[c00 - c16]
plt.figure(12)

plt.subplot()
plt.title('SSL Cipher Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,38], ['Normal_c00']*len(target_normal), 'b.')
plt.plot(features_botnet[:,38], ['Botnet_c00']*len(target_botnet), 'b.')
plt.plot(features_normal[:,39], ['Normal_c01']*len(target_normal), 'cx')
plt.plot(features_botnet[:,39], ['Botnet_c01']*len(target_botnet), 'cx')
plt.plot(features_normal[:,40], ['Normal_c02']*len(target_normal), 'go')
plt.plot(features_botnet[:,40], ['Botnet_c02']*len(target_botnet), 'go')
plt.plot(features_normal[:,41], ['Normal_c03']*len(target_normal), 'k1')
plt.plot(features_botnet[:,41], ['Botnet_c03']*len(target_botnet), 'k1')
plt.plot(features_normal[:,42], ['Normal_c04']*len(target_normal), 'm2')
plt.plot(features_botnet[:,42], ['Botnet_c04']*len(target_botnet), 'm2')
plt.plot(features_normal[:,43], ['Normal_c05']*len(target_normal), 'r3')
plt.plot(features_botnet[:,43], ['Botnet_c05']*len(target_botnet), 'r3')
plt.plot(features_normal[:,44], ['Normal_c06']*len(target_normal), 'y4')
plt.plot(features_botnet[:,44], ['Botnet_c06']*len(target_botnet), 'y4')
plt.plot(features_normal[:,45], ['Normal_c07']*len(target_normal), 'ys')
plt.plot(features_botnet[:,45], ['Botnet_c07']*len(target_botnet), 'ys')
plt.plot(features_normal[:,46], ['Normal_c08']*len(target_normal), 'bp')
plt.plot(features_botnet[:,46], ['Botnet_c08']*len(target_botnet), 'bp')
plt.plot(features_normal[:,47], ['Normal_c09']*len(target_normal), 'c*')
plt.plot(features_botnet[:,47], ['Botnet_c09']*len(target_botnet), 'c*')
plt.plot(features_normal[:,48], ['Normal_c10']*len(target_normal), 'gh')
plt.plot(features_botnet[:,48], ['Botnet_c10']*len(target_botnet), 'gh')
plt.plot(features_normal[:,49], ['Normal_c11']*len(target_normal), 'kd')
plt.plot(features_botnet[:,49], ['Botnet_c11']*len(target_botnet), 'kd')
plt.plot(features_normal[:,50], ['Normal_c12']*len(target_normal), 'm+')
plt.plot(features_botnet[:,50], ['Botnet_c12']*len(target_botnet), 'm+')
plt.plot(features_normal[:,51], ['Normal_c13']*len(target_normal), 'b.')
plt.plot(features_botnet[:,51], ['Botnet_c13']*len(target_botnet), 'b.')
plt.plot(features_normal[:,52], ['Normal_c14']*len(target_normal), 'cx')
plt.plot(features_botnet[:,52], ['Botnet_c14']*len(target_botnet), 'cx')
plt.plot(features_normal[:,53], ['Normal_c15']*len(target_normal), 'go')
plt.plot(features_botnet[:,53], ['Botnet_c15']*len(target_botnet), 'go')
plt.plot(features_normal[:,54], ['Normal_c16']*len(target_normal), 'k1')
plt.plot(features_botnet[:,54], ['Botnet_c16']*len(target_botnet), 'k1')

#-----------------------------------------------------------------
#ssl_server_name_ratio: ['-', ip, noip]
plt.figure(13)

plt.subplot()
plt.title('SSL Server Name Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,55], ['Normal_NOT_KOWN']*len(target_normal), 'b.')
plt.plot(features_botnet[:,55], ['Botnet_NOT_KOWN']*len(target_botnet), 'b.')
plt.plot(features_normal[:,56], ['Normal_IP']*len(target_normal), 'cx')
plt.plot(features_botnet[:,56], ['Botnet_IP']*len(target_botnet), 'cx')
plt.plot(features_normal[:,57], ['Normal_NOIP']*len(target_normal), 'go')
plt.plot(features_botnet[:,57], ['Botnet_NOIP']*len(target_botnet), 'go')

#-----------------------------------------------------------------
#ssl_resumed_ratio
plt.figure(14)

plt.title('SSL Resumed Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,58], target_normal, '.')
plt.plot(features_botnet[:,58], target_botnet, '.')

#-----------------------------------------------------------------
#ssl_last_alert_ratio: ['-', 'unknown-218', 'unknown-156', 'bad_record_mac', 'bad_certificate', 'unknown-238', 'unrecognized_name', 'certificate_unknown', 'certificate_expired', 'unknown_ca', 'unknown-170', 'unknown-76', 'decrypt_error', 'unknown-58', 'unknown-7', 'handshake_failure', 'unexpected_message', 'close_notify']
#[l00 - l17]
plt.figure(15)

plt.subplot()
plt.title('SSL Last Alert Ratio')
plt.xlabel('percentage')

plt.plot(features_normal[:,59], ['Normal_l01']*len(target_normal), 'cx')
plt.plot(features_botnet[:,59], ['Botnet_l01']*len(target_botnet), 'cx')
plt.plot(features_normal[:,60], ['Normal_l02']*len(target_normal), 'go')
plt.plot(features_botnet[:,60], ['Botnet_l02']*len(target_botnet), 'go')
plt.plot(features_normal[:,61], ['Normal_l03']*len(target_normal), 'k1')
plt.plot(features_botnet[:,61], ['Botnet_l03']*len(target_botnet), 'k1')
plt.plot(features_normal[:,62], ['Normal_l04']*len(target_normal), 'm2')
plt.plot(features_botnet[:,62], ['Botnet_l04']*len(target_botnet), 'm2')
plt.plot(features_normal[:,63], ['Normal_l05']*len(target_normal), 'r3')
plt.plot(features_botnet[:,63], ['Botnet_l05']*len(target_botnet), 'r3')
plt.plot(features_normal[:,64], ['Normal_l06']*len(target_normal), 'y4')
plt.plot(features_botnet[:,64], ['Botnet_l06']*len(target_botnet), 'y4')
plt.plot(features_normal[:,65], ['Normal_l07']*len(target_normal), 'ys')
plt.plot(features_botnet[:,65], ['Botnet_l07']*len(target_botnet), 'ys')
plt.plot(features_normal[:,66], ['Normal_l08']*len(target_normal), 'bp')
plt.plot(features_botnet[:,66], ['Botnet_l08']*len(target_botnet), 'bp')
plt.plot(features_normal[:,67], ['Normal_l09']*len(target_normal), 'c*')
plt.plot(features_botnet[:,67], ['Botnet_l09']*len(target_botnet), 'c*')
plt.plot(features_normal[:,68], ['Normal_l10']*len(target_normal), 'gh')
plt.plot(features_botnet[:,68], ['Botnet_l10']*len(target_botnet), 'gh')
plt.plot(features_normal[:,69], ['Normal_l11']*len(target_normal), 'kd')
plt.plot(features_botnet[:,69], ['Botnet_l11']*len(target_botnet), 'kd')
plt.plot(features_normal[:,70], ['Normal_l12']*len(target_normal), 'm+')
plt.plot(features_botnet[:,70], ['Botnet_l12']*len(target_botnet), 'm+')
plt.plot(features_normal[:,71], ['Normal_l13']*len(target_normal), 'b.')
plt.plot(features_botnet[:,71], ['Botnet_l13']*len(target_botnet), 'b.')
plt.plot(features_normal[:,72], ['Normal_l14']*len(target_normal), 'cx')
plt.plot(features_botnet[:,72], ['Botnet_l14']*len(target_botnet), 'cx')
plt.plot(features_normal[:,73], ['Normal_l15']*len(target_normal), 'go')
plt.plot(features_botnet[:,73], ['Botnet_l15']*len(target_botnet), 'go')
plt.plot(features_normal[:,74], ['Normal_l16']*len(target_normal), 'k1')
plt.plot(features_botnet[:,74], ['Botnet_l16']*len(target_botnet), 'k1')
plt.plot(features_normal[:,75], ['Normal_l17']*len(target_normal), 'm2')
plt.plot(features_botnet[:,75], ['Botnet_l17']*len(target_botnet), 'm2')
plt.plot(features_normal[:,76], ['Normal_l00']*len(target_normal), 'b.')
plt.plot(features_botnet[:,76], ['Botnet_l00']*len(target_botnet), 'b.')


#-----------------------------------------------------------------
#ssl_established_ratio
plt.figure(16)

plt.title('SSL Established Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,77], target_normal, '.')
plt.plot(features_botnet[:,77], target_botnet, '.')

#-----------------------------------------------------------------
#ssl_cert_chain_fuids: mean/standard deviation/standard deviation range
plt.figure(17)

plt.subplot(5,1,1)
plt.title('SSL Certificate Chain Fuids Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,78], target_normal, '.')
plt.plot(features_botnet[:,78], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('SSL Certificate Chain Fuids Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,79], target_normal, '.')
plt.plot(features_botnet[:,79], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('SSL Certificate Chain Fuids Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,80], target_normal, '.')
plt.plot(features_botnet[:,80], target_botnet, '.')

#-----------------------------------------------------------------
#ssl_validation_status_ratio: ['-', 'unable to get local issuer certificate', 'ok', 'self signed certificate in certificate chain', 'self signed certificate']
plt.figure(18)

plt.subplot()
plt.title('SSL Validation Status Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,81], ['Normal_NOT_KOWN']*len(target_normal), 'b.')
plt.plot(features_botnet[:,81], ['Botnet_NOT_KOWN']*len(target_botnet), 'b.')
plt.plot(features_normal[:,82], ['Normal_unable']*len(target_normal), 'cx')
plt.plot(features_botnet[:,82], ['Botnet_unable']*len(target_botnet), 'cx')
plt.plot(features_normal[:,83], ['Normal_ok']*len(target_normal), 'go')
plt.plot(features_botnet[:,83], ['Botnet_ok']*len(target_botnet), 'go')
plt.plot(features_normal[:,84], ['Normal_self_in']*len(target_normal), 'k1')
plt.plot(features_botnet[:,84], ['Botnet_self_in']*len(target_botnet), 'k1')
plt.plot(features_normal[:,85], ['Normal_self']*len(target_normal), 'm2')
plt.plot(features_botnet[:,85], ['Botnet_self']*len(target_botnet), 'm2')

#-----------------------------------------------------------------
#ssl_cert_ratio
plt.figure(19)

plt.title('SSL Certificate Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,86], target_normal, '.')
plt.plot(features_botnet[:,86], target_botnet, '.')

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#-----------------------------------------------------------------
#cert_exist

normal_cert_exist_ratio = 0
for i in features_normal[:87]:
    normal_cert_exist_ratio += i
normal_cert_exist_ratio = normal_cert_exist_ratio/len(features_normal)

botnet_cert_exist_ratio = 0
for i in features_botnet[:87]:
    botnet_cert_exist_ratio += i
botnet_cert_exist_ratio = botnet_cert_exist_ratio/len(features_botnet)

fig, ax = plt.subplots()
bar_width = 0.35
ax.bar(0, (normal_cert_exist_ratio), bar_width)
ax.bar(0 + bar_width, (botnet_cert_exist_ratio), bar_width)
ax.set_xticklabels(('Normal', 'Botnet'))
fig.tight_layout()

#-----------------------------------------------------------------
#cert_version_ratio: ['1', '3']
plt.figure(21)

plt.subplot()
plt.title('CERT Version Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,88], ['Normal_V1']*len(target_normal), 'b.')
plt.plot(features_botnet[:,88], ['Botnet_V1']*len(target_botnet), 'b.')
plt.plot(features_normal[:,89], ['Normal_V3']*len(target_normal), 'cx')
plt.plot(features_botnet[:,89], ['Botnet_V3']*len(target_botnet), 'cx')

#-----------------------------------------------------------------
#cert_serial_length: mean/standard deviation/standard deviation range
plt.figure(22)

plt.subplot(5,1,1)
plt.title('CERT Serial Length Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,90], target_normal, '.')
plt.plot(features_botnet[:,90], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CERT Serial Length Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,91], target_normal, '.')
plt.plot(features_botnet[:,91], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CERT Serial Length Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,92], target_normal, '.')
plt.plot(features_botnet[:,92], target_botnet, '.')

#-----------------------------------------------------------------
#cert_validity_period: mean/standard deviation/standard deviation range
plt.figure(23)

plt.subplot(5,1,1)
plt.title('CERT Validity Period Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,93], target_normal, '.')
plt.plot(features_botnet[:,93], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CERT Validity Period Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,94], target_normal, '.')
plt.plot(features_botnet[:,94], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CERT Validity Period Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,95], target_normal, '.')
plt.plot(features_botnet[:,95], target_botnet, '.')

#-----------------------------------------------------------------
#cert_validity_ratio
plt.figure(24)

plt.subplot()
plt.title('CERT Validity Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,96], target_normal, '.')
plt.plot(features_botnet[:,96], target_botnet, '.')

#-----------------------------------------------------------------
#cert_age: mean/standard deviation/standard deviation range
plt.figure(25)

plt.subplot(5,1,1)
plt.title('CERT Age Mean')
plt.xlabel('time/ms')
plt.plot(features_normal[:,97], target_normal, '.')
plt.plot(features_botnet[:,97], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CERT Age Standard Deviation')
plt.xlabel('time/ms')
plt.plot(features_normal[:,98], target_normal, '.')
plt.plot(features_botnet[:,98], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CERT Age Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,99], target_normal, '.')
plt.plot(features_botnet[:,99], target_botnet, '.')

#-----------------------------------------------------------------
#cert_key_alg_ratio: ['md5WithRSAEncryption', 'shaWithRSAEncryption', 'rsaEncryption']
plt.figure(26)

plt.subplot()
plt.title('CERT Key Algorithm Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,100], ['Normal_md5WithRSAEncryption']*len(target_normal), 'b.')
plt.plot(features_botnet[:,100], ['Botnet_md5WithRSAEncryption']*len(target_botnet), 'b.')
plt.plot(features_normal[:,101], ['Normal_shaWithRSAEncryption']*len(target_normal), 'cx')
plt.plot(features_botnet[:,101], ['Botnet_shaWithRSAEncryption']*len(target_botnet), 'cx')
plt.plot(features_normal[:,102], ['Normal_rsaEncryption']*len(target_normal), 'go')
plt.plot(features_botnet[:,102], ['Botnet_rsaEncryption']*len(target_botnet), 'go')


#-----------------------------------------------------------------
#cert_sig_alg_ratio: ['sha1WithRSAEncryption', 'md5WithRSAEncryption', 'sha256WithRSAEncryption']
plt.figure(27)

plt.subplot()
plt.title('CERT Sigature Algorithm Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,100], ['Normal_sha1WithRSAEncryption']*len(target_normal), 'b.')
plt.plot(features_botnet[:,100], ['Botnet_sha1WithRSAEncryption']*len(target_botnet), 'b.')
plt.plot(features_normal[:,101], ['Normal_md5WithRSAEncryption']*len(target_normal), 'cx')
plt.plot(features_botnet[:,101], ['Botnet_md5WithRSAEncryption']*len(target_botnet), 'cx')
plt.plot(features_normal[:,102], ['Normal_sha256WithRSAEncryption']*len(target_normal), 'go')
plt.plot(features_botnet[:,102], ['Botnet_sha256WithRSAEncryption']*len(target_botnet), 'go')

#-----------------------------------------------------------------
#cert_key_type_ratio: ['-', 'rsa']
plt.figure(28)

plt.subplot()
plt.title('CERT Key Type Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,103], ['Normal_NotKown']*len(target_normal), 'b.')
plt.plot(features_botnet[:,103], ['Botnet_NotKown']*len(target_botnet), 'b.')
plt.plot(features_normal[:,104], ['Normal_rsa']*len(target_normal), 'cx')
plt.plot(features_botnet[:,104], ['Botnet_rsa']*len(target_botnet), 'cx')

#-----------------------------------------------------------------
#cert_key_length_ratio: ['-', '512', '1024', '2048', '4096']
plt.figure(29)

plt.subplot()
plt.title('CERT Key Length Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,105], ['Normal_NotKown']*len(target_normal), 'b.')
plt.plot(features_botnet[:,105], ['Botnet_NotKown']*len(target_botnet), 'b.')
plt.plot(features_normal[:,106], ['Normal_512']*len(target_normal), 'cx')
plt.plot(features_botnet[:,106], ['Botnet_512']*len(target_botnet), 'cx')
plt.plot(features_normal[:,107], ['Normal_1024']*len(target_normal), 'go')
plt.plot(features_botnet[:,107], ['Botnet_1024']*len(target_botnet), 'go')
plt.plot(features_normal[:,108], ['Normal_2048']*len(target_normal), 'k1')
plt.plot(features_botnet[:,108], ['Botnet_2048']*len(target_botnet), 'k1')
plt.plot(features_normal[:,109], ['Normal_4096']*len(target_normal), 'm2')
plt.plot(features_botnet[:,109], ['Botnet_4096']*len(target_botnet), 'm2')

#-----------------------------------------------------------------
#cert_exponent_ratio: ['-', '17', '65537']
plt.figure(30)

plt.subplot()
plt.title('CERT Exponent Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,110], ['Normal_NotKown']*len(target_normal), 'b.')
plt.plot(features_botnet[:,110], ['Botnet_NotKown']*len(target_botnet), 'b.')
plt.plot(features_normal[:,111], ['Normal_17']*len(target_normal), 'cx')
plt.plot(features_botnet[:,111], ['Botnet_17']*len(target_botnet), 'cx')
plt.plot(features_normal[:,112], ['Normal_65537']*len(target_normal), 'go')
plt.plot(features_botnet[:,112], ['Botnet_65537']*len(target_botnet), 'go')

#-----------------------------------------------------------------
#cert_basic_constraints_ca_ratio: ['-', 'F', 'T']
plt.figure(31)

plt.subplot()
plt.title('CERT Basic Constraints CA Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,113], ['Normal_NotKown']*len(target_normal), 'b.')
plt.plot(features_botnet[:,113], ['Botnet_NotKown']*len(target_botnet), 'b.')
plt.plot(features_normal[:,114], ['Normal_F']*len(target_normal), 'cx')
plt.plot(features_botnet[:,114], ['Botnet_F']*len(target_botnet), 'cx')
plt.plot(features_normal[:,115], ['Normal_T']*len(target_normal), 'go')
plt.plot(features_botnet[:,115], ['Botnet_T']*len(target_botnet), 'go')

#-----------------------------------------------------------------
#cert_san_dns_domain_number: mean/standard deviation/standard deviation range
plt.figure(32)

plt.subplot(5,1,1)
plt.title('CERT SAN DNS Domain Number Mean')
plt.xlabel('percentage')
plt.plot(features_normal[:,116], target_normal, '.')
plt.plot(features_botnet[:,116], target_botnet, '.')

plt.subplot(5,1,3)
plt.title('CERT SAN DNS Domain Number Standard Deviation')
plt.xlabel('percentage')
plt.plot(features_normal[:,117], target_normal, '.')
plt.plot(features_botnet[:,117], target_botnet, '.')

plt.subplot(5,1,5)
plt.title('CERT SAN DNS Domain Number Standard Deviation Range')
plt.xlabel('percentage')
plt.plot(features_normal[:,118], target_normal, '.')
plt.plot(features_botnet[:,118], target_botnet, '.')

#-----------------------------------------------------------------
#cert_san_dns_sni_ratio
plt.figure(33)

plt.subplot()
plt.title('CERT SAN DNS SNI Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,119], target_normal, '.')
plt.plot(features_botnet[:,119], target_botnet, '.')


#-----------------------------------------------------------------
#cert_san_dns_cn_ratio
plt.figure(34)

plt.subplot()
plt.title('CERT SAN DNS CN Ratio')
plt.xlabel('percentage')
plt.plot(features_normal[:,120], target_normal, '.')
plt.plot(features_botnet[:,120], target_botnet, '.')

plt.show()