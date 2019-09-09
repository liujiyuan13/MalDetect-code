"""
this file aims to find out types of certain features
"""
import re
import os
import glob

def checkip(ip):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ip):
        return True
    else:
        return False


def print_type(dict):
    print(len(dict), dict)
    # if len(dict) < 100:
    #     print(len(dict), dict)
    # else:
    #     print("too many types")

def find_ssl_type():
    tab = '\t'
    version = set()
    cipher = set()
    curve =set()
    server_name = set()
    resumed = set()
    last_alert = set()
    next_protocol = set()
    established = set()
    cert_chain_fuids = set()
    client_cert_chain_fuids = set()
    subject = set()
    issuer = set()
    client_subject = set()
    client_issuer = set()
    # validation_status = set()
    # notaryfirst_seen = set()
    # notarylast_seen = set()
    # notarytimes_seen = set()
    # notaryvalid = set()

    database_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
    dataset_names = os.listdir(database_path)
    for name in dataset_names:
        dataset_path = database_path + "\\" + name

        binetflow_paths = glob.glob(dataset_path + "\\*netflow")
        for binetflow_path in binetflow_paths:
            bro_folder = binetflow_path.split('.')[0]

            conn_label_log_path = bro_folder + "\\conn_label.log"
            ssl_log_path = bro_folder + "\\ssl.log"
            cert_log_path = bro_folder + "\\x509.log"

            if os.path.exists(ssl_log_path):
                f = open(ssl_log_path)


                for line in f:
                    if not '#'==line[0]:
                        split = line.split(tab)
                        version.add(split[6])
                        cipher.add(split[7])
                        curve.add(split[8])
                        server_name.add(split[9])
                        resumed.add(split[10])
                        last_alert.add(split[11])
                        next_protocol.add(split[12])
                        established.add(split[13])
                        cert_chain_fuids.add(split[14])
                        client_cert_chain_fuids.add(split[15])
                        subject.add(split[16])
                        issuer.add(split[17])
                        client_subject.add(split[18])
                        client_issuer.add(split[19])
                        # validation_status.add(split[20])
                        # notaryfirst_seen.add(split[21])
                        # notarylast_seen.add(split[22])
                        # notarytimes_seen.add(split[23])
                        # notaryvalid.add(split[24])

                f.close()
    print("version: ", len(version), ": ", version)
    print("ciper: ", len(cipher), ":", cipher)
    print("curve: ", len(curve), ":", curve)
    print("server_name: ", len(server_name), ": ")
    print("resumed:", len(resumed), ": ", resumed)
    print("last_alter:", len(last_alert), ": ", last_alert)
    print("next_protocol: ", len(next_protocol), ": ", next_protocol)
    print("established: ", len(established), ": ", established)
    print("cert_chain_fuids: ", len(cert_chain_fuids))
    print("client_cert_chain_fuids: ", len(client_cert_chain_fuids), client_cert_chain_fuids)
    print("subject: ", len(subject), subject)
    print("issuer: ", len(issuer), issuer)
    print("client_subject: ", len(client_subject), client_subject)
    print("client_issuer: ", len(client_issuer), client_issuer)
    # print_type(validation_status)
    # print_type(notaryfirst_seen)
    # print_type(notarylast_seen)
    # print_type(notarytimes_seen)
    # print_type(notaryvalid)

def find_conn_type():
    tab = '\t'
    protocol = dict()
    conn_state = set()

    database_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
    dataset_names = os.listdir(database_path)
    for name in dataset_names:
        dataset_path = database_path + "\\" + name

        binetflow_paths = glob.glob(dataset_path + "\\*netflow")
        for binetflow_path in binetflow_paths:
            bro_folder = binetflow_path.split('.')[0]

            conn_label_log_path = bro_folder + "\\conn_label.log"
            ssl_log_path = bro_folder + "\\ssl.log"
            cert_log_path = bro_folder + "\\x509.log"

            if os.path.exists(conn_label_log_path):
                f = open(conn_label_log_path)

                for line in f:
                    if not '#' ==line[0]:
                        split = line.split(tab)
                        if split[6] in protocol:
                            protocol[split[6]]+=1
                        else:
                            protocol[split[6]] = 1
                        #conn_state.add(split[11])
                f.close()

    #print("conn_state: ", len(conn_state), conn_state)
    print("protocol: ", len(protocol), protocol)

def find_cert_type():
    tab = '\t'
    cert_version = set()
    cert_serial = set()
    cert_subject = set()
    cert_issuer  = set()
    cert_key_alg = set()
    cert_sig_alg = set()
    cert_key_type = set()
    cert_key_length = set()
    cert_exponent = set()
    cert_curve = set()
    cert_san_dns = set()
    cert_san_uri = set()
    cert_san_email = set()
    cert_san_ip = set()
    cert_basic_constraints_ca = set()
    cert_basic_constraints_path_len = set()
    flag = False

    database_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
    dataset_names = os.listdir(database_path)
    for name in dataset_names:
        dataset_path = database_path + "\\" + name

        binetflow_paths = glob.glob(dataset_path + "\\*netflow")
        for binetflow_path in binetflow_paths:
            bro_folder = binetflow_path.split('.')[0]

            conn_label_log_path = bro_folder + "\\conn_label.log"
            ssl_log_path = bro_folder + "\\ssl.log"
            cert_log_path = bro_folder + "\\x509.log"

            if os.path.exists(cert_log_path):
                f = open(cert_log_path)
                n=0
                for line in f:
                    n+=1
                    if not line[0]=='#':
                        split = line.split(tab)
                        cert_version.add(split[2])
                        cert_serial.add(split[3])
                        cert_subject.add(split[4])
                        cert_issuer.add(split[5])
                        cert_key_alg.add(split[8])
                        cert_sig_alg.add(split[9])
                        cert_key_type.add(split[10])
                        cert_key_length.add(split[11])
                        cert_exponent.add(split[12])
                        cert_curve.add(split[13])
                        cert_san_dns.add(split[14])
                        cert_san_uri.add(split[15])
                        cert_san_email.add(split[16])
                        cert_san_ip.add(split[17])
                        cert_basic_constraints_ca.add(split[18])
                        cert_basic_constraints_path_len.add(split[19])
                f.close()
    print("cert_version: ", len(cert_version), ": ", cert_version)
    print("cert_serial: ", len(cert_serial), ": ", cert_serial)
    print("cert_subject: ", len(cert_subject), ": ")
    print("cert_issuer: ", len(cert_issuer), ": ")
    print("cert_key_alg: ", len(cert_key_alg), ": ", cert_key_alg)
    print("cert_sig_alg: ", len(cert_sig_alg), ": ", cert_sig_alg)
    print("cert_key_type: ", len(cert_key_type), ": ", cert_key_type)
    print("cert_key_length: ", len(cert_key_length), ": ", cert_key_length)
    print("cert_exponent: ", len(cert_exponent), ": ", cert_exponent)
    print("cert_curve: ", len(cert_curve), ": ", cert_curve)
    print("cert_san_dns: ", len(cert_san_dns), ": ")
    print("cert_san_uri: ", len(cert_san_uri), ": ", cert_san_uri)
    print("cert_san_email: ", len(cert_san_email), ": ", cert_san_email)
    print("cert_san_ip: ", len(cert_san_ip), ": ", cert_san_ip)
    print("cert_basic_constraints_ca: ", len(cert_basic_constraints_ca), ": ", cert_basic_constraints_ca)
    print("cert_basic_constraints_path_len: ", len(cert_basic_constraints_path_len), ": ", cert_basic_constraints_path_len)

def tune_features():
    features_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\features"
    ssl_ratio_botnet = dict()
    ssl_ratio_normal = dict()
    feature_paths = glob.glob(features_path + "\\*")

    many = 0
    one = 0

    for path in feature_paths:
        with open(path) as f:
            for line in f:
                split = line.split('\t')


                a = float(split[6]) - float(split[7])
                if a>0.0001:
                    many += 1
                else:
                    one += 1



                # if "botnet" in split[-1]:
                #     if split[33] in ssl_ratio_botnet:
                #         ssl_ratio_botnet[split[33]] += 1
                #     else:
                #         ssl_ratio_botnet[split[33]] = 1
                # else:
                #     if split[33] in ssl_ratio_normal:
                #         ssl_ratio_normal[split[33]] += 1
                #     else:
                #         ssl_ratio_normal[split[33]] = 1
            f.close()
    # print("ssl_ratio_botnet: ", ssl_ratio_botnet)
    # print("ssl_ratio_normal: ", ssl_ratio_normal)
    print(many,"/", one)


# find_ssl_type()
# find_conn_type()
# find_cert_type()
tune_features()