import os
import pyshark
import time

dbs_path = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
# dbs_path = "/home/ftp2/jiyuan/Dataset"

db_names = os.listdir(dbs_path)

ciphersuites = set()
exts = set()

for db_name in db_names:
    if "Botnet" not in db_name:
    # if "Botnet-10" not in db_name:
        continue
    if int(db_name.split('-')[4])<20:
        continue

    db_path = dbs_path + "\\" + db_name

    pcap_names = os.listdir(db_path)
    for pcap_name in pcap_names:
        if "pcap" not in pcap_name:
            continue
        pcap_path = db_path + "\\" + pcap_name
        print(pcap_path)
        try:
            cap = pyshark.FileCapture(pcap_path, display_filter="ssl", keep_packets=False)
            n = 0
            for c in cap:
                n+=1
                if (n % 1000 == 0):
                    print(n, " ", time.asctime(time.localtime(time.time())))
                try:
                    ssl = c.ssl
                    if ssl.record_content_type == '22':
                        # get list of offfered ciphersuites and list of extensions, they are in client hello subprocess(1) of handshake process(22)
                        if ssl.handshake_type == '1':
                            # get list of SSL ordered offered ciphersuites
                            ciphers = ssl.get_multi_values_of_field("Cipher Suite")
                            for cipher in ciphers:
                                m = cipher.index('(')
                                n = cipher.index(')')
                                ciphersuites.add(cipher[m + 1:n])
                            # get list of SSL extensions
                            extensions = ssl.get_multi_values_of_field("Extension")
                            for ex in extensions:
                                m = ex.index('(')
                                exts.add(ex[:m].replace(' ', ''))
                except:
                    continue

            line = "cipher suites: \n"
            for cs in ciphersuites:
                line += cs + '\t'
            line = line[:-1] + "\nextensions:\n"
            for e in exts:
                line += e + '\t'
            line = line[:-1]
            f = open("types.txt", 'a')
            f.write(line)
            f.close()
        except:
            continue
