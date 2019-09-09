import os

# dbs_path = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
dbs_path = "/home/ftp2/jiyuan/Dataset"

db_names = os.listdir(dbs_path)

ciphersuites = set()
exts = set()

f = open("tcpdump443error.text", 'a')
for db_name in db_names:
    if "Botnet" not in db_name:
    # if "Botnet-10" not in db_name:
        continue
    # if int(db_name.split('-')[4])<20:
    #     continue

    db_path = dbs_path + "/" + db_name

    pcap_names = os.listdir(db_path)
    for pcap_name in pcap_names:
        # if "tcpdump443" not in pcap_name:
        #     continue
        # pcap_path = db_path + "/" + pcap_name
        # print(pcap_path)
        # os.remove(pcap_path)

        if "pcap" not in pcap_name:
            continue
        pcap_path = db_path + "/" + pcap_name
        print(pcap_path)

        try:
            val = os.system("tcpdump -Z root -r "+pcap_path+" \"tcp port 443\" -w "+ pcap_path.replace(".pcap", "")+ "_tcpdump443.pcap")
        except:
            f.write(pcap_path+"\n")
            continue
f.close()
