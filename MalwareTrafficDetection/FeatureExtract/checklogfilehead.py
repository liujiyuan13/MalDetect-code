import os
import glob

def find_binetflow_name(databasePath):
    binetflow_files = glob.glob(databasePath+"/*netflow")
    return binetflow_files

datasetPath = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
databasePathfilter = [datasetPath+"\\CTU-Malware-Capture-Botnet-11", datasetPath+"\\CTU-Malware-Capture-Botnet-111-4", datasetPath+"\\CTU-Malware-Capture-Botnet-112-4", datasetPath+"\\CTU-Malware-Capture-Botnet-129-1", datasetPath+"\\CTU-Malware-Capture-Botnet-36",datasetPath+"\\CTU-Malware-Capture-Botnet-61-3"]
databasePaths = glob.glob(datasetPath+"/CTU*")
flag = 0
for dbPath in databasePaths:
    if dbPath in databasePathfilter:
        continue
    binetflow_paths = find_binetflow_name(dbPath)
    for binetflow_path in binetflow_paths:
        bro_folder = binetflow_path.split('.')[0]

        conn_label_path = bro_folder+"\\conn_label.log"
        ssl_path = bro_folder+"\\ssl.log"
        x509_path = bro_folder+"\\x509.log"


        # f = open(conn_label_path)
        if os.path.exists(ssl_path):
            f = open(ssl_path)
        else:
            continue
        # if os.path.exists(x509_path):
        #     f = open(x509_path)
        # else:
        #     continue
        for line in f:
            if "fields"in line:
                split = line.split('\t')
                if flag != len(split):
                    flag = len(split)
                    print(split)
                break
        f.close()