import os
import ssl
from bs4 import BeautifulSoup
import requests
import urllib

def find_files(url):
    soup = BeautifulSoup(requests.get(url, verify=False).text, "lxml")
    hrefs = []
    for a in soup.find_all('a'):
        try:
            hrefs.append(a['href'])
        except:
            pass
    return hrefs

def download_file(url, path, db_name, file_name):

    split = db_name.split('-')
    if float(split[4]) <=42:
        return
    path = path + db_name
    if not os.path.exists(path):
        os.mkdir(path)
    print(">>>start to download " + path+'\\'+file_name)
    # try:
    if not os.path.exists( path + "\\" + file_name):
        urllib.request.urlretrieve(url, path + "\\" + file_name)
        print(">>>finish downloading " + path + "\\" + file_name)
    else:
        print(">>>" + file_name + " exists")
    # except:
    #     print(">>>fail in downloading " + path)


ssl._create_default_https_context = ssl._create_unverified_context

url = "https://mcfp.felk.cvut.cz/publicDatasets/"
db_path = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\"
names = find_files(url)
db_names = []
for name in names:
    if "CTU-Malware-Capture-Botnet" in name or "CTU-Mixed-Capture" in name or "CTU-Normal" in name:
        db_names.append(name[:-1])

with open(db_path+"contents.csv", 'w') as f:
    for db_name in db_names:
        f.write(db_name + '\n')
        split = db_name.split('-')
        if float(split[4]) <= 300 or float(split[4]) in [300,309]:
            continue
        file_names = find_files(url + db_name)

        for file_name in file_names:
            split = file_name.split('.')
            if split[-1] == 'pcap' or split[-1] == 'netflow' or split[-1] == 'binetflow':
            #if '.pcap' in file_name or '.netflow' in file_name or '.weblog' in file_name:

                download_file(url+db_name+"/"+file_name, db_path, db_name, file_name)
                f.write('--'+file_name+'\n')
    f.close()