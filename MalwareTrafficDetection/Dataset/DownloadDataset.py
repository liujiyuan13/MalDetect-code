
import ssl
from bs4 import BeautifulSoup
import requests
import os
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

def download_files(url, datasetname):
    local_path = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\"

    os.mkdir(local_path+datasetname)
    os.mkdir(local_path+datasetname+"\\bro")

    print(">>>start to download "+ datasetname)
    try:
        urllib.request.urlretrieve(url + datasetname + "/bro/conn.log", local_path+datasetname+"\\bro\\conn.log")
        urllib.request.urlretrieve(url + datasetname + "/bro/ssl.log", local_path+datasetname+"\\bro\\ssl.log")
        urllib.request.urlretrieve(url + datasetname + "/bro/x509.log", local_path + datasetname + "\\bro\\x509.log")
        print(">>>finish downloading " + datasetname)
    except:
        print(">>>fail in downloading "+ datasetname)


ssl._create_default_https_context = ssl._create_unverified_context
url = "https://mcfp.felk.cvut.cz/publicDatasets/"

dataset_names = []
download_dataset_names_file = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\download_files.txt"
if os.path.exists(download_dataset_names_file):
    with open(download_dataset_names_file) as f:
        line = f.read()
        dataset_names = line[1:-1].split(',')
        f.close()
else:
    # find the urls to download
    names = []
    hrefs = find_files(url)
    for href in hrefs:
        if "CTU-Malware-Capture-Botnet" in href or "CTU-Mixed-Capture" in href or "CTU-Normal" in href:
            names.append(href)
    print(len(names), ": ", names)
    # delete the datasets which do not have ssl.log
    for name in names:
        files = find_files(url+name+"bro/")
        if 'ssl.log' in files:
            dataset_names.append(name[:-1])
    with open(download_dataset_names_file, 'w') as f:
        line = ""
        for i in dataset_names:
            line += i + '\t'
        f.write(line)
        f.close()
print(len(dataset_names),dataset_names)

#find local dataset that have been downloaded
path = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
downloaded_datasets = os.listdir(path)
#download needed files
for dname in dataset_names:
    if dname not in downloaded_datasets:
        download_files(url, dname)
download_files(url, dname)