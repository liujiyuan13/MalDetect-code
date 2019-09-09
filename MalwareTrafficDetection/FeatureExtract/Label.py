
import os
import glob
import re

def findip(str):
    p = re.compile( r"((?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))")
    res = p.findall(str)
    ips = [g[0] for g in res]
    if len(ips) == 0:
        return -1
    else:
        return ips[0]

def checkip(str):
    p = re.compile( r"((?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))")
    if p.match(str):
        return  True
    else:
        return False

def find_label_from_binetflow(binetflowPath):
    pathSplit = binetflowPath.split('\\')
    datasetName = pathSplit[-2]
    binetflowName = pathSplit[-1]
    print(">>>finding label from ", datasetName)

    infected_ips = {}
    normal_ips = {}


    with open(binetflowPath) as f:
        for line in f:
            if 'StartTime' in line:
                continue

            if "binetflow" in binetflowName:
                split = line.split(',')
                src_address = split[3]
            elif "netflow" in binetflowName:
                src_address = findip(line)
                if src_address == -1:
                    continue


            if "Botnet" in line:
                try:
                    infected_ips[src_address] = infected_ips[src_address] + 1
                except:
                    infected_ips[src_address] = 1
            elif "Normal" in line:
                try:
                    normal_ips[src_address] = normal_ips[src_address] + 1
                except:
                    normal_ips[src_address] = 1
            #if src_addr is infected, all the traffic from src_addr are considered as malware traffic
            for addr in infected_ips:
                if addr in normal_ips.keys():
                    normal_ips.pop(addr)
        f.close()
        print(">>>In ", datasetName, ", the infected ips are:\n", infected_ips)
        print(">>>In ", datasetName, ", the normal ips are:\n", normal_ips)



    return infected_ips, normal_ips


def create_conn_label(bro_folder, infected_ips, normal_ips):

    tab = '\t'
    malware_label = 0
    normal_label = 0
    flow_array = []

    try:
        print(">>>reading conn.log")
        with open(bro_folder + "\\conn.log") as f:
            for line in f:
                newline = line
                if not('#'==line[0]):
                    split = line.split(tab)
                    src_address = split[2]

                    if src_address in infected_ips:
                        newline = line.rstrip() + tab + "botnet\n"
                        malware_label += 1
                    elif src_address in normal_ips:
                        newline = line.rstrip() + tab + "normal\n"
                        normal_label += 1
                    else:
                        newline = line.rstrip() + tab + "background\n"
                else:
                    if "fields" in line:
                        newline = line.rstrip() + tab + "label\n"
                    elif "types" in line:
                        newline  = line.rstrip() + tab + "string\n"
                flow_array.append(newline)
            f.close()
            print("malwares:", malware_label)
            print("normals:", normal_label)

        try:
            print(">>>creating conn_label.log")
            # dir = bro_folder + "\\self_create"
            # if not os.path.exists(dir):
            #     os.makedirs(dir)
            with open(bro_folder + "\\conn_label.log", 'w')as f:
                for flow in flow_array:
                    f.write(flow)
                f.close()
        except:
            print(">>>Error: cannot create conn_label.log")

    except:
        print(">>>Error: cannot read conn.log")


def find_binetflow_name(databasePath):
    binetflow_files = glob.glob(databasePath+"/*netflow")
    return binetflow_files


def get_ips_from_input(databasePath):
    print(databasePath)
    infected_ips_str = input("infected_ips(separate with comma):")
    ips = infected_ips_str.split(',')
    infected_ips = {}
    normal_ips = {}
    for ip in ips:
        infected_ips[ip] = 1

    return infected_ips, normal_ips

def write_ips_into_file(infected_ips, normal_ips, databasePath, filename):
    if filename == "":
        filename = input("input the file name to store the ips:")
    f = open(databasePath+"\\"+filename+"_ips_labeled.txt", 'w')
    str = "infected_ips:\n"
    for ip in infected_ips.keys():
        str += (ip+",")
    str = str[:-1]+"\n"+"normal_ips:\n"
    for ip in normal_ips.keys():
        str += (ip+",")
    str = str[:-1]
    f.write(str)
    f.close()

def get_ips_from_file(ips_file_path):
    f = open(ips_file_path)
    lines = f.readlines()
    infected_ips_str = lines[1]
    ips_list = infected_ips_str.split(',')
    infected_ips = {}
    normal_ips = {}
    for ip in ips_list:
        infected_ips[ip[:-1]] = 1
    if len(lines) != 3:
        ips_list = lines[3].split(',')
        for ip in ips_list:
            normal_ips[ip[:-1]]=1
    f.close()
    return infected_ips, normal_ips

def estimate_label_from_binetflow(binetflow_path):
    f = open(binetflow_path)
    infected_ips= {}
    for line in f:
        split = line.split(',')
        if checkip(split[3]):
            ip = split[3]
            if ip not in infected_ips:
                infected_ips[ip] = 1
            else:
                infected_ips[ip] += 1
    infected_ip = max(infected_ips, key=infected_ips.get)
    return {infected_ip: infected_ips[infected_ip]}, {}


def has_conn_label_log(binetflow_path):
    bro_folder = binetflow_path.split('.')[0]
    if os.path.exists(bro_folder+"\\conn_label.log"):
        return True
    else:
        return False

datasetPath = "D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
databasePaths = glob.glob(datasetPath+"/CTU*")
databasePathfilter = [datasetPath+"\\CTU-Malware-Capture-Botnet-11", datasetPath+"\\CTU-Malware-Capture-Botnet-129-1", datasetPath+"\\CTU-Malware-Capture-Botnet-36"]

for dbPath in databasePaths:
    if dbPath in databasePathfilter:
        continue
    binetflow_paths = find_binetflow_name(dbPath)
    if len(binetflow_paths) == 0:
        # read from ips file
        print(dbPath)
        ips_file = glob.glob(dbPath + "/*ips_labeled.txt")
        if len(ips_file) != 0:
            infected_ips, normal_ips = get_ips_from_file(ips_file[0])
        else:
            # output window
            print(">>>there are no neflow files!!!")
            infected_ips, normal_ips = get_ips_from_input(dbPath)
            write_ips_into_file(infected_ips, normal_ips, dbPath, "")
        name = os.listdir(dbPath)[0]

        create_conn_label(dbPath + "\\" + name, infected_ips, normal_ips)
    else:
        for binetflow_path in binetflow_paths:

            #skip which has conn_label
            if has_conn_label_log(binetflow_path):
                continue

            str = binetflow_path.split('.')[0]

            ips_file_path = str + "_ips_labeled.txt"
            if os.path.exists(ips_file_path):
                print(">>>read from ips file ", ips_file_path)
                infected_ips, normal_ips = get_ips_from_file(ips_file_path)
                print("infected ips:", infected_ips)
                print("normal ips", normal_ips)
            else:
                infected_ips, normal_ips = find_label_from_binetflow(binetflow_path)
                if len(infected_ips) == 0 and len(normal_ips) == 0:
                    print(">>>estimate ip from binetflow path")
                    infected_ips, normal_ips = estimate_label_from_binetflow(binetflow_path)
                    print("--------------------please check----------------------")
                    print("infected ips:", infected_ips)
                    print("normal ips", normal_ips)
                    print("--------------------please check----------------------")
                    #output window
                    # infected_ips, normal_ips = get_ips_from_input(databasePath)
                filename = str.replace(dbPath + "\\", "")
                write_ips_into_file(infected_ips, normal_ips, dbPath, filename)
            bro_folder = binetflow_path.split('.')[0]

            create_conn_label(bro_folder, infected_ips, normal_ips)







