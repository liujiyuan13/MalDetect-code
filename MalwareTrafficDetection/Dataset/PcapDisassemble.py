import pyshark
import math
import time
import re

def is_ipv4(ip):
    r = '^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5]).(\d{1,2}|1\d\d|2[0-4]\d|25[0-5]).(\d{1,2}|1\d\d|2[0-4]\d|25[0-5]).(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$'
    return re.match(r, ip)

def reverse_ft(ft):
    tab = '\t'
    split = ft.split(tab)
    return split[2]+tab+split[3]+tab+split[0]+tab+split[1]
def is_nor(ft):
    tab = '\t'
    split = ft.split(tab)
    if split[3] == '443':
        return True
    else:
        return False

# print the start of running
start_time = time.asctime(time.localtime(time.time()))
print(start_time)

cap = pyshark.FileCapture('D:\\Work\\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\CTU-Malware-Capture-Botnet-237-1\\2017-3-30_win4.pcap', display_filter="tcp.port == 443", keep_packets=False)
# cap = pyshark.FileCapture('dst.pcap', display_filter="tcp", keep_packets=False)
#use a dict to store flows
#key is five tuple and value is selected data
flow = dict()
ssl_properties = dict()


def calculate_features(ft, file):
    if ft not in flow:
        return
    if ft not in ssl_properties:
        return

    features = [0]*29
    # flow metadata
    # inbound/outbound bytes/packets
    bytes = 0
    for conn in flow[ft]:
        bytes += conn[0]
    pkts = len(flow[ft])
    features[0] = bytes
    features[1] = pkts

    ft_rev = reverse_ft(ft)
    bytes = 0
    for conn in flow[ft_rev]:
        bytes += conn[0]
    pkts = len(flow[ft_rev])
    features[2] = bytes
    features[3] = pkts

    # source port, destination port
    features[4] = int(ft.split(tab)[1])
    features[5] = 443

    # sort the undirectional connnections according to timestamp
    conns = flow[ft]
    for i in range(0, len(conns)):
        for j in range(0, len(conns) - 1 - i):
            if conns[j][1] > conns[j + 1][1]:
                temp = conns[j + 1]
                conns[j + 1] = conns[j]
                conns[j] = temp

    # total duration
    features[6] = conns[len(conns)-1][1] - conns[0][1]

    # SPLT
    #get the first 50 packets
    if len(conns)<=50:
        selected_conns = conns
    else:
        selected_conns = conns[:50]
    #sequence of packet length
    for conn in conns:
        n = math.floor(conn[0]/150)
        if n>=10:
            n=10
        features[7+n] += 1
    #sequence of packet times
    for i in range(0, len(selected_conns)-1):
        inter_pkt_time = selected_conns[i+1][1] - selected_conns[i][1]
        n = math.floor(inter_pkt_time/0.05)
        if n>=10:
            n = 10
        features[18+n] += 1

    s = ""
    for f in features:
        s += str(f) + '\t'
    file.write(s[:-1]+'\n')


tab='\t'
times = 0
file = open("pcap_features.txt", 'w')
for c in cap:

    times += 1
    if(times%1000==0):
        print(times, " ", time.asctime(time.localtime(time.time())))

    # abort ipv6
    if not is_ipv4(c.ip.src) or not is_ipv4(c.ip.dst):
        continue
    try:
        tcp = c.tcp
    except:
        continue

    #get four tuple
    ft = c.ip.src + tab + c.tcp.srcport + tab + c.ip.dst + tab + c.tcp.dstport
    if c.tcp.dstport == '443':
        nor += 1
        ft_nor = c.ip.src +tab+ c.tcp.srcport +tab+ c.ip.dst +tab+ c.tcp.dstport
    elif c.tcp.srcport == '443':
        rev += 1
        ft_nor = c.ip.dst +tab+ c.tcp.dstport +tab+ c.ip.src +tab+ c.tcp.srcport
    else:
        continue


    # select useful datafield
    conn = []
    # packet length for SPLT
    conn.append(int(c.length))
    # packet time for SPLT
    conn.append(float(c.sniff_timestamp))
    try:
        flow[ft].append(conn)
    except:
        flow[ft] = [conn]

    #TLS
    try:
        #if this packet has a ssl layer
        ssl = c.ssl

        if ft_nor in ssl_properties:
            props = ssl_properties[ft_nor]
        else:
            props = [0]*6


        if ssl.record_content_type == '22':

            # get ssl version
            props[0] = ssl.record_version
            # get list of offfered ciphersuites and list of extensions, they are in client hello subprocess(1) of handshake process(22)
            if ssl.handshake_type == '1':
                #get list of SSL ordered offered ciphersuites
                ciphers = ssl.get_multi_values_of_field("Cipher Suite")
                codes = []
                for cipher in ciphers:
                    m = cipher.index('(')
                    n = cipher.index(')')
                    codes.append(cipher[m+1:n])
                props[1] = codes
                # get list of SSL extensions
                extensions = ssl.get_multi_values_of_field("Extension")
                exts = []
                for ex in extensions:
                    m = ex.index('(')
                    exts.append(ex[:m].replace(' ', ''))
                props[2] = exts
            #get the selected cipher suite and selected extensions, they are in server hello subprocess(2) of handshake process(22)
            elif ssl.handshake_type == '2':
                #get the selected cipher suite
                code = int(ssl.handshake_ciphersuite)
                props[3] = str("%#x"%code)
                #get the selected extensions
                extensions = ssl.get_multi_values_of_field("Extension")
                exts = []
                for ex in extensions:
                    m = ex.index('(')
                    exts.append(ex[:m].replace(' ', ''))
                props[4] = exts
            #get certificate information, they are in certificate subprocess(11) of handshake process(22)
            elif ssl.handshake_type == '11':
                #get nothing in aderson
                continue
            # get client key exchange information, they are in client key exchange subprocess(16) of handshake process(22)
            elif ssl.handshake_type == '16':
                #get public key length
                pubkey_length = ssl.get_multi_values_of_field("Pubkey Length")
                props[5] = int(pubkey_length[0][1:])
            ssl_properties[ft_nor] = props

    except:
        a=0

    # when close the tcp flow, calculate corresponding flow features
    if c.tcp.flags == '0x00000014':
        ft_nor = ft
        if not is_nor(ft):
            ft_nor = reverse_ft(ft)

        calculate_features(ft_nor, file)
        flow.pop(ft_nor)
        flow.pop(reverse_ft(ft_nor))
        # ssl_properties.pop(ft_nor)


file.close()

# print the start of running
print(start_time)
mid_time = time.asctime(time.localtime(time.time()))
print("finish disassemble pcap file: ", mid_time)
