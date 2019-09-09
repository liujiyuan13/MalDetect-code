import pyshark
import math
import time

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

cap = pyshark.FileCapture('/home/ftp2/jiyuan/Dataset/CTU-Malware-Capture-Botnet-71/2014-04-07_capture-win19.pcap', display_filter="tcp", keep_packets=False)
#use a dict to store flows
#key is five tuple and value is selected data
flow = dict()
ssl_properties = dict()

tab='\t'
n = 0
for c in cap:
    try:
        n +=1
        if(n%1000==0):
            print(n, " ", time.asctime(time.localtime(time.time())))
        # print(c.tcp.time_relative)
        # print(c.sniff_timestamp)
        #get four tuple
        ft = c.ip.src + tab + c.tcp.srcport + tab + c.ip.dst + tab + c.tcp.dstport
        if c.tcp.dstport == '443':
            ft_nor = c.ip.src +tab+ c.tcp.srcport +tab+ c.ip.dst +tab+ c.tcp.dstport
        elif c.tcp.srcport == '443':
            ft_nor = c.ip.dst +tab+ c.tcp.dstport +tab+ c.ip.src +tab+ c.tcp.srcport
        else:
            continue
        #select useful datafield
        conn = []

        #packet length for SPLT
        conn.append(int(c.length))
        #packet time for SPLT
        conn.append(float(c.sniff_timestamp))
        # conn.append(float(c.tcp.time_relative))
        # conn.append(float(c.tcp.time_delta))

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

            #get ssl version
            props[0] = ssl.record_version

            if ssl.record_content_type == '22':
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
                    c = int(ssl.handshake_ciphersuite)
                    props[3] = str("%#x"%c)
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
            continue
    except:
        print(c)
print(flow)
print(ssl_properties)

# print time
mid_time = time.asctime(time.localtime(time.time()))
print("finish disassemble pcap file: ", mid_time)


#to store features
features = dict()
for ft in flow:
    if is_nor(ft):
        features[ft] = [0]*29


for ft in flow:
    # flow metadata
    # inbound/outbound bytes/packets
    bytes = 0
    for conn in flow[ft]:
        bytes += conn[0]
    pkts = len(flow[ft])
    if is_nor(ft):
        features[ft][0] = bytes
        features[ft][1] = pkts
    else:
        ft_nor = reverse_ft(ft)
        features[ft_nor][2] = bytes
        features[ft_nor][3] = pkts

    ##################################
    # we define the flow is undirectional
    if not is_nor(ft):
        continue
    ###################################

    # source port, destination port
    features[ft][4] = int(ft.split(tab)[1])
    features[ft][5] = 443

    # sort the undirectional connnections according to timestamp
    conns = flow[ft]
    for i in range(0, len(conns)):
        for j in range(0, len(conns) - 1 - i):
            if conns[j][1] > conns[j + 1][1]:
                temp = conns[j + 1]
                conns[j + 1] = conns[j]
                conns[j] = temp

    # total duration
    features[ft][6] = conns[len(conns)-1][1] - conns[0][1]

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
        features[ft][7+n] += 1
    #sequence of packet times
    for i in range(0, len(selected_conns)-1):
        inter_pkt_time = selected_conns[i+1][1] - selected_conns[i][1]
        n = math.floor(inter_pkt_time/0.05)
        if n>=10:
            n = 10
        features[ft][18+n] += 1
print(features)

end_time = time.asctime(time.localtime(time.time()))
print("start: ", start_time)
print("end: ", end_time)

# ssl_features = dict()
# for ft in ssl_properties:
#     #there are ssl 4 versions