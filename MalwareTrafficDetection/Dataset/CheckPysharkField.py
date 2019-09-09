import pyshark

cap = pyshark.FileCapture("data.pcap", display_filter="tcp", keep_packets=False)

for c in cap:
    try:
        ssl = c.ssl
    except:
        continue

    try:

        if ssl.record_content_type == '22':
            # get list of offfered ciphersuites and list of extensions, they are in client hello subprocess(1) of handshake process(22)
            if ssl.handshake_type == '1':
                print(ssl.handshake_ciphersuites)
                print(ssl.handshake_extensions_supported_groups)
                print(ssl.get_field_by_showname("Cipher Suites"))
                print(ssl.handshake_sig_hash_alg)



    except:
        a=0