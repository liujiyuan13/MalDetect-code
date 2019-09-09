import sys
import re
import numpy as np
import os
import glob

class Unit:
    unitID = ""
    label = ""

    # connection parameters
    conn_ts = []
    conn_uid = []
    conn_orig_h = []
    conn_orig_p = []
    conn_resp_h = []
    conn_resp_p = []
    conn_proto = []
    conn_service = []
    conn_duration = []
    conn_orig_bytes = []
    conn_resp_bytes = []
    conn_state = []
    conn_local_orig = []
    conn_local_resp = []
    conn_missed_bytes = []
    conn_history = []
    conn_orig_pkts = []
    conn_orig_ip_bytes = []
    conn_resp_pkts = []
    conn_resp_ip_bytes = []
    conn_tunnel_parents = []


    #ssl parameters
    ssl_time = []
    ssl_uid = []
    ssl_version = []
    ssl_cipher = []
    #ssl_curve = []
    ssl_server_name = []
    ssl_resumed = []
    ssl_last_alert = []
    #ssl_next_protocol = []
    ssl_established = []
    ssl_cert_chain_fuids = []
    # ssl_client_cert_chain_fuids = []
    # ssl_subject = []
    # ssl_issuer = []
    # ssl_client_subject = []
    # ssl_client_issuer = []

    # ssl_validation_status = []
    # ssl_notary_first_seen = []
    # ssl_notary_last_seen = []
    # ssl_notary_times_seen = []
    # ssl_notary_valid = []


    #certificate parameters
    cert_time = []
    cert_uid = []
    cert_version = []
    cert_serial = []
    cert_subject = []
    #cert_issuer = []
    cert_not_valid_before = []
    cert_not_valid_after = []
    cert_key_alg = []
    cert_sig_alg = []
    cert_key_type = []
    cert_key_length = []
    cert_exponent = []
    #cert_curve = []
    cert_san_dns = []
    #cert_san_uri = []
    #cert_san_email = []
    #cert_san_ip = []
    cert_basic_constraints_ca = []
    cert_basic_constraints_path_len = []

    #for certificates
    cert_frequence = []


    # connection features
    duration_mean = 0
    duration_standard_deviation = 0
    duration_standard_deviation_range = 0
    orig_bytes_mean = 0
    orig_bytes_standard_deviation = 0
    orig_bytes_standard_deviation_range = 0
    resp_bytes_mean = 0
    resp_bytes_standard_deviation = 0
    resp_bytes_standard_deviation_range = 0
    orig_bytes_ratio = 0
    orig_pkts_mean = 0
    orig_pkts_standard_deviation = 0
    orig_pkts_standard_deviation_range = 0
    resp_pkts_mean = 0
    resp_pkts_standard_deviation = 0
    resp_pkts_standard_deviation_range = 0
    orig_pkts_ratio = 0
    periodicity_mean = 0
    periodicity_standard_deviation = 0
    periodicity_standard_deviation_range = 0
    #[S0 S1 SF REJ S2 S3 RSTO RSTR RSTOS0 RSTRH SH SHR OTH]
    conn_state_ratio = [0,0,0,0,0,0,0,0,0,0,0,0,0]

    #ssl features
    ssl_ratio = 0

    ssl_version_ratio = [0]*6

    ssl_cipher_ratio = [0]*34
    #['-', ip, noip]
    ssl_server_name_ratio = [0,0,0]
    #resumed: T/F T's ratio
    ssl_resumed_ratio = 0

    ssl_last_alert_ratio = [0]*23
    #established: T/F T's ratio
    ssl_established_ratio = 0
    #three features about ssl_cert_chain_fuids
    ssl_cert_chain_fuids_mean = 0
    ssl_cert_chain_fuids_standard_deviation = 0
    ssl_cert_chain_fuids_standard_deviation_range = 0
    #['-', 'unable to get local issuer certificate', 'ok', 'self signed certificate in certificate chain', 'self signed certificate']
    # ssl_validation_status_ratio = [0,0,0,0,0]
    #the ratio of ssls which have cert
    ssl_cert_ratio = 0


    #certificate features
    #0 there is no certificate; 1 there are certificates
    cert_exist = 0
    cert_version_ratio = [0]*3
    #certificate serial length
    cert_serial_length_mean = 0
    cert_serial_length_standard_deviation = 0
    cert_serial_length_standard_deviation_range = 0
    #certificate validity period
    cert_validity_period_mean = 0
    cert_validity_period_standard_deviation = 0
    cert_validity_period_standard_deviation_range = 0
    #validity ratio during the capturing
    cert_validity_ratio = 0
    #age of certificate
    cert_age_mean = 0
    cert_age_standard_deviation = 0
    cert_age_standard_deviation_range = 0
    #'md5WithRSAEncryption', 'id-ecPublicKey', 'shaWithRSAEncryption', 'rsaEncryption'
    cert_key_alg_ratio = [0]*4
    #in the file: ['sha1WithRSAEncryption', 'md5WithRSAEncryption', 'sha256WithRSAEncryption', 'sha1WithRSA']
    #['sha1WithRSA', 'md2WithRSAEncryption', 'md5WithRSAEncryption', 'ecdsa-with-SHA384', 'ecdsa-with-SHA256', 'sha512WithRSAEncryption', 'sha1WithRSAEncryption', 'sha256WithRSAEncryption', 'sha384WithRSAEncryption']
    cert_sig_alg_ratio = [0]*9
    #['ecdsa', '-', 'rsa']
    cert_key_type_ratio = [0]*3
    #['-', '256', '384', '4096', '1024', '512', '2048']
    cert_key_length_ratio = [0]*7
    #['17', '65537', '3', '35353', '-']
    cert_exponent_ratio = [0]*5
    #['-', 'F', 'T']
    cert_basic_constraints_ca_ratio = [0,0,0]
    #domain number in san.dns
    cert_san_dns_domain_number_mean = 0
    cert_san_dns_domain_number_standard_deviation = 0
    cert_san_dns_domain_number_standard_deviation_range = 0
    #SNI in SAN DNS
    cert_san_dns_sni_ratio = 0
    #CN in SAN DNS
    cert_san_dns_cn_ratio = 0



    def __init__(self, unitID, label):
        self.unitID = unitID
        self.label = label

        self.conn_ts = []
        self.conn_uid = []
        self.conn_orig_h = []
        self.conn_orig_p = []
        self.conn_resp_h = []
        self.conn_resp_p = []
        self.conn_proto = []
        self.conn_service = []
        self.conn_duration = []
        self.conn_orig_bytes = []
        self.conn_resp_bytes = []
        self.conn_state = []
        self.conn_local_orig = []
        self.conn_local_resp = []
        self.conn_missed_bytes = []
        self.conn_history = []
        self.conn_orig_pkts = []
        self.conn_orig_ip_bytes = []
        self.conn_resp_pkts = []
        self.conn_resp_ip_bytes = []
        self.conn_tunnel_parents = []

        # ssl parameters
        self.ssl_time = []
        self.ssl_uid = []
        self.ssl_version = []
        self.ssl_cipher = []
        #self.ssl_curve = []
        self.ssl_server_name = []
        self.ssl_resumed = []
        self.ssl_last_alert = []
        #self.ssl_next_protocol = []
        self.ssl_established = []
        self.ssl_cert_chain_fuids = []
        #self.ssl_client_cert_chain_fuids = []
        #self.ssl_subject = []
        #self.ssl_issuer = []
        #self.ssl_client_subject = []
        #self.ssl_client_issuer = []

        # self.ssl_validation_status = []
        # self.ssl_notary_first_seen = []
        # self.ssl_notary_last_seen = []
        # self.ssl_notary_times_seen = []
        # self.ssl_notary_valid = []

        # certificate parameters
        self.cert_time = []
        self.cert_uid = []
        self.cert_version = []
        self.cert_serial = []
        self.cert_subject = []
        #self.cert_issuer = []
        self.cert_not_valid_before = []
        self.cert_not_valid_after = []
        self.cert_key_alg = []
        self.cert_sig_alg = []
        self.cert_key_type = []
        self.cert_key_length = []
        self.cert_exponent = []
        #self.cert_curve = []
        self.cert_san_dns = []
        #self.cert_san_uri = []
        #self.cert_san_email = []
        #self.cert_san_ip = []
        self.cert_basic_constraints_ca = []
        self.cert_basic_constraints_path_len = []

        # for certificates
        self.cert_frequence = []

        # connection features
        self.duration_mean = 0
        self.duration_standard_deviation = 0
        self.duration_standard_deviation_range = 0
        self.orig_bytes_mean = 0
        self.orig_bytes_standard_deviation = 0
        self.orig_bytes_standard_deviation_range = 0
        self.resp_bytes_mean = 0
        self.resp_bytes_standard_deviation = 0
        self.resp_bytes_standard_deviation_range = 0
        self.orig_bytes_ratio = 0
        self.orig_pkts_mean = 0
        self.orig_pkts_standard_deviation = 0
        self.orig_pkts_standard_deviation_range = 0
        self.resp_pkts_mean = 0
        self.resp_pkts_standard_deviation = 0
        self.resp_pkts_standard_deviation_range = 0
        self.orig_pkts_ratio = 0
        self.periodicity_mean = 0
        self.periodicity_standard_deviation = 0
        self.periodicity_standard_deviation_range = 0
        # [S0 S1 SF REJ S2 S3 RSTO RSTR RSTOS0 RSTRH SH SHR OTH]
        self.conn_state_ratio = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        # ssl features
        self.ssl_ratio = 0

        self.ssl_version_ratio = [0]*6

        self.ssl_cipher_ratio = [0]*34

        # ['-', ip, noip]
        self.ssl_server_name_ratio = [0, 0, 0]
        # resumed: T/F T's ratio
        self.ssl_resumed_ratio = 0
        # ['-', 'unknown-218', 'unknown-156', 'internal_error', 'bad_record_mac', 'bad_certificate', 'unknown-238', 'unrecognized_name', 'certificate_unknown', 'certificate_expired', 'unknown_ca', 'unknown-170', 'unknown-76', 'decrypt_error', 'unknown-58', 'unknown-7', 'handshake_failure', 'unexpected_message', 'close_notify']
        self.ssl_last_alert_ratio = [0]*23
        # established: T/F T's ratio
        self.ssl_established_ratio = 0
        # three features about ssl_cert_chain_fuids
        self.ssl_cert_chain_fuids_mean = 0
        self.ssl_cert_chain_fuids_standard_deviation = 0
        self.ssl_cert_chain_fuids_standard_deviation_range = 0
        # ['-', 'unable to get local issuer certificate', 'ok', 'self signed certificate in certificate chain', 'self signed certificate']
        # self.ssl_validation_status_ratio = [0, 0, 0, 0, 0]
        # the ratio of ssls which have cert
        self.ssl_cert_ratio = 0

        # certificate features
        # 0 there is no certificate; 1 there are certificates
        self.cert_exist = 0
        self.cert_version_ratio = [0]*3
        # certificate serial length
        self.cert_serial_length_mean = 0
        self.cert_serial_length_standard_deviation = 0
        self.cert_serial_length_standard_deviation_range = 0
        # certificate validity period
        self.cert_validity_period_mean = 0
        self.cert_validity_period_standard_deviation = 0
        self.cert_validity_period_standard_deviation_range = 0
        # validity ratio during the capturing
        self.cert_validity_ratio = 0
        # age of certificate
        self.cert_age_mean = 0
        self.cert_age_standard_deviation = 0
        self.cert_age_standard_deviation_range = 0
        #'md5WithRSAEncryption', 'id-ecPublicKey', 'shaWithRSAEncryption', 'rsaEncryption'
        self.cert_key_alg_ratio = [0]*4
        # in the file: ['sha1WithRSAEncryption', 'md5WithRSAEncryption', 'sha256WithRSAEncryption', 'sha1WithRSA']
        # ['sha1WithRSAEncryption', 'md5WithRSAEncryption', 'sha256WithRSAEncryption']
        self.cert_sig_alg_ratio = [0]*9
        # ['ecdsa', '-', 'rsa']
        self.cert_key_type_ratio = [0]*3
        # ['-', '256', '384', '4096', '1024', '512', '2048']
        self.cert_key_length_ratio = [0]*7
        # ['17', '65537', '3', '35353', '-']
        self.cert_exponent_ratio = [0]*5
        # ['-', 'F', 'T']
        self.cert_basic_constraints_ca_ratio = [0, 0, 0]
        # domain number in san.dns
        self.cert_san_dns_domain_number_mean = 0
        self.cert_san_dns_domain_number_standard_deviation = 0
        self.cert_san_dns_domain_number_standard_deviation_range = 0
        # SNI in SAN DNS
        self.cert_san_dns_sni_ratio = 0
        # CN in SAN DNS
        self.cert_san_dns_cn_ratio = 0

    def add_conn_label_log(self, conn_label_line):
        '''
        add a data line from conn_label.log
        :param conn_label_line: the data line
        :return:
        '''
        tab = '\t'
        split = conn_label_line.split(tab)
        if not (split[0] == '-' or split[8] == '-' or split[9] == '-' or split[10] == '-' or split[16] == '-' or split[18] == '-' or "background" in line):

            self.conn_ts.append(float(split[0]))
            self.conn_uid.append(split[1])
            self.conn_orig_h.append(split[2])
            self.conn_orig_p.append(split[3])
            self.conn_resp_h.append(split[4])
            self.conn_resp_p.append(split[5])
            self.conn_proto.append(split[6])
            self.conn_service.append(split[7])
            self.conn_duration.append(float(split[8]))
            self.conn_orig_bytes.append(float(split[9]))
            self.conn_resp_bytes.append(float(split[10]))
            self.conn_state.append(split[11])
            self.conn_local_orig.append(split[12])
            self.conn_local_resp.append(split[13])
            self.conn_missed_bytes.append(split[14])
            self.conn_history.append(split[15])
            self.conn_orig_pkts.append(float(split[16]))
            self.conn_orig_ip_bytes.append(split[17])
            self.conn_resp_pkts.append(float(split[18]))
            self.conn_resp_ip_bytes.append(split[19])
            self.conn_tunnel_parents.append(split[20][:-1])

        # else:
        #     print(conn_label_line)

    def add_ssl_log(self, ssl_line):
        """
        add a data line from ssl.log
        :param ssl_line: the data line
        :return:
        """
        tab = '\t'
        split = ssl_line.split(tab)
        if not (split[0]=='-'):
            self.ssl_time.append(float(split[0]))
            self.ssl_uid.append(split[1])
            self.ssl_version.append(split[6])
            self.ssl_cipher.append(split[7])
            #self.ssl_curve.append(split[8])
            self.ssl_server_name.append(split[9])
            self.ssl_resumed.append(split[10])
            self.ssl_last_alert.append(split[11])
            #self.ssl_next_protocol.append(split[12])
            self.ssl_established.append(split[13])
            self.ssl_cert_chain_fuids.append(split[14])
            #self.ssl_client_cert_chain_fuids.append(split[15])
            #self.ssl_subject.append(split[16])
            #self.ssl_issuer.append(split[17])
            #self.ssl_client_subject.append(split[18])
            #self.ssl_client_issuer.append(split[19])

            # self.ssl_validation_status.append(split[20])
            # self.ssl_notary_first_seen.append(split[21])
            # self.ssl_notary_last_seen.append(split[22])
            # self.ssl_notary_times_seen.append(split[23])
            # self.ssl_notary_valid.append(split[24][:-1])

    def add_cert_log(self, cert_line):
        """
        add a line from x509.log
        :param cert_line: the line
        :return:
        """
        tab = '\t'
        split = cert_line.split(tab)
        if not split[0] == '-':
            self.cert_time.append(split[0])
            self.cert_uid.append(split[1])
            self.cert_version.append(split[2])
            self.cert_serial.append(split[3])
            self.cert_subject.append(split[4])
            #self.cert_issuer.append(split[5])
            self.cert_not_valid_before.append(split[6])
            self.cert_not_valid_after.append(split[7])
            self.cert_key_alg.append(split[8])
            self.cert_sig_alg.append(split[9])
            self.cert_key_type.append(split[10])
            self.cert_key_length.append(split[11])
            self.cert_exponent.append(split[12])
            #self.cert_curve.append(split[13])
            self.cert_san_dns.append(split[14])
            #self.cert_san_uri.append(split[15])
            #self.cert_san_email.append(split[16])
            #self.cert_san_ip.append(split[17])
            self.cert_basic_constraints_ca.append(split[18])
            self.cert_basic_constraints_path_len.append(split[19][-1])

    def compute_conn_features(self):



        self.duration_mean = self.mean(self.conn_duration)
        self.duration_standard_deviation = self.standard_deviation(self.conn_duration)
        self.duration_standard_deviation_range = self.standard_deviation_range(self.conn_duration)
        self.orig_bytes_mean = self.mean(self.conn_orig_bytes)
        self.orig_bytes_standard_deviation = self.standard_deviation(self.conn_orig_bytes)
        self.orig_bytes_standard_deviation_range = self.standard_deviation_range(self.conn_orig_bytes)
        self.resp_bytes_mean = self.mean(self.conn_resp_bytes)
        self.resp_bytes_standard_deviation = self.standard_deviation(self.conn_resp_bytes)
        self.resp_bytes_standard_deviation_range = self.standard_deviation_range(self.conn_resp_bytes)
        self.orig_bytes_ratio = self.ratio(self.conn_orig_bytes, self.conn_resp_bytes)
        self.orig_pkts_mean = self.mean(self.conn_orig_pkts)
        self.orig_pkts_standard_deviation = self.standard_deviation(self.conn_orig_pkts)
        self.orig_pkts_standard_deviation_range = self.standard_deviation_range(self.conn_orig_pkts)
        self.resp_pkts_mean = self.mean(self.conn_resp_pkts)
        self.resp_pkts_standard_deviation = self.mean(self.conn_resp_pkts)
        self.resp_pkts_standard_deviation_range = self.standard_deviation_range(self.conn_resp_pkts)
        self.orig_pkts_ratio = self.ratio(self.conn_orig_pkts, self.conn_resp_pkts)
        #compute periodicity
        if len(self.conn_ts) == 1:
            self.periodicity_mean = 0
            self.periodicity_standard_deviation = 0
            self.periodicity_standard_deviation_range = 0
        else:
            firstTime = []
            for i in range(1, len(self.conn_ts)):
                firstTime.append(self.conn_ts[i]-self.conn_ts[i-1])
            self.periodicity_mean = self.mean(firstTime)
            self.periodicity_standard_deviation = self.standard_deviation(firstTime)
            self.periodicity_standard_deviation_range = self.standard_deviation_range(firstTime)

        #compute conn_state_ratio
        self.conn_state_ratio = self.type_ratio(["S0","S1","SF","REJ","S2","S3","RSTO","RSTR","RSTOS0","RSTRH","SH","SHR","OTH"], self.conn_state)

    def compute_ssl_features(self):
        #compute ssl_ratio
        n = 0
        for i in self.ssl_uid:
            if i in self.conn_uid:
                n += 1
        self.ssl_ratio = n/len((self.conn_uid))

        #compute ssl_version
        self.ssl_version_ratio = self.type_ratio(['TLSv11', 'TLSv10', 'SSLv3', 'SSLv2', '-', 'TLSv12'], self.ssl_version)
        # self.ssl_version_ratio = self.type_ratio(['-', 'TLSv12', 'SSLv3', 'SSLv2'], self.ssl_version)

        #compute ssl_cipher_ratio
        typelist = ['TLS_RSA_WITH_AES_256_CBC_SHA256', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_DH_ANON_WITH_RC4_128_MD5', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5', 'TLS_RSA_WITH_RC4_128_MD5', 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'SSLv20_CK_RC4_128_WITH_MD5', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', '-']
        # typelist = ['-', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_DH_ANON_WITH_RC4_128_MD5', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_RC4_128_MD5', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'SSLv20_CK_RC4_128_WITH_MD5', 'SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5']
        self.ssl_cipher_ratio = self.type_ratio(typelist, self.ssl_cipher)


        #compute ssl_server_name_ratio
        for name in self.ssl_server_name:
            if name == '-':
                self.ssl_server_name_ratio[0] += 1
            elif self.checkip(name):
                self.ssl_server_name_ratio[1] += 1
            else:
                self.ssl_server_name_ratio[2] += 1
        for i in range(0, len(self.ssl_server_name_ratio)):
            self.ssl_server_name_ratio[i] = self.ssl_server_name_ratio[i]/len(self.ssl_server_name)

        #compute ssl_resumed_ratio
        self.ssl_resumed_ratio = self.type_ratio(['T', 'F'], self.ssl_resumed)[0]

        #compute ssl_last_alert_ratio
        typelist = ['certificate_unknown', 'unknown-170','internal_error', 'unknown-238', 'illegal_parameter', 'bad_record_mac', 'certificate_expired', 'unknown-218', 'unknown-156', 'handshake_failure', 'protocol_version', 'decode_error', 'unknown-58', 'close_notify', 'unexpected_message', 'unrecognized_name', 'unknown-7', 'unknown-76', 'unknown_ca', 'decrypt_error', 'inappropriate_fallback', '-', 'bad_certificate']
        self.ssl_last_alert_ratio = self.type_ratio(typelist, self.ssl_last_alert)

        #compute ssl_established_ratio
        self.ssl_established_ratio = self.type_ratio(['T', 'F'], self.ssl_established)[0]

        #compute three features about ssl_cert_chain_fuids
        ssl_cert_num = []
        for i in self.ssl_cert_chain_fuids:
            if i == '-':
                ssl_cert_num.append(0)
            else:
                ssl_cert_num.append(len(i.split(',')))
        self.ssl_cert_chain_fuids_mean = self.mean(ssl_cert_num)
        self.ssl_cert_chain_fuids_standard_deviation = self.standard_deviation(ssl_cert_num)
        self.ssl_cert_chain_fuids_standard_deviation_range = self.standard_deviation_range(ssl_cert_num)

        #compute ssl_validation_status_ratio
        # typelist = ['-', 'unable to get local issuer certificate', 'ok', 'self signed certificate in certificate chain', 'self signed certificate']
        # self.ssl_validation_status_ratio = self.type_ratio(typelist, self.ssl_validation_status)

        # the ratio of ssls which have cert
        num = 0
        for i in self.ssl_cert_chain_fuids:
            if not i == '-':
                num += 1
        self.ssl_cert_ratio = num/len(self.ssl_cert_chain_fuids)

    def compute_cert_features(self):
        """
        compute cert_features
        :return:
        """
        # if there is no certificates
        # then cert_exist is set to 0, and the other certificate features remain default
        if len(self.cert_uid) == 0:
            self.cert_exist = 0
        # if there are certificates,
        # then cert_exist is set to 1, and the other certificate features are further calculated
        else:
            self.cert_exist = 1

            #certificate is the basis of the later calculation
            for c in self.cert_uid:
                n = 0
                for i in self.ssl_cert_chain_fuids:
                    if c in i:
                        n += 1
                self.cert_frequence.append(n)

            #cert_version_ratio
            cert_version_with_frequence = self.combine_with_frequence(self.cert_version, self.cert_frequence)
            self.cert_version_ratio = self.type_ratio(['1', '3', '4'], cert_version_with_frequence)

            #compute certificate serial length
            cert_serial_with_frequence = self.combine_with_frequence(self.cert_serial, self.cert_frequence)
            serial_length = []
            for i in cert_serial_with_frequence:
                serial_length.append(len(i))
            self.cert_serial_length_mean = self.mean(serial_length)
            self.cert_serial_length_standard_deviation = self.standard_deviation(serial_length)
            self.cert_serial_length_standard_deviation_range = self.standard_deviation_range(serial_length)

            #compute certificate validity period
            validity_period = []
            for i in range(0, len(self.cert_not_valid_before)):
                validity_period.append(float(self.cert_not_valid_after[i]) - float(self.cert_not_valid_before[i]))
            validity_period_with_frequence = self.combine_with_frequence(validity_period, self.cert_frequence)
            self.cert_validity_period_mean = self.mean(validity_period_with_frequence)
            self.cert_validity_period_standard_deviation = self.standard_deviation(validity_period_with_frequence)
            self.cert_validity_period_standard_deviation_range = self.standard_deviation_range(validity_period_with_frequence)

            #compute validity ratio during the capturing
            validity_status = []
            for i in range(0, len(self.cert_not_valid_before)):
                if float(self.cert_time[i]) > float(self.cert_not_valid_before[i]) and float(self.cert_time[i])<float(self.cert_not_valid_after[i]):
                    validity_status.append(1)
                else:
                    validity_status.append(0)
            validity_status_with_frequence = self.combine_with_frequence(validity_status, self.cert_frequence)
            sum = 0
            for i in validity_period_with_frequence:
                sum += i
            self.cert_validity_ratio = sum/len(validity_status_with_frequence)

            #age of certificate
            cert_age = []
            for i in range(0, len(self.cert_time)):
                age = (float(self.cert_time[i])-float(self.cert_not_valid_before[i]))/(float(self.cert_not_valid_after[i])-float(self.cert_not_valid_before[i]))
                cert_age.append(age)
            cert_age_with_frequence = self.combine_with_frequence(cert_age, self.cert_frequence)
            self.cert_age_mean = self.mean(cert_age_with_frequence)
            self.cert_age_standard_deviation = self.standard_deviation(cert_age_with_frequence)
            self.cert_age_standard_deviation_range = self.standard_deviation_range(cert_age_with_frequence)

            #compute the certificate key_alg ratio
            cert_key_alg_with_frequence = self.combine_with_frequence(self.cert_key_alg, self.cert_frequence)
            self.cert_key_alg_ratio = self.type_ratio(['md5WithRSAEncryption', 'id-ecPublicKey', 'shaWithRSAEncryption', 'rsaEncryption'], cert_key_alg_with_frequence)

            #compute cert_key_alg_ratio
            cert_sig_alg_with_frequence = self.combine_with_frequence(self.cert_sig_alg, self.cert_frequence)
            self.cert_sig_alg_ratio = self.type_ratio(['sha1WithRSA', 'md2WithRSAEncryption', 'md5WithRSAEncryption', 'ecdsa-with-SHA384', 'ecdsa-with-SHA256', 'sha512WithRSAEncryption', 'sha1WithRSAEncryption', 'sha256WithRSAEncryption', 'sha384WithRSAEncryption'], cert_sig_alg_with_frequence)
            #previous code
            # numberlist = [0,0,0]
            # for i in cert_sig_alg_with_frequence:
            #     if i in 'sha1WithRSAEncryption':
            #         numberlist[0] += 1
            #     elif i in 'md5WithRSAEncryption':
            #         numberlist[1] += 1
            #     else:
            #         numberlist[2] += 1
            # for i in range(0, len(numberlist)):
            #     self.cert_sig_alg_ratio[i] = numberlist[i]/len(cert_sig_alg_with_frequence)

            #compute cert_key_type_ratio
            cert_key_type_with_frequence = self.combine_with_frequence(self.cert_key_type, self.cert_frequence)
            self.cert_key_type_ratio = self.type_ratio(['ecdsa', '-', 'rsa'], cert_key_type_with_frequence)

            #compute cert_key_length_ratio
            cert_key_length_with_frequence = self.combine_with_frequence(self.cert_key_length, self.cert_frequence)
            self.cert_key_length_ratio = self.type_ratio(['-', '256', '384', '4096', '1024', '512', '2048'], cert_key_length_with_frequence)

            #compute cert_exponent_ratio
            cert_exponent_with_frequence = self.combine_with_frequence(self.cert_exponent, self.cert_frequence)
            self.cert_exponent_ratio = self.type_ratio(['17', '65537', '3', '35353', '-'], cert_exponent_with_frequence)

            #compute cert_basic_constraints_ca_ratio
            cert_basic_constraints_ca_with_frequence = self.combine_with_frequence(self.cert_basic_constraints_ca, self.cert_frequence)
            self.cert_basic_constraints_ca_ratio = self.type_ratio(['-', 'F', 'T'], cert_basic_constraints_ca_with_frequence)

            #compute domain number in san.dns
            cert_san_dns_number = []
            for i in self.cert_san_dns:
                if i == '-':
                    cert_san_dns_number.append(0)
                else:
                    split = i.split(',')
                    cert_san_dns_number.append(len(split))
            cert_san_dns_number_with_frequence = self.combine_with_frequence(cert_san_dns_number, self.cert_frequence)
            self.cert_san_dns_domain_number_mean = self.mean(cert_san_dns_number_with_frequence)
            self.cert_san_dns_domain_number_standard_deviation = self.standard_deviation(cert_san_dns_number_with_frequence)
            self.cert_san_dns_domain_number_standard_deviation_range = self.standard_deviation_range(cert_san_dns_number_with_frequence)

            #SNI in SAN DNS
            san_dns_str = ""
            for i in self.cert_san_dns:
                san_dns_str += i
            n = 0
            for j in self.ssl_server_name:
                if j in san_dns_str:
                    n += 1
            self.cert_san_dns_sni_ratio = n/len(self.ssl_server_name)

            #CN in SAN DNS
            n = 0
            for i in range(0, len(self.cert_subject)):
                split = self.cert_subject[i].split(',')
                cn = split[0].replace("CN=", "")
                if cn in self.cert_san_dns:
                    n += 1
            self.cert_san_dns_cn_ratio = n/len(self.cert_subject)


    def mean(self, list):
        """
        compute mean
        :param list: number list
        :return: mean
        """
        sum = 0
        for i in list:
            sum += i
        return sum/len(list)

    def standard_deviation(self, list):
        """
        compute standard deviation
        :param list: number list
        :return: standard deviation
        """
        # powersum = 0.0
        # for i in list:
        #     powersum += i*i
        # e = powersum/len(list)
        # e2 = self.mean(list)**2
        # if e > e2:
        #     return 0
        # else:
        #     return (e2-e)**0.5

        arr = np.array(list)
        return np.std(arr)


    def standard_deviation_range(self, list):
        """
        compute standard deviation range
        :param list: number list
        :return: standard deviation range
        """
        up = self.mean(list) + self.standard_deviation(list)
        down = self.mean(list) - self.standard_deviation(list)
        sum = 0
        for i in list:
            if i>up or i<down:
                sum += 1
        return sum/len(list)

    def ratio(self, lista, listb):
        """
        compute the percentage of lista sum
        :param lista: number list
        :param listb: number list
        :return: percentage
        """
        suma = 0
        sumb = 0
        for i in lista:
            suma += i
        for j in listb:
            sumb += j
        try:
            res = suma/(suma+sumb)
        except:
            return -1
        return res

    def type_ratio(self, typelist, list):
        """
        compute the ratio of type in typelist with list
        :param typelist: types
        :param list: wait to be classified
        :return: list of type ratio
        """
        res = []
        for i in typelist:
             res.append(0)
        for i in list:
            a = typelist.index(i)
            res[a] += 1
        for j in range(0, len(typelist)):
            res[j] = res[j]/len(list)
        return res

    def combine_with_frequence(self, list, frequence_list):
        """
        extend the list with the element's frequence in frequence_list
        :param list: type list
        :param frequence_list: frequence list
        :return: a new list integrated with the frequence
        """
        res = []
        for i in range(0, len(list)):
            for a in range(0, frequence_list[i]):
                res.append(list[i])
        return res

    def checkip(self, ip):
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if p.match(ip):
            return True
        else:
            return False

def extract_unitID_label(line, label):
    """
    extract unitID and label from data line in conn_label
    :param line: data line in conn_label.log
    :return: unit string, label string
    """
    tab = '\t'
    split = line.split(tab)
    if label == "conn":
        return split[2] + tab + split[3] + tab + split[4] + tab + split[5] + tab + split[6], split[21][:-1]
    elif label == "ssl":
        return split[2] + tab + split[3] + split[4] + tab + split[5] + tab + split[6]

def numberlist2elementstring(list):
    line = "" + str(list[0])
    for i in range(1, len(list)):
        line = line + tab + str(list[i])
    return line


def get_conn_seg(start, end, unit):
    unitsg = Unit(unit.unitID, unit.label)
    unitsg.conn_ts = unit.conn_ts[start:end]
    unitsg.conn_uid = unit.conn_uid[start: end]
    unitsg.conn_orig_h = unit.conn_orig_h[start: end]
    unitsg.conn_orig_p = unit.conn_orig_p[start: end]
    unitsg.conn_orig_h = unit.conn_orig_h[start: end]
    unitsg.conn_orig_p = unit.conn_orig_p[start: end]
    unitsg.conn_proto = unit.conn_proto[start: end]
    unitsg.conn_service = unit.conn_proto[start: end]
    unitsg.conn_duration = unit.conn_duration[start: end]
    unitsg.conn_orig_bytes = unit.conn_orig_bytes[start: end]
    unitsg.conn_resp_bytes = unit.conn_resp_bytes[start: end]
    unitsg.conn_state = unit.conn_state[start: end]
    unitsg.conn_local_orig = unit.conn_local_orig[start: end]
    unitsg.conn_local_resp = unit.conn_local_resp[start: end]
    unitsg.conn_missed_bytes = unit.conn_missed_bytes[start: end]
    unitsg.conn_history = unit.conn_history[start: end]
    unitsg.conn_orig_pkts = unit.conn_orig_pkts[start: end]
    unitsg.conn_orig_ip_bytes = unit.conn_orig_ip_bytes[start: end]
    unitsg.conn_resp_pkts = unit.conn_resp_pkts[start: end]
    unitsg.conn_resp_ip_bytes = unit.conn_resp_ip_bytes[start: end]
    unitsg.conn_tunnel_parents = unit.conn_tunnel_parents[start: end]
    return unitsg

def add_ssl_to_seg(unitsg, unit):
    for j in range(0, len(unit.ssl_uid)):
        if unit.ssl_uid[j] in unitsg.conn_uid:
            unitsg.ssl_time.append(unit.ssl_time[j])
            unitsg.ssl_uid.append(unit.ssl_uid[j])
            unitsg.ssl_version.append(unit.ssl_version[j])
            unitsg.ssl_cipher.append(unit.ssl_cipher[j])
            #unitsg.ssl_curve.append(unit.ssl_curve[j])
            unitsg.ssl_server_name.append(unit.ssl_server_name[j])
            unitsg.ssl_resumed.append(unit.ssl_resumed[j])
            unitsg.ssl_last_alert.append(unit.ssl_last_alert[j])
            #unitsg.ssl_next_protocol.append(unit.ssl_next_protocol[j])
            unitsg.ssl_established.append(unit.ssl_established[j])
            unitsg.ssl_cert_chain_fuids.append(unit.ssl_cert_chain_fuids[j])
            #unitsg.ssl_client_cert_chain_fuids.append(unit.ssl_client_cert_chain_fuids[j])
            # unitsg.ssl_subject.append(unit.ssl_subject[j])
            # unitsg.ssl_issuer.append(unit.ssl_issuer[j])
            # unitsg.ssl_client_subject.append(unit.ssl_client_subject[j])
            # unitsg.ssl_client_issuer.append(unit.ssl_client_issuer[j])

def add_cert_to_seg(unitsg, unit):
    for x in range(0, len(unit.cert_uid)):
        flag = False
        for certs in unitsg.ssl_cert_chain_fuids:
            if unit.cert_uid[x] in certs:
                flag = True
                break
        if flag:
            unitsg.cert_time.append(unit.cert_time[x])
            unitsg.cert_uid.append(unit.cert_uid[x])
            unitsg.cert_version.append(unit.cert_version[x])
            unitsg.cert_serial.append(unit.cert_serial[x])
            unitsg.cert_subject.append(unit.cert_subject[x])
            # unitsg.cert_issuer.append(unit.cert_issuer[x])
            unitsg.cert_not_valid_before.append(unit.cert_not_valid_before[x])
            unitsg.cert_not_valid_after.append(unit.cert_not_valid_after[x])
            unitsg.cert_key_alg.append(unit.cert_key_alg[x])
            unitsg.cert_sig_alg.append(unit.cert_sig_alg[x])
            unitsg.cert_key_type.append(unit.cert_key_type[x])
            unitsg.cert_key_length.append(unit.cert_key_length[x])
            unitsg.cert_exponent.append(unit.cert_exponent[x])
            # unitsg.cert_curve.append(unit.cert_curve[x])
            unitsg.cert_san_dns.append(unit.cert_san_dns[x])
            # unitsg.cert_san_uri.append(unit.cert_san_uri[x])
            # unitsg.cert_san_email.append(unit.cert_san_email[x])
            # unitsg.cert_san_ip.append(unit.cert_san_ip[x])
            unitsg.cert_basic_constraints_ca.append(unit.cert_basic_constraints_ca[x])
            unitsg.cert_basic_constraints_path_len.append(unit.cert_basic_constraints_path_len[x])

def use_timeout(unitDict):
    units = []
    for unitID in unitDict:
        conn_ts = unitDict[unitID].conn_ts
        duration = unitDict[unitID].conn_duration
        unit = unitDict[unitID]
        sp_previous = 0
        i = 0
        for i in range(0,len(conn_ts)-1):

            if (conn_ts[i+1]-conn_ts[i]-duration[i])>120:
                #create unit segment
                #set conn part
                unitsg = get_conn_seg(sp_previous, i+1, unit)

                #add conresponding ssl
                add_ssl_to_seg(unitsg, unit)

                #add coresponding cert
                add_cert_to_seg(unitsg, unit)

                if len(unitsg.ssl_time) != 0:
                    units.append(unitsg)
                sp_previous = i+1
        #the last conn is the last unit
        unitsg = get_conn_seg(sp_previous, len(conn_ts), unit)

        add_ssl_to_seg(unitsg, unit)
        add_cert_to_seg(unitsg, unit)
        if len(unitsg.ssl_time) != 0:
            units.append(unitsg)
    return units



record_num_malware = 0
record_num_normal = 0

database_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset"
dataset_names = os.listdir(database_path)
for name in dataset_names:
    dataset_path = database_path+"\\"+name

    split = name.split('-')
    if len(split)<5:
        continue

    if int(split[4]) in [164,31,61, 215]:
        continue

    binetflow_paths = glob.glob(dataset_path+"\\*binetflow")
    for binetflow_path in binetflow_paths:
        bro_folder = binetflow_path.split('.')[0]
        bro_folder_name = bro_folder.split('\\')[-1]

        features_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\features\\" + name + "_" + bro_folder_name + "-features.log"
        if os.path.exists(features_path):
            continue


        print("------------------------------------------------------------")
        print(">>>Start to handle with ", name)


        conn_label_log_path = bro_folder+"\\conn_label.log"
        ssl_log_path = bro_folder + "\\ssl.log"
        cert_log_path = bro_folder + "\\x509.log"

        #skip which do not have those files
        if not (os.path.exists(conn_label_log_path) and os.path.exists(ssl_log_path) and os.path.exists(cert_log_path)):
            continue

        # conn_label_log_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\CTU-Malware-Capture-Botnet-"+str(dataseti)+"\\bro\\self_create\\conn_label.log"
        # conn_label_log_path = "/home/jiyuan/Work/MalwareTrafficDetection/Dataset/CTU-Malware-Capture-Botnet-42/bro/self_create/conn_label.log"
        unitDict = {}

        print(">>>start to read conn_label")
        n=0
        with open(conn_label_log_path) as f:

            for line in f:

                if not line[0] == '#':
                    unitID, label = extract_unitID_label(line, "conn")
                    if "background" not in line:
                        if unitID not in unitDict:
                            unitDict[unitID] = Unit(unitID, label)
                        #ssl_flag is default normal, revise when reading ssl_log
                        unitDict[unitID].add_conn_label_log(line)
            print(">>>finish reading conn_label")
            f.close()

        conn_uid_dict = dict()
        for unitID in unitDict:
            for i in unitDict[unitID].conn_uid:
                conn_uid_dict[i] = unitID


        # ssl_log_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\CTU-Malware-Capture-Botnet-"+str(dataseti)+"\\bro\\ssl.log"
        print(">>>start to read ssl")
        with open(ssl_log_path) as f:
            # n=0
            for line in f:
                if not line[0] == "#":
                    split = line.split('\t')
                    try:
                        unitDict[conn_uid_dict[split[1]]].add_ssl_log(line)
                    except:
                        # n += 1
                        continue
                        # print("ssl not in conn :", line)
            f.close()
            print(">>>finish reading ssl")

        #delete the conns without ssl
        #we only need encrypted traffic
        print(">>>delete conns without ssl")
        listdel = []
        for unitID in unitDict:
            if len(unitDict[unitID].ssl_time) == 0:
                listdel.append(unitID)
        for i in listdel:
            unitDict.pop(i)

        cert_uid_dict = dict()
        for unitID in unitDict:
            for i in unitDict[unitID].ssl_cert_chain_fuids:
                for j in i.split(','):
                    cert_uid_dict[j] = unitID


        # cert_log_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\CTU-Malware-Capture-Botnet-"+str(dataseti)+"\\bro\\x509.log"
        print(">>>start to read x509.log")
        with open(cert_log_path) as f:
            for line in f:
                if not line[0] == "#":
                    split = line.split('\t')
                    try:
                        unitDict[cert_uid_dict[split[1]]].add_cert_log(line)
                    except:
                        continue
                        # print("ssl not in conn :", line)
            f.close()
            print(">>>finish reading x509.log")

        # #-------------------------------------------------------------------
        # #donot use timeout
        print(">>>start to compute features")
        print("computing process")
        num = 0
        total = len(unitDict)
        for unitID in unitDict:
            unitDict[unitID].compute_conn_features()
            unitDict[unitID].compute_ssl_features()
            unitDict[unitID].compute_cert_features()
            num+=1
        print(">>>finish computing features")
        # #--------------------------------------------------------------------

        #--------------------------------------------------------------------
        #use timeout
        # print(">>>start to use timeout to cut flow into segments")
        # units = use_timeout(unitDict)
        # print(">>>finish using timeout to cut flow into segments")
        # print(">>>start to compute features")
        # num = 0
        # total = len(units)
        # for unit in units:
        #     unit.compute_conn_features()
        #     unit.compute_ssl_features()
        #     unit.compute_cert_features()
        #     # num+=1
        #     # print(num,"/", total)
        # print(">>>finish computing features")
        #--------------------------------------------------------------------

        print(">>>start to write into features")
        tab = '\t'
        features_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\features\\"+name+"_"+bro_folder_name+ "-features.log"
        # features_path = "D:\\Work\PyCharm-workspace\\MalwareTrafficDetection\\Dataset\\features\\CTU-Malware-Capture-Botnet-" + str(dataseti) + "-features.log"
        # conn_features_path = "/home/jiyuan/Work/MalwareTrafficDetection/Dataset/CTU-Malware-Capture-Botnet-42/bro/self_create/conn_features.log"
        with open(features_path, 'w') as f:
            for unitID in unitDict:
                unit = unitDict[unitID]
            # for unit in units:
                conn_ts_np = np.array(unit.conn_ts)
                conn_duration_np = np.array(unit.conn_duration)
                f.write(unit.unitID + tab + unit.label + tab + str(np.max(conn_ts_np+conn_duration_np) - np.min(conn_ts_np)) + tab +
                    str(unit.duration_mean) + tab + str(unit.duration_standard_deviation) + tab + str(unit.duration_standard_deviation_range) + tab + str(
                    unit.orig_bytes_mean) + tab + str(unit.orig_bytes_standard_deviation) + tab + str(
                    unit.orig_bytes_standard_deviation_range) + tab + str(unit.resp_bytes_mean) + tab + str(
                    unit.resp_bytes_standard_deviation) + tab + str(
                    unit.resp_bytes_standard_deviation_range) + tab + str(unit.orig_bytes_ratio) + tab + str(
                    unit.orig_pkts_mean) + tab + str(unit.orig_pkts_standard_deviation) + tab + str(
                    unit.orig_pkts_standard_deviation_range) + tab + str(unit.resp_pkts_mean) + tab + str(
                    unit.resp_pkts_standard_deviation) + tab + str(unit.resp_pkts_standard_deviation_range) + tab + str(
                    unit.orig_pkts_ratio) + tab + str(unit.periodicity_mean) + tab + str(
                    unit.periodicity_standard_deviation) + tab + str(
                    unit.periodicity_standard_deviation_range) + tab + numberlist2elementstring(
                    unit.conn_state_ratio) + tab +
                    str(unit.ssl_ratio) + tab + numberlist2elementstring(unit.ssl_version_ratio) + tab +
                    numberlist2elementstring(unit.ssl_cipher_ratio) + tab + numberlist2elementstring(unit.ssl_server_name_ratio) + tab +
                    str(unit.ssl_resumed_ratio) + tab + numberlist2elementstring(unit.ssl_last_alert_ratio) + tab +
                    str(unit.ssl_established_ratio) + tab + str(unit.ssl_cert_chain_fuids_mean) + tab +
                    str(unit.ssl_cert_chain_fuids_standard_deviation) + tab + str(unit.ssl_cert_chain_fuids_standard_deviation_range) + tab +
                    #numberlist2elementstring(unit.ssl_validation_status_ratio) + tab +
                    str(unit.ssl_cert_ratio) + tab +
                    str(unit.cert_exist) + tab + numberlist2elementstring(unit.cert_version_ratio) + tab + str(unit.cert_serial_length_mean) + tab +
                    str(unit.cert_serial_length_standard_deviation) + tab + str(unit.cert_serial_length_standard_deviation_range) + tab +
                    str(unit.cert_validity_period_mean) + tab + str(unit.cert_validity_period_standard_deviation) + tab +
                    str(unit.cert_validity_period_standard_deviation_range) + tab + str(unit.cert_validity_ratio) + tab +
                    str(unit.cert_age_mean) + tab + str(unit.cert_age_standard_deviation) + tab + str(unit.cert_age_standard_deviation_range) + tab +
                    numberlist2elementstring(unit.cert_key_alg_ratio) + tab + numberlist2elementstring(unit.cert_sig_alg_ratio) + tab +
                    numberlist2elementstring(unit.cert_key_type_ratio) + tab + numberlist2elementstring(unit.cert_key_length_ratio) + tab +
                    numberlist2elementstring(unit.cert_exponent_ratio) + tab + numberlist2elementstring(unit.cert_basic_constraints_ca_ratio) + tab +
                    str(unit.cert_san_dns_domain_number_mean) + tab + str(unit.cert_san_dns_domain_number_standard_deviation) + tab +
                    str(unit.cert_san_dns_domain_number_standard_deviation_range) + tab + str(unit.cert_san_dns_sni_ratio) + tab +
                    str(unit.cert_san_dns_cn_ratio) + '\n')

            f.close()
            print(">>>finish writing into features")

        for i in unitDict:
            if 'normal' in unitDict[i].label:
                record_num_normal += 1
            elif 'botnet' in unitDict[i].label:
                record_num_malware += 1

        print(">>>Finish handling with ", name)
        print("------------------------------------------------------------")

print("total record number is (normal/malware): ", record_num_normal, "/", record_num_malware)