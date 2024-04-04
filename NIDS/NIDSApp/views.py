import asyncio
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseBadRequest
import pyshark
import random
import pickle
import tempfile
import sklearn
import warnings
import joblib
from numpy import array
warnings.filterwarnings("ignore")
import asyncio
import os
import tempfile
from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from . serializer import *

loop = asyncio.new_event_loop()

model = joblib.load('./NIDSApp/model.joblib')

# Create your views here.
def scanAttacks(file_name):
    with pyshark.FileCapture(file_name) as capture : 
        result_array = []
        n = 0
        for packet in capture:
            try:
                total_udp_packets = 0
                total_tcp_packets = 0
                total_icmp_packets = 0
                if hasattr(packet, 'transport_layer'):
                    if packet.transport_layer == 'TCP':
                        total_tcp_packets += 1
                    elif packet.transport_layer == 'UDP':
                        total_udp_packets += 1
                    elif packet.transport_layer == 'ICMP':
                        total_icmp_packets += 1
            # 1. Duration 
                duration = float(packet.frame_info.time_delta_displayed) * 10**6
                
        ####    # 2. Protocol Type
                protocol_type_encoding = {'icmp': 0, 'tcp': 1, 'udp': 2, 'oth': -1}
                protocolTypeValue = packet.frame_info.protocols
                
                if 'icmp' in protocolTypeValue:
                    protocol_type = 'icmp'
                elif 'tcp' in protocolTypeValue:
                    protocol_type = 'tcp'
                elif 'udp' in protocolTypeValue:
                    protocol_type = 'udp'
                else:
                    protocol_type = 'oth'
                protocol_type = protocol_type_encoding[protocol_type]
        ####    # 3. Service
                if 'TCP' in packet:
                    serviceValue = packet.tcp.dstport
                elif 'UDP' in packet:
                    serviceValue = packet.udp.dstport
                elif 'IP' in packet:
                    serviceValue = random.choice([0, -1])
                else:
                    serviceValue = 123456
                serviceMap = {
                    0: 'eco_i', -1: 'ecr_i', 6667: 'IRC', 6000: 'X11', 210: 'Z39_50', 113: 'auth', 179: 'bgp',
                    25: 'courier', 105: 'csnet_ns', 13: 'daytime', 9: 'discard', 53: 'domain', 7: 'echo', 512: 'exec',
                    79: 'finger', 21: 'ftp', 20: 'ftp_data', 70: 'gopher', 80: 'http', 2784: 'http_2784', 443: 'http_443',
                    8001: 'http_8001', 143: 'imap4', 543: 'klogin', 544: 'kshell', 389: 'ldap', 513: 'login', 57: 'mtp',
                    138: 'netbios_dgm', 137: 'netbios_ns', 139: 'netbios_ssn', 119: random.choice(['nnsp', 'nntp']),
                    123: 'ntp_u', 109: 'pop_2', 110: 'pop_3', 514: random.choice(['remote_job', 'shell']), 77: 'rje',
                    25: 'smtp', 66: 'sql_net', 22: 'ssh', 111: 'sunrpc', 95: 'supdup', 11: 'systat', 23: 'telnet',
                    69: 'tftp_u', 37: 'time', 540: 'uucp', 117: 'uucp_path', 43: 'whois', 60593: 'netstat'
                    }
                serviceType = serviceMap.get(int(serviceValue), 'None')
                service = serviceType
                if service == 'None':
                    service = random.choice(['private', 'domain_u', 'other'])
                service_encoding = {'IRC': 0, 'X11': 1, 'Z39_50': 2, 'aol': 3, 'auth': 4,
                    'bgp': 5, 'courier': 6, 'csnet_ns': 7, 'ctf': 8, 'daytime': 9, 'discard': 10, 'domain': 11, 'domain_u': 12,
                    'echo': 13, 'eco_i': 14, 'ecr_i': 15, 'efs': 16, 'exec': 17, 'finger': 18, 'ftp': 19, 'ftp_data': 20,
                    'gopher': 21, 'harvest': 22, 'hostnames': 23, 'http': 24, 'http_2784': 25, 'http_443': 26, 'http_8001': 27, 'imap4': 28,
                    'iso_tsap': 29, 'klogin': 30, 'kshell': 31, 'ldap': 32, 'link': 33, 'login': 34, 'mtp': 35, 'name': 36,
                    'netbios_dgm': 37, 'netbios_ns'
                                    : 38, 'netbios_ssn': 39, 'netstat': 40, 'nnsp': 41, 'nntp': 42, 'ntp_u': 43, 'other': 44,
                    'pm_dump': 45, 'pop_2': 46, 'pop_3': 47, 'printer': 48, 'private': 49, 'red_i': 50, 'remote_job': 51, 'rje': 52,
                    'shell': 53, 'smtp': 54, 'sql_net': 55, 'ssh': 56, 'sunrpc': 57, 'supdup': 58, 'systat': 59, 'telnet': 60,
                    'tftp_u': 61, 'tim_i': 62, 'time': 63, 'urh_i': 64, 'urp_i': 65, 'uucp': 66, 'uucp_path': 67, 'vmnet': 68, 'whois': 69}
                service = service_encoding[service]
        ####    # 4. Flags
                # OTH (Other): 0x00 (No flags set)
                # REJ (Reject): 0x14 (RST, ACK flags set)
                # RSTO (Reset Originator): 0x04 (RST flag set)
                # RSTOS0 (Reset Originator, SYN Stealth): 0x14 (RST, ACK flags set)
                # RSTR (Reset Response): 0x14 (RST, ACK flags set)
                # S0 (Stealth Scan, No Response): 0x00 (No flags set)
                # S1 (Stealth Scan, Syn Ack): 0x12 (SYN, ACK flags set)
                # S2 (Stealth Scan, No Syn Ack): 0x04 (RST flag set)
                # S3 (Stealth Scan, RST Received): 0x14 (RST, ACK flags set)
                # SF (Stealth Scan, FIN): 0x01 (FIN flag set)
                # SH (Stealth Scan, Half Open): 0x02 (SYN flag set)
                
                if 'TCP' in packet:
                    flagcode = packet.tcp.flags
                elif 'IP' in packet:
                    flagcode = packet.ip.flags
                elif 'UDP' in packet:
                    flagcode = packet.udp.flags
                else:
                    flagcode = None
                if flagcode == '0x00':
                    flag = 'S0'
                elif flagcode == '0x02':
                    flag = 'SH'
                elif flagcode == '0x14':
                    flag = random.choice(['REJ', 'S3', 'RSTOS0'])
                elif flagcode == '0x04':
                    flag = 'RSTO'
                elif flagcode == '0x12':
                    flag = 'S1'
                elif flagcode == '0x04':
                    flag = 'S2'
                elif flagcode == '0x01':
                    flag = 'SF'
                else:
                    flag = 'OTH'
                flag_encoding = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9, 'SH': 10}
                flag = flag_encoding[flag]
            # 5 & 6. Source and Destination Lengths
                if 'TCP' in packet:
                    src_bytes = int(packet.tcp.len)
                    dst_bytes = int(packet.tcp.len)
                elif 'UDP' in packet:
                    src_bytes = int(packet.udp.length)
                    dst_bytes = int(packet.udp.length)
                elif 'icmp' in packet:
                    src_bytes = int(packet.icmp.length)
                    dst_bytes = int(packet.icmp.length)
                else:
                    src_bytes = 0
                    dst_bytes = 0
            # 9. Urgent: Only for TCP packets
                if 'TCP' in packet:
                    urgent = int(packet.tcp.urgent_pointer)
                else:
                    urgent = 0
            
            # 11. Number of Failed Logins: Depends on Network Traffic
                def count_failed_logins():
                    failed_logins = 0
                    if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport') and hasattr(packet, 'http') and hasattr(packet.http, 'response_for_uri'):
                        if packet.http.response_for_uri == "login.php" and packet.http.response_code == "401":
                            failed_logins += 1
                    return failed_logins
                num_failed_logins = count_failed_logins()
            
        ####    # 25. Rate of packets that have the 'S1' (SYN error) flag set, indicating errors related to the SYN flag in TCP packets
                syn_error_tcp_packets = 0
                syn_error_icmp_packets = 0
                def calculate_syn_error_rate(total_tcp_packets, total_icmp_packets, syn_error_tcp_packets, syn_error_icmp_packets):
                    if hasattr(packet, 'transport_layer'):
                        if 'TCP' in packet:
                            if hasattr(packet.tcp, 'flags') and 'S1' in packet.tcp.flags:
                                syn_error_tcp_packets += 1
                        elif 'ICMP' in packet:
                            if hasattr(packet.icmp, 'type') and packet.icmp.type == '3' and hasattr(packet.icmp, 'code') and packet.icmp.code == '1':
                                syn_error_icmp_packets += 1
                    syn_error_rate_tcp = (float)(syn_error_tcp_packets / total_tcp_packets) if total_tcp_packets > 0 else 0
                    syn_error_rate_icmp = (float)(syn_error_icmp_packets / total_icmp_packets) if total_icmp_packets > 0 else 0
                    return syn_error_rate_tcp, syn_error_rate_icmp
                
                syn_error_rate_tcp, syn_error_rate_icmp = calculate_syn_error_rate(total_tcp_packets, 
                                            total_icmp_packets, syn_error_tcp_packets, syn_error_icmp_packets)
                if 'TCP' in packet:
                    serror_rate = syn_error_rate_tcp
                elif 'IP' in packet:
                    serror_rate = syn_error_rate_icmp
                else:
                    serror_rate = 0

        ####    # 27. Rate of packets that have the 'R' (reset) flag set in TCP packets among all packets
                rerror_tcp_packets = 0
                rerror_icmp_packets = 0
                def calculate_rerror_rate(total_tcp_packets, total_icmp_packets, rerror_tcp_packets, rerror_icmp_packets):
                    if hasattr(packet, 'transport_layer'):
                        if packet.transport_layer == 'TCP':
                            if hasattr(packet.tcp, 'flags') and 'R' in packet.tcp.flags:
                                rerror_tcp_packets += 1
                        elif packet.transport_layer == 'ICMP':
                            if hasattr(packet.icmp, 'type') and packet.icmp.type == '3' and hasattr(packet.icmp, 'code') and packet.icmp.code == '3':
                                rerror_icmp_packets += 1
                    rerror_rate_tcp = (rerror_tcp_packets / total_tcp_packets) * 100 if total_tcp_packets > 0 else 0
                    rerror_rate_icmp = (rerror_icmp_packets / total_icmp_packets) * 100 if total_icmp_packets > 0 else 0
                    return rerror_rate_tcp, rerror_rate_icmp
                rerror_rate_tcp, rerror_rate_icmp = calculate_rerror_rate(total_tcp_packets, total_icmp_packets, rerror_tcp_packets, rerror_icmp_packets)
                if 'TCP' in packet:
                    rerror_rate = rerror_rate_tcp
                elif 'IP' in packet:
                    rerror_rate = rerror_rate_icmp
                else:
                    rerror_rate = 0
                
                attack_encoding = {0: 'DoS', 1: 'Probe', 2: 'R2L', 3: 'U2R', 4: 'normal'}
                
                
                if(protocol_type!=-1):
                    packet_array = [duration, protocol_type, service, flag, src_bytes, dst_bytes, urgent, num_failed_logins, serror_rate, rerror_rate]
                    # print('[', duration,',', protocol_type,',', service, ',', flag, ',', src_bytes, ',', dst_bytes, ',', urgent,
                    #     ',', num_failed_logins, ',', serror_rate, ',', rerror_rate,']')
                    n += 1
                    # attack_type = model.predict([packet_array])
                    # packet_array.append(attack_encoding[attack_type[0]])
                    packet_array.append(attack_encoding[model.predict([packet_array])[0]])
                    result_array.append(packet_array)
                    if(n==20):
                        break
            except AttributeError as e:
                pass
        print(result_array)
        return result_array

def processPCAP(request):
    return render(request, 'index.html')

def scanPCAP(request):
    if request.method == 'POST':
        if 'pcap_file' not in request.FILES:
            return HttpResponseBadRequest('No file uploaded!')
        pcap_file = request.FILES.get('pcap_file')

        # Save the uploaded file to a temporary location
        # file_name = ''
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(pcap_file.file.getvalue())
            file_name = temp_file.name

        # Call scanAttacks with the file path
        asyncio.set_event_loop(loop)
        # print("FILE_NAME = "  ,file_name)
        # print("PCAP FILE = " , pcap_file.file.getvalue())
        attack_array = scanAttacks(file_name)
        print(attack_array)

        # Clean up the temporary file
        # os.unlink(pcap_file)
        # print(pcap_file)
        # return HttpResponse(f'<h1>File recieved successfully!</h1><h2>Name of the File: {pcap_file}</h2>')
    return render(request, 'NIDSApp/results1.html', {'packets': attack_array})