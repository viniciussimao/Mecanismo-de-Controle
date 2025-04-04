#!/usr/bin/env python3

import argparse
import sys
import socket
import psutil
import struct
import subprocess
import re
import time
from time import sleep
from scapy.all import Packet, bind_layers, BitField, Ether, IP, sendp, get_if_hwaddr, ShortField, LongField, PacketListField, ByteField

# Define o novo cabeçalho HostINT
class HostINT(Packet):
    name = "HostINT"
    fields_desc = [
        BitField("cpu_usage", 0, 32),        # Porcentagem de uso de CPU
        BitField("mem_usage", 0, 32),        # Porcentagem de uso de memória
#        BitField("battery", 100, 32),        # Percentual de bateria
#        BitField("rssi", 0, 32),             # RSSI (32 bits)
        BitField("timestamp", 0, 48),        # Timestamp (48 bits)
        BitField("bind", 253, 8)          # Campo proto para indicar o próximo protocolo
    ]

class InBandNetworkTelemetry(Packet):
    fields_desc = [ BitField("switchID_t", 0, 31),
                    BitField("ingress_port",0, 9),
                    BitField("egress_port",0, 9),
                    BitField("egress_spec", 0, 9),
                    BitField("ingress_global_timestamp", 0, 48),
                    BitField("egress_global_timestamp", 0, 48),
                    BitField("enq_timestamp",0, 32),
                    BitField("enq_qdepth",0, 19),
                    BitField("deq_timedelta", 0, 32),
                    BitField("deq_qdepth", 0, 19)
                  ]

    def extract_padding(self, p):
        return "", p

class nodeCount(Packet):
    name = "nodeCount"
    fields_desc = [
        ShortField("count", 0),
        PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))
    ]

'''
def get_rssi_iwconfig(interface):
    try:
        # Execute o comando iwconfig
        result = subprocess.check_output(['iwconfig', interface], encoding='utf-8')

        # Procura pela linha que contém "Signal level"
        rssi_search = re.search(r'Signal level=(-\d+) dBm', result)
        if rssi_search:
            rssi = int(rssi_search.group(1))
            return rssi
        else:
            raise Exception("RSSI não encontrado.")
    except subprocess.CalledProcessError:
        raise Exception("Erro ao executar iwconfig. Verifique se o comando está instalado e a interface está correta.")
'''

def get_system_data(interface):
    # Coleta as informações do sistema
    cpu_usage = int(psutil.cpu_percent())
    mem_usage = int(psutil.virtual_memory().percent)
#    battery = psutil.sensors_battery().percent if psutil.sensors_battery() else 100

    # Obtém o RSSI da interface de rede
    #rssi = get_rssi_iwconfig(interface)
#    rssi = 30

    # Obtém o timestamp atual em microssegundos e ajusta para 32 bits
    timestamp = int(time.time() * 1e6)

    return cpu_usage, mem_usage, timestamp

def main():
    addr = socket.gethostbyname(sys.argv[1])
    iface = 'ens36'  

    bind_layers(IP, HostINT, proto=254)
    bind_layers(HostINT, nodeCount)

    while True:
        cpu_usage, mem_usage, timestamp = get_system_data(iface)

        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
            dst=addr, proto=254) / HostINT(
            cpu_usage=cpu_usage,
            mem_usage=mem_usage,
#            battery=battery,
#            rssi=rssi,
            timestamp=timestamp,
            bind=253
        ) / nodeCount(count=0, INT=[])

        sendp(pkt, iface=iface)
        pkt.show2()
        sleep(0.2)

    '''
    cpu_usage, mem_usage, battery, rssi, timestamp = get_system_data(iface)

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
        dst=addr, proto=254) / HostINT(
        cpu_usage=cpu_usage,
        mem_usage=mem_usage,
        battery=battery,
        rssi=rssi,
        timestamp=timestamp,
        bind=253
    ) / nodeCount(count=0, INT=[])

    sendp(pkt, iface=iface)
    pkt.show2()
    '''
if __name__ == '__main__':
    main()
