"""Independent PCAP decode/checksum verification using dpkt 1.9.8.

Run: python -m pip install -r requirements-verification.txt
     python -m lab.verify_pcap
"""
import json
import hashlib
import socket
import struct
from pathlib import Path
import dpkt
ROOT=Path(__file__).resolve().parents[1]

def verify(path):
    rows=[];dns=[]
    with Path(path).open('rb') as f:
        for when,raw in dpkt.pcap.Reader(f):
            eth=dpkt.ethernet.Ethernet(raw);ip=eth.data
            if not isinstance(ip,dpkt.ip.IP):raise ValueError('expected IPv4')
            header=raw[14:14+ip.hl*4]
            if dpkt.in_cksum(header)!=0:raise ValueError('invalid IP checksum')
            if isinstance(ip.data,dpkt.tcp.TCP):
                tcp=ip.data
                segment=raw[14+ip.hl*4:14+ip.len]
                pseudo=ip.src+ip.dst+struct.pack('!BBH',0,6,len(segment))
                if dpkt.in_cksum(pseudo+segment)!=0:raise ValueError('invalid TCP checksum')
                row={'protocol':6,'src_port':tcp.sport,'dst_port':tcp.dport,'tcp_flags':tcp.flags}
            elif isinstance(ip.data,dpkt.udp.UDP):
                udp=ip.data;row={'protocol':17,'src_port':udp.sport,'dst_port':udp.dport}
                if udp.dport==53:
                    question=dpkt.dns.DNS(udp.data).qd[0].name;dns.append(question);row['dns_query']=question
            else:raise ValueError('unexpected transport')
            row.update(src_ip=socket.inet_ntoa(ip.src),dst_ip=socket.inet_ntoa(ip.dst))
            rows.append(row)
    return {'decoder':'dpkt','version':dpkt.__version__,'packet_count':len(rows),
            'ip_checksums_valid':True,'tcp_checksums_valid':True,'dns_queries':dns,'packets':rows}

def main():
    from .forensics import read_pcap
    p=ROOT/'lab/fixtures/network/traffic.pcap'
    result=verify(p);local=read_pcap(p)
    result['source_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
    if len(local)!=result['packet_count']:raise AssertionError('packet counts disagree')
    for authored,independent in zip(local,result['packets']):
        for key,value in independent.items():
            if authored.get(key)!=value:raise AssertionError(f'decoders disagree: {key}')
    output=ROOT/'evidence/network/independent_verification.json'
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(f"PASS: independently decoded {len(local)} packets; IP/TCP checksums valid")

if __name__=='__main__':main()
