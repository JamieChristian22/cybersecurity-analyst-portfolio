"""Construct inert synthetic Windows event XML and Ethernet PCAP fixtures.

No processes are launched and no packets are transmitted. All bytes are authored locally.
"""
import json
import socket
import struct
import xml.etree.ElementTree as ET
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NS='http://schemas.microsoft.com/win/2004/08/events/event'
ET.register_namespace('',NS)

def checksum(data):
    if len(data)%2:data+=b'\x00'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16:total=(total&0xffff)+(total>>16)
    return (~total)&0xffff

def ipv4(payload,proto,src,dst,ident):
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),ident,0,64,proto,0,socket.inet_aton(src),socket.inet_aton(dst))
    header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
    return bytes.fromhex('0200000000020200000000010800')+header+payload

def syn(src,dst,sport,ident):
    segment=struct.pack('!HHIIBBHHH',sport,443,1000+ident,0,0x50,0x02,64240,0,0)
    pseudo=socket.inet_aton(src)+socket.inet_aton(dst)+struct.pack('!BBH',0,6,len(segment))
    check=checksum(pseudo+segment)
    segment=segment[:16]+struct.pack('!H',check)+segment[18:]
    return ipv4(segment,6,src,dst,ident)

def dns(src,dst):
    name=b''.join(bytes([len(label)])+label.encode() for label in 'telemetry.lab.example'.split('.'))+b'\x00'
    payload=struct.pack('!HHHHHH',1,0x0100,1,0,0,0)+name+struct.pack('!HH',1,1)
    udp=struct.pack('!HHHH',53000,53,8+len(payload),0)+payload
    return ipv4(udp,17,src,dst,1)

def windows_event(record,event_id,when,data,provider='Microsoft-Windows-Sysmon',channel='Microsoft-Windows-Sysmon/Operational'):
    node=ET.Element('{'+NS+'}Event');system=ET.SubElement(node,'{'+NS+'}System')
    ET.SubElement(system,'{'+NS+'}Provider',Name=provider)
    for name,value in [('EventID',event_id),('EventRecordID',record),('Channel',channel),('Computer','LAB-WS01')]:
        ET.SubElement(system,'{'+NS+'}'+name).text=str(value)
    ET.SubElement(system,'{'+NS+'}TimeCreated',SystemTime=when)
    payload=ET.SubElement(node,'{'+NS+'}EventData')
    for key,value in data.items():ET.SubElement(payload,'{'+NS+'}Data',Name=key).text=str(value)
    return node

def build():
    folder=ROOT/'lab/fixtures'
    parent='{00000000-0000-0000-0000-000000000101}'
    child='{00000000-0000-0000-0000-000000000102}'
    benign='{00000000-0000-0000-0000-000000000201}'
    records=[
        windows_event(101,1,'2026-10-01T11:59:50Z',{'ProcessGuid':parent,'Image':r'C:\Program Files\Microsoft Office\WINWORD.EXE','User':r'LAB\alex','ParentImage':r'C:\Windows\explorer.exe','CommandLine':'WINWORD.EXE lab-document.docx'}),
        windows_event(102,1,'2026-10-01T12:00:00Z',{'ProcessGuid':child,'ParentProcessGuid':parent,'Image':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','ParentImage':r'C:\Program Files\Microsoft Office\WINWORD.EXE','User':r'LAB\alex','CommandLine':'powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEwAQQBCACcA'}),
        windows_event(103,3,'2026-10-01T12:00:01Z',{'ProcessGuid':child,'Image':'powershell.exe','User':r'LAB\alex','SourceIp':'192.0.2.10','DestinationIp':'203.0.113.50','DestinationPort':'443','Protocol':'tcp','Initiated':'true'}),
        windows_event(104,106,'2026-10-01T12:06:00Z',{'TaskName':r'\LabTelemetry','UserContext':r'LAB\alex'},'Microsoft-Windows-TaskScheduler','Microsoft-Windows-TaskScheduler/Operational'),
        windows_event(201,1,'2026-10-01T13:00:00Z',{'ProcessGuid':benign,'Image':'powershell.exe','ParentImage':r'C:\Windows\System32\services.exe','User':r'LAB\svc-maintenance','CommandLine':'powershell.exe -File C:\\Lab\\inventory.ps1'}),
        windows_event(202,3,'2026-10-01T13:00:01Z',{'ProcessGuid':benign,'Image':'powershell.exe','User':r'LAB\svc-maintenance','SourceIp':'192.0.2.10','DestinationIp':'198.51.100.60','DestinationPort':'443','Protocol':'tcp','Initiated':'true'})]
    root=ET.Element('Events')
    for r in records:root.append(r)
    ET.indent(root)
    ET.ElementTree(root).write(folder/'endpoint/windows_events.xml',encoding='utf-8',xml_declaration=True)
    start=int(datetime(2026,10,1,12,tzinfo=timezone.utc).timestamp())
    packets=[(start-2,dns('192.0.2.10','192.0.2.53'))]
    packets += [(start+i*60,syn('192.0.2.10','203.0.113.50',50000+i,i+2)) for i in range(6)]
    packets += [(start+t,syn('192.0.2.20','198.51.100.60',51000+i,i+20)) for i,t in enumerate([12,39,97,181,240,390])]
    packets.sort(key=lambda p:p[0])
    with (folder/'network/traffic.pcap').open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for seconds,packet in packets:f.write(struct.pack('<IIII',seconds,0,len(packet),len(packet))+packet)
    expected={'endpoint_alert_record':'102','endpoint_supporting_records':['102','103'],
              'task_record_for_context':'104','packets':13,'dns_queries':['telemetry.lab.example'],
              'periodic_source':'192.0.2.10','periodic_destination':'203.0.113.50','syn_attempts':6,'interval_seconds':60}
    (folder/'forensics_expected.json').write_text(json.dumps(expected,indent=2)+'\n')
    print('Created 6 synthetic Windows events and 13 inert packet records')

if __name__=='__main__':build()
