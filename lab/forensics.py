"""Restricted, fail-closed decoders for the authored fixture formats.

PCAP support: little-endian microsecond Ethernet/IPv4 captures, unfragmented TCP,
UDP DNS questions without compression. Unsupported formats raise explicit errors.
This is a teaching decoder, not a replacement for Wireshark or an EVTX parser.
"""
import json
import socket
import statistics
import struct
import xml.etree.ElementTree as ET
from datetime import datetime,timezone
from pathlib import Path
from .detections import timestamp
NS={'e':'http://schemas.microsoft.com/win/2004/08/events/event'}

def read_windows(path):
    events=[];ids=set()
    for node in ET.parse(path).getroot().findall('e:Event',NS):
        system=node.find('e:System',NS)
        record=system.findtext('e:EventRecordID',namespaces=NS)
        host=system.findtext('e:Computer',namespaces=NS)
        channel=system.findtext('e:Channel',namespaces=NS)
        key=(host,channel,record)
        if not record or key in ids:raise ValueError('missing or duplicate event record identity')
        ids.add(key)
        when=system.find('e:TimeCreated',NS).get('SystemTime');timestamp(when)
        events.append({'record_id':record,'event_id':int(system.findtext('e:EventID',namespaces=NS)),
                       'timestamp':when,'host':host,'channel':channel,
                       'provider':system.find('e:Provider',NS).get('Name'),
                       'data':{d.get('Name'):d.text or '' for d in node.findall('e:EventData/e:Data',NS)}})
    if not events:raise ValueError('no Windows events found')
    return sorted(events,key=lambda e:(timestamp(e['timestamp']),e['record_id']))

def endpoint_alerts(events):
    alerts=[]
    for e in events:
        d=e['data'];cmd=d.get('CommandLine','').lower()
        if e['event_id']!=1 or e['provider']!='Microsoft-Windows-Sysmon':continue
        if d.get('Image','').lower().split('\\')[-1] not in ('powershell.exe','pwsh.exe'):continue
        if d.get('ParentImage','').lower().split('\\')[-1] not in ('winword.exe','excel.exe','outlook.exe'):continue
        if '-encodedcommand' not in cmd and '-enc ' not in cmd:continue
        guid=d.get('ProcessGuid')
        if not guid:continue
        connections=[c for c in events if c['event_id']==3 and c['provider']=='Microsoft-Windows-Sysmon'
                     and c['host']==e['host'] and c['data'].get('ProcessGuid')==guid
                     and 0<=(timestamp(c['timestamp'])-timestamp(e['timestamp'])).total_seconds()<=300]
        if connections:
            alerts.append({'rule_id':'ENDPOINT-001','severity':'high','host':e['host'],
                           'record_id':e['record_id'],'timestamp':e['timestamp'],
                           'evidence_record_ids':[e['record_id']]+[c['record_id'] for c in connections],
                           'finding':'Office-parent encoded PowerShell with correlated network event',
                           'disposition':'Suspicious; payload intent and compromise unconfirmed'})
    return alerts

def dns_question(payload):
    if len(payload)<12:raise ValueError('truncated DNS header')
    _,flags,questions,_,_,_=struct.unpack('!HHHHHH',payload[:12])
    if flags&0x8000 or questions!=1:return None
    offset=12;labels=[]
    while True:
        if offset>=len(payload):raise ValueError('truncated DNS name')
        size=payload[offset];offset+=1
        if size==0:break
        if size>63:raise ValueError('compressed DNS names are unsupported')
        if offset+size>len(payload):raise ValueError('truncated DNS label')
        labels.append(payload[offset:offset+size].decode('ascii'));offset+=size
    if offset+4>len(payload):raise ValueError('truncated DNS question')
    return '.'.join(labels)

def read_pcap(path):
    raw=Path(path).read_bytes()
    if len(raw)<24:raise ValueError('truncated PCAP header')
    magic,major,minor,_,_,snaplen,link=struct.unpack('<IHHIIII',raw[:24])
    if (magic,major,minor,link)!=(0xa1b2c3d4,2,4,1):raise ValueError('unsupported PCAP format')
    offset=24;packets=[]
    while offset<len(raw):
        if offset+16>len(raw):raise ValueError('truncated record header')
        sec,usec,included,original=struct.unpack('<IIII',raw[offset:offset+16]);offset+=16
        if included>snaplen or included!=original or offset+included>len(raw) or usec>=1000000:
            raise ValueError('truncated or invalid packet record')
        p=raw[offset:offset+included];offset+=included
        if len(p)<34 or p[12:14]!=b'\x08\x00':raise ValueError('unsupported link or IP protocol')
        ip=p[14:];ihl=(ip[0]&15)*4
        total=struct.unpack('!H',ip[2:4])[0]
        if ip[0]>>4!=4 or ihl<20 or total>len(ip) or total<ihl:raise ValueError('invalid IPv4 header')
        if struct.unpack('!H',ip[6:8])[0]&0x3fff:raise ValueError('fragmented IP is unsupported')
        body=ip[ihl:total]
        item={'packet_number':len(packets)+1,'timestamp':datetime.fromtimestamp(sec+usec/1e6,timezone.utc).isoformat(),
              'src_ip':socket.inet_ntoa(ip[12:16]),'dst_ip':socket.inet_ntoa(ip[16:20]),'protocol':ip[9]}
        if ip[9]==6:
            if len(body)<20 or (body[12]>>4)*4<20 or (body[12]>>4)*4>len(body):raise ValueError('invalid TCP header')
            item.update(src_port=struct.unpack('!H',body[:2])[0],dst_port=struct.unpack('!H',body[2:4])[0],tcp_flags=body[13])
        elif ip[9]==17:
            if len(body)<8:raise ValueError('truncated UDP')
            src,dst,length,_=struct.unpack('!HHHH',body[:8])
            if length!=len(body):raise ValueError('invalid UDP length')
            item.update(src_port=src,dst_port=dst)
            if dst==53:item['dns_query']=dns_question(body[8:])
        else:raise ValueError('unsupported transport protocol')
        packets.append(item)
    return packets

def network_findings(packets):
    groups={}
    for p in packets:
        if p.get('tcp_flags')==2:
            groups.setdefault((p['src_ip'],p['dst_ip'],p['dst_port']),[]).append(p)
    findings=[]
    for key,events in sorted(groups.items()):
        events=sorted(events,key=lambda e:timestamp(e['timestamp']))
        gaps=[(timestamp(b['timestamp'])-timestamp(a['timestamp'])).total_seconds() for a,b in zip(events,events[1:])]
        if len(events)<6 or not gaps or min(gaps)<=0:continue
        mean=statistics.mean(gaps);cv=statistics.pstdev(gaps)/mean
        if 30<=statistics.median(gaps)<=300 and cv<=0.1:
            findings.append({'rule_id':'NET-001','src_ip':key[0],'dst_ip':key[1],'dst_port':key[2],
                             'syn_attempts':len(events),'median_interval_seconds':statistics.median(gaps),
                             'interval_cv':round(cv,6),'evidence_packet_numbers':[e['packet_number'] for e in events],
                             'finding':'Periodic outbound TCP SYN attempts; connection establishment and C2 unproven'})
    return findings
