import copy
import struct
import tempfile
import unittest
from pathlib import Path
from lab.forensics import read_windows,endpoint_alerts,read_pcap,network_findings,dns_question
ROOT=Path(__file__).resolve().parents[1]
XML=ROOT/'lab/fixtures/endpoint/windows_events.xml'
PCAP=ROOT/'lab/fixtures/network/traffic.pcap'

class EndpointTests(unittest.TestCase):
    def setUp(self):self.events=read_windows(XML)
    def test_exact_chain(self):
        alerts=endpoint_alerts(self.events)
        self.assertEqual(len(alerts),1);self.assertEqual(alerts[0]['evidence_record_ids'],['102','103'])
    def test_service_script_is_negative(self):
        self.assertEqual(endpoint_alerts([e for e in self.events if e['record_id'] in ('201','202')]),[])
    def test_no_network_no_correlated_alert(self):
        self.assertEqual(endpoint_alerts([e for e in self.events if e['record_id']!='103']),[])
    def test_wrong_process_guid(self):
        self.events[2]['data']['ProcessGuid']='other'
        self.assertEqual(endpoint_alerts(self.events),[])
    def test_wrong_host(self):
        self.events[2]['host']='OTHER'
        self.assertEqual(endpoint_alerts(self.events),[])
    def test_network_before_process(self):
        self.events[2]['timestamp']='2026-10-01T11:59:59Z'
        self.assertEqual(endpoint_alerts(self.events),[])
    def test_expired_network(self):
        self.events[2]['timestamp']='2026-10-01T12:05:01Z'
        self.assertEqual(endpoint_alerts(self.events),[])
    def test_network_boundary(self):
        self.events[2]['timestamp']='2026-10-01T12:05:00Z'
        self.assertEqual(len(endpoint_alerts(self.events)),1)
    def test_missing_encoded_flag(self):
        self.events[1]['data']['CommandLine']='powershell.exe -File inventory.ps1'
        self.assertEqual(endpoint_alerts(self.events),[])
    def test_missing_guid(self):
        del self.events[1]['data']['ProcessGuid']
        self.assertEqual(endpoint_alerts(self.events),[])
    def test_duplicate_identity_rejected(self):
        import xml.etree.ElementTree as ET
        tree=ET.parse(XML);tree.getroot().append(copy.deepcopy(tree.getroot()[0]))
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'events.xml';tree.write(p)
            with self.assertRaises(ValueError):read_windows(p)

class PacketTests(unittest.TestCase):
    def setUp(self):self.packets=read_pcap(PCAP)
    def test_exact_packet_count(self):self.assertEqual(len(self.packets),13)
    def test_dns_name(self):self.assertEqual(self.packets[0]['dns_query'],'telemetry.lab.example')
    def test_periodicity(self):
        findings=network_findings(self.packets)
        self.assertEqual(len(findings),1)
        self.assertEqual(findings[0]['dst_ip'],'203.0.113.50')
        self.assertEqual(findings[0]['median_interval_seconds'],60)
    def test_irregular_background_negative(self):
        self.assertEqual(network_findings([p for p in self.packets if p['src_ip']=='192.0.2.20']),[])
    def test_five_attempts_insufficient(self):
        packets=[p for p in self.packets if p['dst_ip']=='203.0.113.50'][:5]
        self.assertEqual(network_findings(packets),[])
    def test_ack_not_connection_attempt(self):
        for p in self.packets:
            if 'tcp_flags' in p:p['tcp_flags']=16
        self.assertEqual(network_findings(self.packets),[])
    def parse_bytes(self,data):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'test.pcap';p.write_bytes(data);return read_pcap(p)
    def test_truncated_capture(self):
        with self.assertRaises(ValueError):self.parse_bytes(PCAP.read_bytes()[:-1])
    def test_bad_magic(self):
        data=bytearray(PCAP.read_bytes());data[0]=0
        with self.assertRaises(ValueError):self.parse_bytes(data)
    def test_truncated_global_header(self):
        with self.assertRaises(ValueError):self.parse_bytes(b'123')
    def test_dns_truncation(self):
        with self.assertRaises(ValueError):dns_question(b'123')
    def test_compressed_dns_is_explicitly_unsupported(self):
        with self.assertRaises(ValueError):dns_question(struct.pack('!HHHHHH',1,0,1,0,0,0)+b'\xc0\x0c')
    def test_fragmented_packet_rejected(self):
        data=bytearray(PCAP.read_bytes());data[24+16+14+6]=0x20
        with self.assertRaises(ValueError):self.parse_bytes(data)
