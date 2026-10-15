import importlib.util
import ipaddress
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'System & Automation'

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
mgr=load('allowlist',BASE/'python/ip_allowlist_manager.py')
parser=load('parser',BASE/'python/security_log_parser.py')

class AllowlistTests(unittest.TestCase):
    def setUp(self): self.networks=[ipaddress.ip_network('192.0.2.0/24')]
    def test_classification(self):
        result=mgr.evaluate_allowlist(['192.0.2.1','192.0.2.1','203.0.113.1','bad'],self.networks)
        self.assertEqual(result,{'approved':['192.0.2.1'],'duplicates':['192.0.2.1'],'unauthorized':['203.0.113.1'],'invalid':['bad']})
    def test_ipv6_rejected(self):
        self.assertEqual(mgr.evaluate_allowlist(['::1'],self.networks)['invalid'],['::1'])
    def test_empty_input(self): self.assertEqual(mgr.evaluate_allowlist([],self.networks)['approved'],[])
    def test_numeric_sort(self):
        self.assertEqual(mgr.evaluate_allowlist(['192.0.2.10','192.0.2.2'],self.networks)['approved'],['192.0.2.2','192.0.2.10'])
    def test_network_boundaries_are_members(self):
        self.assertEqual(len(mgr.evaluate_allowlist(['192.0.2.0','192.0.2.255'],self.networks)['approved']),2)
    def test_malformed_network(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'nets';p.write_text('invalid')
            with self.assertRaises(ValueError): mgr.load_networks(p)
    def test_ipv6_network(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'nets';p.write_text('::/0')
            with self.assertRaises(ValueError): mgr.load_networks(p)
    def test_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'nets';p.write_text('# example\n\n192.0.2.0/24\n')
            self.assertEqual(mgr.load_networks(p),self.networks)
    def cli(self,d,extra=None,network='192.0.2.0/24'):
        d=Path(d);(d/'input').write_text('192.0.2.1\n203.0.113.1\n');(d/'net').write_text(network)
        command=[sys.executable,str(BASE/'python/ip_allowlist_manager.py'),'--allowlist',str(d/'input'),
                 '--networks',str(d/'net'),'--output',str(d/'out'),'--summary',str(d/'summary'),'--log',str(d/'log')]
        return subprocess.run(command+(extra or []),capture_output=True,text=True)
    def test_dry_run_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'out';p.write_text('preserve')
            r=self.cli(d,['--dry-run'])
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(p.read_text(),'preserve')
            self.assertTrue(json.loads((Path(d)/'summary').read_text())['dry_run'])
    def test_write_output(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.cli(d);self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual((Path(d)/'out').read_text(),'192.0.2.1\n')
    def test_no_input_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.cli(d,['--output',str(Path(d)/'input')]);self.assertNotEqual(r.returncode,0)
            self.assertEqual((Path(d)/'input').read_text(),'192.0.2.1\n203.0.113.1\n')
    def test_empty_network_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.cli(d,network='');self.assertNotEqual(r.returncode,0)
            self.assertFalse((Path(d)/'out').exists())

class ParserTests(unittest.TestCase):
    def test_legacy_dataset_accepted(self):
        events=parser.load_events(BASE/'data/auth_events_for_parser.csv')
        self.assertTrue(events);self.assertTrue(all(e['timestamp'].endswith('+00:00') for e in events))
    def test_invalid_csv_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.csv';p.write_text('wrong\nvalue\n')
            r=subprocess.run([sys.executable,str(BASE/'python/security_log_parser.py'),'--input',str(p),'--output',str(Path(d)/'out')],capture_output=True,text=True)
            self.assertEqual(r.returncode,2);self.assertNotIn('Traceback',r.stderr)
            self.assertFalse((Path(d)/'out').exists())
    def test_parser_matches_canonical_fixture(self):
        self.assertEqual(len(parser.detect(parser.load_events(ROOT/'lab/auth_events.csv'))),4)
