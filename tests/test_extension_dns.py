"""Offline regressions for node DNS, upstream hooks and local extension layout."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'subscribe'))
from extensions import node_dns as nd


def node(name='台湾 001', host='edge.airport.example', **kw):
    return {'name': name, 'server': host, 'port': 443, 'type': 'trojan', 'password': 'dummy', **kw}


def with_hint(n, *values, kind='dns'):
    return dict(n, **{nd.KEY: {'host': n['server'], 'kind': kind, 'values': list(values)}})


class NodeDNSTests(unittest.TestCase):
    def setUp(self):
        p = patch.dict(os.environ, {"AGGREGATOR_ALLOW_TOKENIZED_DNS": "0"})
        p.start(); self.addCleanup(p.stop)

    def test_tokenized_dns_opt_in_and_no_unsafe_schemes(self):
        url = "https://dns.example:8443/dns-query/dummy-token?key=abc%2F123&mode=1"
        self.assertFalse(nd.resolver(url))
        with patch.dict(os.environ, {"AGGREGATOR_ALLOW_TOKENIZED_DNS": "true"}):
            self.assertEqual(nd.resolver(url), url)
            for bad in ["https://user:pass@dns.example/dns-query", "https://127.0.0.1/secret", "https://dns.example/dns-query#PROXY", "https://dns.example/dns-query?x=a,b", "https://dns.example/dns-query?x=a\nb"]:
                self.assertFalse(nd.resolver(bad))
            n = node()
            nd.attach_from_source("[Host]\nedge.airport.example = server:" + url, [n])
            self.assertEqual(nd.metadata(n)["values"], [url])
        self.assertIsNone(nd.metadata(n))

    def test_mask_only_in_actions(self):
        token = 'https://dns.example/dns-query/sampletoken123?key=samplekey123'
        with patch.dict(os.environ, {'AGGREGATOR_ALLOW_TOKENIZED_DNS': 'true', 'GITHUB_ACTIONS': 'false'}):
            with patch('builtins.print') as out:
                nd.mask_credentials([with_hint(node(), token)])
                out.assert_not_called()
        with patch.dict(os.environ, {'AGGREGATOR_ALLOW_TOKENIZED_DNS': 'true', 'GITHUB_ACTIONS': 'true'}):
            with patch('builtins.print') as out:
                nd.mask_credentials([with_hint(node(), token)])
                self.assertTrue(any(c.args[0] == '::add-mask::' + token for c in out.call_args_list))
                self.assertTrue(all(c.args[0].startswith('::add-mask::') for c in out.call_args_list))

    def test_surge_first_match(self):
        n = node()
        nd.attach_from_source("[Host]\n*.airport.example = server:1.1.1.1\nedge.airport.example = 8.8.8.8\n", [n])
        self.assertEqual(nd.metadata(n)["values"], ["1.1.1.1"])

    def test_clash_exact_wildcard_and_only_source_nodes(self):
        text = '''proxies: []
hosts:
  edge.airport.example: 8.8.8.8
  unrelated.example: 9.9.9.9
dns:
  proxy-server-nameserver-policy:
    '+.airport.example': https://dns.airport.example/dns-query
    other.example: [1.1.1.1, 8.8.4.4]
  nameserver: [114.114.114.114]
  nameserver-policy:
    '+.unrelated.example': 1.0.0.1
'''
        nodes = [node(), node('B', 'other.airport.example'), node('C','other.example'), node('D','normal.example'), node('E','1.1.1.1')]
        nd.attach_from_source(text,nodes)
        self.assertEqual(nd.metadata(nodes[0])['values'], ['8.8.8.8'])
        self.assertEqual(nd.metadata(nodes[0])['kind'], 'ip')
        self.assertEqual(nd.metadata(nodes[1])['values'], ['https://dns.airport.example/dns-query'])
        self.assertEqual(nd.metadata(nodes[2])['values'], ['1.1.1.1','8.8.4.4'])
        self.assertNotIn(nd.KEY,nodes[3]); self.assertNotIn(nd.KEY,nodes[4])
        self.assertNotIn('unrelated.example',nd.mappings(nodes))

    def test_surge_exact_and_wildcard(self):
        text = '''[Host]
edge.airport.example = 1.1.1.1
*.airport.example = server:https://dns.example/dns-query, 9.9.9.9
unrelated.example = server:8.8.8.8
[Rule]
FINAL,DIRECT
'''
        nodes=[node(),node('B','tw.airport.example'),node('C','normal.example')]
        nd.attach_from_source(text,nodes)
        self.assertEqual(nd.metadata(nodes[0])['kind'],'ip')
        self.assertEqual(nd.metadata(nodes[1])['values'],['9.9.9.9','https://dns.example/dns-query'])
        self.assertNotIn(nd.KEY,nodes[2])

    def test_untrusted_or_private_values_are_not_retained(self):
        for value in ['https://dns.example/secret-token','https://dns.example/dns-query?token=123',
                      'https://user:pass@dns.example/dns-query','https://127.0.0.1/dns-query',
                      'https://169.254.169.254/dns-query','https://192.168.0.1/dns-query',
                      'https://dns.example/dns-query#PROXY','https://localhost/dns-query',
                      'script:evil','system','10.0.0.1','100.64.0.1','224.0.0.1','udp://127.0.0.1']:
            with self.subTest(value=value): self.assertFalse(nd.resolver(value))
        original=with_hint(node(),'https://dns.example/dns-query')
        nd.attach_from_source('ss://abcdef',[original]); self.assertNotIn(nd.KEY,original)
        nd.attach_from_source('dns:\n  proxy-server-nameserver-policy:\n    edge.airport.example: https://dns.example/private-token\n',[original])
        self.assertNotIn(nd.KEY,original)

    def test_only_explicit_proxy_default_is_inherited(self):
        n=node()
        nd.attach_from_source('dns:\n  nameserver: [1.1.1.1]\n',[n]);self.assertNotIn(nd.KEY,n)
        nd.attach_from_source('dns:\n  proxy-server-nameserver: [1.1.1.1]\n',[n]);self.assertEqual(nd.metadata(n)['values'],['1.1.1.1'])
        nd.attach_from_source('dns:\n  enable: false\n  proxy-server-nameserver: [1.1.1.1]\n',[n]);self.assertNotIn(nd.KEY,n)

    def test_fresh_conflict_and_history(self):
        a=with_hint(node(),'1.1.1.1'); b=with_hint(node('B'),'8.8.8.8')
        fresh,old=nd.reconcile_sources([a,b],[a]); self.assertFalse(nd.mappings(fresh+old))
        fresh,old=nd.reconcile_sources([b],[a]); self.assertEqual(nd.metadata(old[0])['values'],['8.8.8.8'])
        fresh,old=nd.reconcile_sources([node()],[a]); self.assertEqual(nd.metadata(fresh[0])['values'],['1.1.1.1'])
        self.assertEqual(nd.metadata(a)['values'],['1.1.1.1'])
        a=with_hint(node(),'https://edge.airport.example/dns-query');self.assertFalse(nd.mappings([a]))

    def test_mihomo_config_no_global_override(self):
        a=with_hint(node(),'1.1.1.1');b=with_hint(node('B','fixed.example'),'8.8.8.8',kind='ip')
        cfg={'dns':{'enable':True,'nameserver':['8.8.4.4'],'proxy-server-nameserver':['223.5.5.5']},'proxies':[]}
        nd.apply_mihomo(cfg,[a,b]); self.assertEqual(cfg['dns']['proxy-server-nameserver'],['223.5.5.5'])
        self.assertEqual(cfg['dns']['nameserver'],['8.8.4.4'])
        self.assertEqual(cfg['dns']['proxy-server-nameserver-policy'],{'edge.airport.example':['1.1.1.1']})
        self.assertEqual(cfg['hosts'],{'fixed.example':['8.8.8.8']})
        cfg={};nd.apply_mihomo(cfg,[node()]);self.assertEqual(cfg,{})
        cfg={};nd.apply_mihomo(cfg,[a]);self.assertTrue(cfg['dns']['proxy-server-nameserver'])
        self.assertNotIn(nd.KEY,nd.clean_nodes([a])[0]); self.assertIn(nd.KEY,a)

    def test_actual_output_only_retained_nodes(self):
        a=with_hint(node(),'1.1.1.1');b=with_hint(node('B','fixed.example'),'8.8.8.8',kind='ip');c=with_hint(node('C','discard.example'),'9.9.9.9')
        doc={'dns':{'nameserver':['223.5.5.5']},'proxies':nd.clean_nodes([a,b]),'proxy-groups':[],'rules':['MATCH,DIRECT']}
        profile=yaml.safe_dump(doc,allow_unicode=True,sort_keys=False)
        generated=yaml.safe_load(nd.apply_clash_profile(profile,[a,b,c]));self.assertEqual(generated['proxies'],doc['proxies']);self.assertEqual(generated['rules'],doc['rules'])
        self.assertEqual(generated['dns']['proxy-server-nameserver-policy'],{'edge.airport.example':['1.1.1.1']})
        self.assertEqual(generated['hosts'],{'fixed.example':['8.8.8.8']})
        surge='[General]\nloglevel = notify\n[Proxy]\n台湾 001 = trojan, edge.airport.example, 443, password=dummy\nB = trojan, fixed.example, 443, password=dummy\n[Rule]\nFINAL,DIRECT\n'
        rendered=nd.apply_surge_profile(surge,[a,b,c]);self.assertIn('[Host]\n',rendered)
        self.assertIn('edge.airport.example = server:1.1.1.1',rendered);self.assertIn('fixed.example = 8.8.8.8',rendered)
        self.assertNotIn('discard.example',rendered);self.assertIn('FINAL,DIRECT',rendered)
        self.assertEqual(nd.apply_surge_profile(rendered,[a,b,c]),rendered)
        module=nd.surge_dns_module(rendered,[a,b,c])
        self.assertIn('edge.airport.example = server:1.1.1.1',module)
        self.assertIn('fixed.example = 8.8.8.8',module)
        self.assertNotIn('discard.example',module);self.assertNotIn('[Proxy]',module)
        self.assertNotIn('edge.airport.example',nd.surge_dns_module(rendered,[]))
        self.assertEqual(nd.apply_clash_profile(profile,[node()]),profile)


class IntegrationTests(unittest.TestCase):
    def test_snapshot_preserves_valid_hint_not_private_fields(self):
        from verified_nodes import merge_candidates, snapshot_content
        a=with_hint(node(),'1.1.1.1');a['sub']='private';a['_other']='secret'
        obj=json.loads(snapshot_content([a]));rec=obj['nodes'][0]
        self.assertEqual(nd.metadata(rec)['values'],['1.1.1.1']);self.assertNotIn('sub',rec);self.assertNotIn('_other',rec)
        merged,_=merge_candidates([node()],[rec]);self.assertEqual(nd.metadata(merged[0])['values'],['1.1.1.1'])
        self.assertEqual(len(merged),1)

    def test_legacy_module_is_same_implementation(self):
        import profile_layout, extensions.profile_layout, verified_nodes, extensions.verified_nodes
        self.assertIs(profile_layout,extensions.profile_layout);self.assertIs(verified_nodes,extensions.verified_nodes)
        from surge_provider import proxy_lines_only
        source='[Proxy]\nA = trojan, edge.airport.example, 443, password=dummy\n[Host]\nedge.airport.example = server:1.1.1.1\n'
        self.assertEqual(proxy_lines_only(source),'A = trojan, edge.airport.example, 443, password=dummy\n')

    def test_surge_three_artifacts_publish_atomically(self):
        from output_publish import publication_groups
        records={'surge.conf':'full','surge-proxy.conf':'pure','surge-node-dns.sgmodule':'dns'}
        self.assertEqual(publication_groups([('surge','surge.conf','surge')],records),[('surge',list(records))])

    def test_geo_rename_retains_dns(self):
        import types
        from geo_labels import label_verified_nodes
        a=with_hint(node(),'1.1.1.1')
        def batch_query(proxies, **kwargs):
            return [types.SimpleNamespace(proxy=n,success=True,result=types.SimpleNamespace(country='台湾',is_cdn=False)) for n in proxies]
        fake=types.SimpleNamespace(ISO_TO_CHINESE={'TW':'台湾'},batch_query=batch_query,locate_by_ipinfo=lambda x:x)
        with patch.dict(sys.modules,{'location':fake}):
            nodes,_=label_verified_nodes([a])
        self.assertEqual(nd.metadata(nodes[0])['values'],['1.1.1.1'])
        self.assertEqual(nodes[0]['name'],'🇹🇼 台湾 001')

    def test_decode_capture_only_when_enabled(self):
        from airport import AirPort
        source='''proxies:
  - {name: A, type: trojan, server: edge.airport.example, port: 443, password: dummy}
dns:
  proxy-server-nameserver-policy:
    edge.airport.example: 1.1.1.1
'''
        with patch.dict(os.environ,{'AGGREGATOR_CAPTURE_NODE_DNS':'1'}):
            nodes=AirPort.decode(source,'',use_subconverter=False,do_verify=False)
        self.assertEqual(nd.metadata(nodes[0])['values'],['1.1.1.1'])
        with patch.dict(os.environ,{'AGGREGATOR_CAPTURE_NODE_DNS':'0'}):
            nodes=AirPort.decode(source,'',use_subconverter=False,do_verify=False)
        self.assertNotIn(nd.KEY,nodes[0])

    def test_liveness_and_geo_actual_configuration(self):
        from clash import generate_config
        from location import generate_mihomo_config
        a=with_hint(node(),'1.1.1.1')
        with tempfile.TemporaryDirectory() as d:
            result=generate_config(d,[a], 'test.yaml')
            doc=yaml.safe_load((Path(d)/'test.yaml').read_text('utf-8'))
            self.assertEqual(doc['dns']['proxy-server-nameserver-policy'],{'edge.airport.example':['1.1.1.1']})
            self.assertNotIn(nd.KEY,doc['proxies'][0]);self.assertIn(nd.KEY,result[0])
        cfg,records=generate_mihomo_config([a],[18081],18080)
        self.assertEqual(cfg['dns']['proxy-server-nameserver-policy'],{'edge.airport.example':['1.1.1.1']})
        self.assertNotIn(nd.KEY,cfg['proxies'][0]);self.assertEqual(records[a['name']],18081)

    def test_merge_contract_wiring(self):
        collect=(ROOT/'subscribe/collect.py').read_text('utf-8')
        self.assertLess(collect.index('AGGREGATOR_CAPTURE_NODE_DNS'),collect.index('pipeline.execute_tasks(tasks)'))
        self.assertLess(collect.index('merge_candidates(proxies, previous)'),collect.index('clash.generate_config(workspace'))
        for term in ('snapshot_content(nodes)','clean_nodes(nodes)','apply_clash_profile(updated, nodes)','apply_surge_profile(updated, nodes)'):
            self.assertIn(term,collect)
        weekly=(ROOT/'.github/workflows/collect.yaml').read_text('utf-8')
        self.assertIn('subscribe/extensions',weekly);self.assertIn('tests/test_extension_dns.py',weekly)
        self.assertIn('git diff --name-only --diff-filter=U',weekly);self.assertIn('unittest discover -s tests',weekly)
        self.assertIn('git merge --abort',weekly)
        self.assertIn('git push origin HEAD:main',weekly)
        refresh=(ROOT/'.github/workflows/refresh.yaml').read_text('utf-8')
        self.assertIn('AGGREGATOR_ALLOW_TOKENIZED_DNS: ${{ vars.AGGREGATOR_ALLOW_TOKENIZED_DNS }}',refresh)

if __name__=='__main__': unittest.main()
