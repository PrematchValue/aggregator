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
        nd.attach_from_source("[Host]\n*.airport.example = server:https://resolver-a.example/dns-query\nedge.airport.example = 8.8.8.8\n", [n])
        self.assertEqual(nd.metadata(n)["values"], ["https://resolver-a.example/dns-query"])

    def test_clash_exact_wildcard_and_only_source_nodes(self):
        text = '''proxies: []
hosts:
  edge.airport.example: 8.8.8.8
  unrelated.example: 9.9.9.9
dns:
  proxy-server-nameserver-policy:
    '+.airport.example': https://dns.airport.example/dns-query
    other.example: [https://resolver-a.example/dns-query, https://resolver-b.example/dns-query]
  nameserver: [114.114.114.114]
  nameserver-policy:
    '+.unrelated.example': 1.0.0.1
'''
        nodes = [node(), node('B', 'other.airport.example'), node('C','other.example'), node('D','normal.example'), node('E','1.1.1.1')]
        nd.attach_from_source(text,nodes)
        self.assertEqual(nd.metadata(nodes[0])['values'], ['8.8.8.8'])
        self.assertEqual(nd.metadata(nodes[0])['kind'], 'ip')
        self.assertEqual(nd.metadata(nodes[1])['values'], ['https://dns.airport.example/dns-query'])
        self.assertEqual(nd.metadata(nodes[2])['values'], ['https://resolver-a.example/dns-query', 'https://resolver-b.example/dns-query'])
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
        self.assertEqual(nd.metadata(nodes[1])['values'],['https://dns.example/dns-query'])
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
        nd.attach_from_source('dns:\n  proxy-server-nameserver: [1.1.1.1]\n',[n]);self.assertNotIn(nd.KEY,n)
        nd.attach_from_source('dns:\n  proxy-server-nameserver: [https://resolver-a.example/dns-query]\n',[n]);self.assertEqual(nd.metadata(n)['values'],['https://resolver-a.example/dns-query'])
        nd.attach_from_source('dns:\n  enable: false\n  proxy-server-nameserver: [1.1.1.1]\n',[n]);self.assertNotIn(nd.KEY,n)

    def test_fresh_conflict_and_history(self):
        a=with_hint(node(),'https://resolver-a.example/dns-query'); b=with_hint(node('B'),'https://resolver-b.example/dns-query')
        fresh,old=nd.reconcile_sources([a,b],[a]); self.assertFalse(nd.mappings(fresh+old))
        fresh,old=nd.reconcile_sources([b],[a]); self.assertEqual(nd.metadata(old[0])['values'],['https://resolver-b.example/dns-query'])
        fresh,old=nd.reconcile_sources([node()],[a]); self.assertEqual(nd.metadata(fresh[0])['values'],['https://resolver-a.example/dns-query'])
        self.assertEqual(nd.metadata(a)['values'],['https://resolver-a.example/dns-query'])
        a=with_hint(node(),'https://edge.airport.example/dns-query');self.assertFalse(nd.mappings([a]))

    def test_mihomo_config_no_global_override(self):
        a=with_hint(node(),'https://resolver-a.example/dns-query');b=with_hint(node('B','fixed.example'),'8.8.8.8',kind='ip')
        cfg={'dns':{'enable':True,'nameserver':['8.8.4.4'],'proxy-server-nameserver':['223.5.5.5']},'proxies':[]}
        nd.apply_mihomo(cfg,[a,b]); self.assertEqual(cfg['dns']['proxy-server-nameserver'],['223.5.5.5'])
        self.assertEqual(cfg['dns']['nameserver'],['8.8.4.4'])
        self.assertEqual(cfg['dns']['proxy-server-nameserver-policy'],{'edge.airport.example':['https://resolver-a.example/dns-query']})
        self.assertEqual(cfg['hosts'],{'fixed.example':['8.8.8.8']})
        cfg={};nd.apply_mihomo(cfg,[node()]);self.assertEqual(cfg,{})
        cfg={};nd.apply_mihomo(cfg,[a]);self.assertTrue(cfg['dns']['proxy-server-nameserver'])
        self.assertNotIn(nd.KEY,nd.clean_nodes([a])[0]); self.assertIn(nd.KEY,a)

    def test_actual_output_only_retained_nodes(self):
        a=with_hint(node(),'https://resolver-a.example/dns-query');b=with_hint(node('B','fixed.example'),'8.8.8.8',kind='ip');c=with_hint(node('C','discard.example'),'https://resolver-b.example/dns-query')
        doc={'dns':{'nameserver':['223.5.5.5']},'proxies':nd.clean_nodes([a,b]),'proxy-groups':[],'rules':['MATCH,DIRECT']}
        profile=yaml.safe_dump(doc,allow_unicode=True,sort_keys=False)
        generated=yaml.safe_load(nd.apply_clash_profile(profile,[a,b,c]));self.assertEqual(generated['proxies'],doc['proxies']);self.assertEqual(generated['rules'],doc['rules'])
        self.assertEqual(generated['dns']['proxy-server-nameserver-policy'],{'edge.airport.example':['https://resolver-a.example/dns-query']})
        self.assertEqual(generated['hosts'],{'fixed.example':['8.8.8.8']})
        surge='[General]\nloglevel = notify\n[Proxy]\n台湾 001 = trojan, edge.airport.example, 443, password=dummy\nB = trojan, fixed.example, 443, password=dummy\n[Rule]\nFINAL,DIRECT\n'
        rendered=nd.apply_surge_profile(surge,[a,b,c]);self.assertIn('[Host]\n',rendered)
        self.assertIn('edge.airport.example = server:https://resolver-a.example/dns-query',rendered);self.assertIn('fixed.example = 8.8.8.8',rendered)
        self.assertNotIn('discard.example',rendered);self.assertIn('FINAL,DIRECT',rendered)
        self.assertEqual(nd.apply_surge_profile(rendered,[a,b,c]),rendered)
        module=nd.surge_dns_module(rendered,[a,b,c])
        self.assertIn('edge.airport.example = server:https://resolver-a.example/dns-query',module)
        self.assertIn('fixed.example = 8.8.8.8',module)
        self.assertNotIn('discard.example',module);self.assertNotIn('[Proxy]',module)
        self.assertNotIn('edge.airport.example',nd.surge_dns_module(rendered,[]))
        self.assertEqual(nd.apply_clash_profile(profile,[node()]),profile)


class IntegrationTests(unittest.TestCase):
    def test_snapshot_preserves_valid_hint_not_private_fields(self):
        from verified_nodes import merge_candidates, snapshot_content
        a=with_hint(node(),'https://resolver-a.example/dns-query');a['sub']='private';a['_other']='secret'
        obj=json.loads(snapshot_content([a]));rec=obj['nodes'][0]
        self.assertEqual(nd.metadata(rec)['values'],['https://resolver-a.example/dns-query']);self.assertNotIn('sub',rec);self.assertNotIn('_other',rec)
        merged,_=merge_candidates([node()],[rec]);self.assertEqual(nd.metadata(merged[0])['values'],['https://resolver-a.example/dns-query'])
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
        a=with_hint(node(),'https://resolver-a.example/dns-query')
        def batch_query(proxies, **kwargs):
            return [types.SimpleNamespace(proxy=n,success=True,result=types.SimpleNamespace(country='台湾',is_cdn=False)) for n in proxies]
        fake=types.SimpleNamespace(ISO_TO_CHINESE={'TW':'台湾'},batch_query=batch_query,locate_by_ipinfo=lambda x:x)
        with patch.dict(sys.modules,{'location':fake}):
            nodes,_=label_verified_nodes([a])
        self.assertEqual(nd.metadata(nodes[0])['values'],['https://resolver-a.example/dns-query'])
        self.assertEqual(nodes[0]['name'],'🇹🇼 台湾 001')

    def test_decode_capture_only_when_enabled(self):
        from airport import AirPort
        source='''proxies:
  - {name: A, type: trojan, server: edge.airport.example, port: 443, password: dummy}
dns:
  proxy-server-nameserver-policy:
    edge.airport.example: https://resolver-a.example/dns-query
'''
        with patch.dict(os.environ,{'AGGREGATOR_CAPTURE_NODE_DNS':'1'}):
            nodes=AirPort.decode(source,'',use_subconverter=False,do_verify=False)
        self.assertEqual(nd.metadata(nodes[0])['values'],['https://resolver-a.example/dns-query'])
        with patch.dict(os.environ,{'AGGREGATOR_CAPTURE_NODE_DNS':'0'}):
            nodes=AirPort.decode(source,'',use_subconverter=False,do_verify=False)
        self.assertNotIn(nd.KEY,nodes[0])

    def test_refresh_detection_dns_matches_client_template(self):
        from clash import generate_config
        from location import generate_mihomo_config
        from test_clash_oneclick import simplified_clash_template
        expected = simplified_clash_template()["dns"]
        ordinary = node('A', 'ordinary.example')
        special = with_hint(node('B', 'special.example'), 'https://resolver-a.example/dns-query')
        fixed = with_hint(node('C', 'fixed.example'), '8.8.8.8', kind='ip')
        with patch.dict(os.environ, {'AGGREGATOR_CAPTURE_NODE_DNS': '1', 'AGGREGATOR_RUNNER_IPV6': '0'}):
            for sample in ([ordinary], [ordinary, special, fixed]):
                with tempfile.TemporaryDirectory() as d:
                    result = generate_config(d, [dict(n) for n in sample], 'test.yaml')
                    live = yaml.safe_load((Path(d) / 'test.yaml').read_text('utf-8'))
                geo, _ = generate_mihomo_config([dict(n) for n in sample],
                                               [18081, 18082, 18083], 18080)
                for config in (live, geo):
                    dns = config['dns']
                    self.assertTrue(dns['enable'])
                    self.assertFalse(config['ipv6']); self.assertFalse(dns['ipv6'])
                    self.assertTrue(config['tcp-concurrent'])
                    for key in ('default-nameserver', 'proxy-server-nameserver'):
                        self.assertEqual(dns[key], expected[key])
                    self.assertTrue(all(nd.KEY not in n for n in config['proxies']))
                    if len(sample) == 3:
                        self.assertEqual(dns['proxy-server-nameserver-policy'],
                                         {'special.example': ['https://resolver-a.example/dns-query']})
                        self.assertEqual(config['hosts'], {'fixed.example': ['8.8.8.8']})
                        self.assertEqual(len(nd.mappings(result)), 2)
                    else:
                        self.assertNotIn('proxy-server-nameserver-policy', dns)
                        self.assertNotIn('hosts', config)
                self.assertEqual(live['dns']['nameserver'], ['system'])
                self.assertEqual(geo['dns']['nameserver'], ['114.114.114.114', '8.8.8.8'])

    def test_detection_dns_outside_refresh_is_unchanged(self):
        with patch.dict(os.environ, {'AGGREGATOR_CAPTURE_NODE_DNS': '0'}):
            config = {'dns': {'nameserver': ['8.8.8.8']}}
            nd.apply_detection_dns(config, [node()])
            self.assertEqual(config, {'dns': {'nameserver': ['8.8.8.8']}})
            a = with_hint(node(), 'https://resolver-a.example/dns-query')
            expected = {'dns': {'nameserver': ['8.8.8.8']}}
            nd.apply_mihomo(expected, [a])
            nd.apply_detection_dns(config, [a])
            self.assertEqual(config, expected)

    def test_liveness_and_geo_actual_configuration(self):
        from clash import generate_config
        from location import generate_mihomo_config
        a=with_hint(node(),'https://resolver-a.example/dns-query')
        with tempfile.TemporaryDirectory() as d:
            result=generate_config(d,[a], 'test.yaml')
            doc=yaml.safe_load((Path(d)/'test.yaml').read_text('utf-8'))
            self.assertEqual(doc['dns']['proxy-server-nameserver-policy'],{'edge.airport.example':['https://resolver-a.example/dns-query']})
            self.assertNotIn(nd.KEY,doc['proxies'][0]);self.assertIn(nd.KEY,result[0])
        cfg,records=generate_mihomo_config([a],[18081],18080)
        self.assertEqual(cfg['dns']['proxy-server-nameserver-policy'],{'edge.airport.example':['https://resolver-a.example/dns-query']})
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

class SourceDNSDiagnosticsTests(unittest.TestCase):
    def test_primary_counts_match_reject_and_unmatched(self):
        source = '''proxies: []
dns:
  nameserver: [8.8.8.8]
  proxy-server-nameserver-policy:
    edge.airport.example: https://resolver-a.example/dns-query
    bad.example: 127.0.0.1
'''
        ns = [node(), node('B', 'bad.example'), node('C','unmatched.example'), node('D','1.0.0.1')]
        stats = {}
        nd.attach_from_source(source, ns, stats)
        self.assertEqual({k:stats[k] for k in ('entries','domain_nodes','matched','attached','rejected','unmatched')},
                         {'entries':2,'domain_nodes':3,'matched':2,'attached':1,'rejected':1,'unmatched':1})
        self.assertEqual(nd.metadata(ns[0])['values'],['https://resolver-a.example/dns-query'])

    def test_quoted_yaml_and_json_source(self):
        ns = [node()]
        stats = {}
        nd.attach_from_source('"dns": {"proxy-server-nameserver-policy": {"edge.airport.example": "https://resolver-a.example/dns-query"}}',ns,stats)
        self.assertEqual(stats['attached'],1)
        nd.attach_from_source('{"dns":{"proxy-server-nameserver-policy":{"edge.airport.example":"https://resolver-b.example/dns-query"}}}',ns,{})
        self.assertEqual(nd.metadata(ns[0])['values'],['https://resolver-b.example/dns-query'])

    def test_supplemental_profiles_require_same_endpoint_and_do_not_replace_primary(self):
        ns=[node(), node('B','tw.airport.example'),node('C','jp.airport.example'),node('D','other.example')]
        original='''proxies: []
dns:
  proxy-server-nameserver-policy:
    edge.airport.example: https://resolver-a.example/dns-query
'''
        clash='''proxies:
  - {name: C, server: tw.airport.example, port: 443}
  - {name: D, server: jp.airport.example, port: 444}
  - {name: E, server: edge.airport.example, port: 443}
dns:
  proxy-server-nameserver-policy:
    '+.airport.example': https://resolver-b.example/dns-query
'''
        surge='''[Proxy]
A = trojan, jp.airport.example, 443, password=x
[Host]
*.airport.example = server:https://dns.example/dns-query?key=secret_token_123
other.example = server:8.8.8.8
'''
        from unittest.mock import Mock
        fetch=Mock(side_effect=[clash,surge]); logs=[]
        with patch.dict(os.environ,{'AGGREGATOR_ALLOW_TOKENIZED_DNS':'true'}):
            nd.enrich_subscription(original,ns,'https://airport.example/sub?token=private',fetch,logs.append)
            self.assertEqual(nd.metadata(ns[0])['values'],['https://resolver-a.example/dns-query'])
            self.assertEqual(nd.metadata(ns[1])['values'],['https://resolver-b.example/dns-query'])
            self.assertEqual(nd.metadata(ns[2])['values'],['https://dns.example/dns-query?key=secret_token_123'])
            self.assertIsNone(nd.metadata(ns[3]))
        self.assertEqual(fetch.call_count,2)
        self.assertEqual([c.kwargs['headers']['User-Agent'] for c in fetch.call_args_list],['Clash.Meta','Surge'])
        self.assertTrue(all(c.kwargs['url']=='https://airport.example/sub?token=private' and c.kwargs['retry']==1 and c.kwargs['trace'] is False for c in fetch.call_args_list))
        self.assertIn('总附加=3',logs[0]); self.assertNotIn('secret_token',logs[0]);self.assertNotIn('private',logs[0]);self.assertNotIn('airport.example',logs[0])

    def test_already_mapped_and_ip_nodes_do_not_probe(self):
        from unittest.mock import Mock
        fetch=Mock();logs=[]
        nd.enrich_subscription('[Host]\nedge.airport.example = server:https://resolver-a.example/dns-query',[node(),node('B','8.8.8.8')], 'https://airport.example/sub',fetch,logs.append)
        fetch.assert_not_called();self.assertIn('补取=未执行',logs[0])

    def test_identical_and_failed_responses_counted_without_losing_nodes(self):
        from unittest.mock import Mock
        ns=[node()];logs=[]
        fetch=Mock(side_effect=['ss://sample',TimeoutError()])
        nd.enrich_subscription('ss://sample',ns,'https://airport.example/sub',fetch,logs.append)
        self.assertIsNone(nd.metadata(ns[0]));self.assertEqual(len(ns),1)
        self.assertIn('Clash.Meta=同原响应',logs[0]);self.assertIn('Surge=空响应',logs[0])

    def test_stage_diagnostics_counts_conflicts(self):
        logs=[]
        nd.log_stage('测试',[with_hint(node(),'https://resolver-a.example/dns-query'),with_hint(node('B'),'https://resolver-b.example/dns-query')],logs.append)
        self.assertIn('带映射节点=2',logs[0]);self.assertIn('可用映射=0',logs[0]);self.assertIn('冲突或循环跳过=1',logs[0]);self.assertNotIn('https://resolver-a.example/dns-query',logs[0])


    def test_profile_diagnostics_counts_only_rendered_entries(self):
        a=with_hint(node(),'https://resolver-a.example/dns-query'); b=with_hint(node('B','other.example'),'https://resolver-b.example/dns-query')
        logs=[]
        nd.log_profile('Clash', 'dns:\n  proxy-server-nameserver-policy:\n    edge.airport.example: [https://resolver-a.example/dns-query]\n', [a,b],logs.append)
        nd.log_profile('Surge', '[Host]\nedge.airport.example = server:https://resolver-a.example/dns-query\n', [a,b],logs.append)
        self.assertTrue(all('实际输出=1，未输出=1' in l for l in logs))
        self.assertTrue(all('https://resolver-a.example/dns-query' not in l for l in logs))


class SourceDNSWiringAndIconTests(unittest.TestCase):
    def test_decode_calls_supplementary_fetch_only_in_capture_mode(self):
        from airport import AirPort
        raw='''proxies:
  - {name: A, type: trojan, server: edge.airport.example, port: 443, password: dummy}
'''
        full=raw+'dns:\n  proxy-server-nameserver-policy:\n    edge.airport.example: https://resolver-a.example/dns-query\n'
        with patch.dict(os.environ,{'AGGREGATOR_CAPTURE_NODE_DNS':'1'}), patch('airport.utils.http_get',return_value=full) as fetch:
            ns=AirPort.decode(raw,'',use_subconverter=False,do_verify=False,source_url='https://airport.example/sub')
            self.assertEqual(nd.metadata(ns[0])['values'],['https://resolver-a.example/dns-query']);fetch.assert_called_once()
        with patch.dict(os.environ,{'AGGREGATOR_CAPTURE_NODE_DNS':'0'}), patch('airport.utils.http_get') as fetch:
            ns=AirPort.decode(raw,'',use_subconverter=False,do_verify=False,source_url='https://airport.example/sub')
            self.assertIsNone(nd.metadata(ns[0]));fetch.assert_not_called()

    def test_weekly_protection_and_core_contract(self):
        airport=(ROOT/'subscribe/airport.py').read_text('utf-8')
        self.assertIn('source_url=url,',airport)
        self.assertIn('enrich_subscription(original_dns_source, nodes, source_url, utils.http_get, logger.info)',airport)
        collector=(ROOT/'subscribe/collect.py').read_text('utf-8')
        for label in ('采集后','历史合并与去重后','连通性检测后','出口地区确认后'):
            self.assertIn(f'log_stage("{label}"',collector)
        weekly=(ROOT/'.github/workflows/collect.yaml').read_text('utf-8')
        self.assertIn('subscribe/extensions',weekly);self.assertIn('tests/test_extension_dns.py',weekly)
        self.assertIn('python -m unittest discover -s tests -q',weekly)
        self.assertIn('git merge --abort',weekly)

    def test_five_icon_urls_and_preserved_group_behavior(self):
        from profile_layout import groups_for_clash, icon_url, apply_profile_layout
        from struct import unpack
        expected={'人工智能':'ChatGPT.png','苹果推送':'ApplePush.png','数字资产':'Binance.png','冷钱包':'ColdWallet.png','特殊节点':'Rocket.png','国际媒体':'Netflix.png'}
        names=['🇭🇰 香港 001','🇹🇼 台湾 001','🇯🇵 日本 001','🇰🇷 韩国 001']
        groups={g['name']:g for g in groups_for_clash(names)}
        for name,file in expected.items():
            self.assertTrue(icon_url(name).endswith('/'+file));self.assertEqual(groups[name]['icon'],icon_url(name))
        self.assertNotEqual(icon_url('苹果推送'),icon_url('苹果服务'))
        self.assertEqual(icon_url('国际媒体'), 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Netflix.png')
        self.assertIn('电报代理',groups); self.assertIn('GitHub',groups)
        self.assertNotIn('Telegram',groups); self.assertNotIn('GitHub服务',groups)
        self.assertEqual(groups['GitHub']['proxies'][0],'香港节点')
        import tomllib
        reg=tomllib.loads((ROOT/'subconverter/snippets/rulesets.toml').read_text('utf-8'))
        self.assertIn('group = "电报代理"',(ROOT/'subconverter/snippets/rulesets.toml').read_text('utf-8'))
        self.assertIn('group = "GitHub"',(ROOT/'subconverter/snippets/rulesets.toml').read_text('utf-8'))
        self.assertEqual(groups['特殊节点']['type'],'select')
        self.assertEqual(groups['台湾节点']['type'],'url-test');self.assertEqual(groups['台湾节点']['interval'],600);self.assertTrue(groups['台湾节点']['lazy'])
        self.assertEqual(groups['人工智能']['proxies'][0],'日本节点')
        self.assertEqual(groups['港台番剧']['proxies'][0],'国内直连')
        for f in ('ApplePush.png','Binance.png','ColdWallet.png'):
            data=(ROOT/'subscribe/extensions/icons'/f).read_bytes()
            self.assertEqual(data[:8],b'\x89PNG\r\n\x1a\n'); self.assertEqual(unpack('>II',data[16:24]),(128,128));self.assertEqual(data[25],6)
        surge='[General]\n[Proxy]\n'+'\n'.join(n+' = trojan, edge.airport.example, 443, password=dummy' for n in names)+'\n[Rule]\nFINAL,DIRECT\n'
        result=apply_profile_layout(surge,'surge')
        for name in expected: self.assertIn('icon-url='+icon_url(name),result)
        self.assertIn('电报代理 = select,',result);self.assertIn('GitHub = select,',result)
        self.assertIn('特殊节点 = select,',result);self.assertIn('台湾节点 = smart,',result)


class StrictDoHAndIPv6Tests(unittest.TestCase):
    def test_generic_ipv4_and_public_doh_not_special(self):
        n = node()
        for value in ('1.1.1.1', '223.5.5.5', '8.8.8.8', 'https://dns.alidns.com/dns-query',
                      'https://doh.pub/dns-query', 'https://doh-pure.onedns.net/dns-query',
                      'https://doh.360.cn/dns-query', 'https://1.1.1.1/dns-query',
                      'tls://9.9.9.9', 'https://[2606:4700:4700::1111]/dns-query'):
            self.assertIsNone(nd.hint('dns', value), value)
            for text in ('dns:\n  proxy-server-nameserver: ['+value+']\n',
                         'dns:\n  proxy-server-nameserver-policy:\n    edge.airport.example: '+value+'\n'):
                nd.attach_from_source(text, [n]); self.assertNotIn(nd.KEY, n)
        self.assertIsNone(nd.metadata(with_hint(n,'1.1.1.1')))
        self.assertEqual(nd.mappings([with_hint(n,'1.1.1.1')]), {})
        # Fixed address mappings are a distinct, intentional feature.
        self.assertEqual(nd.hint('ip','8.8.8.8')['values'], ['8.8.8.8'])

    def test_custom_ip_port_token_doh_only_and_history_cleanup(self):
        from verified_nodes import merge_candidates, snapshot_content
        special = 'https://20.30.40.50:2443/dns-query/example-token?site=example'
        with patch.dict(os.environ, {'AGGREGATOR_ALLOW_TOKENIZED_DNS':'true'}):
            n = node()
            values = ['1.1.1.1', 'https://doh.pub/dns-query', special]
            text = yaml.safe_dump({'dns': {'proxy-server-nameserver-policy': {'+.airport.example': values}}}, sort_keys=False)
            self.assertEqual(yaml.safe_load(text)['dns']['proxy-server-nameserver-policy']['+.airport.example'], values)
            nd.attach_from_source(text, [n])
            self.assertEqual(nd.metadata(n)['values'], [special])
            inline = yaml.safe_dump({'dns': {'proxy-server-nameserver-policy': {'+.airport.example': values}}}, default_flow_style=True)
            nd.attach_from_source(inline, [n])
            self.assertEqual(nd.metadata(n)['values'], [special])
            fresh, _ = merge_candidates([node()], [with_hint(node(),'8.8.8.8')])
            self.assertFalse(nd.mappings(fresh))
            self.assertNotIn(nd.KEY, json.loads(snapshot_content(fresh))['nodes'][0])
            fresh, _ = merge_candidates([node()], [with_hint(node(),special)])
            self.assertEqual(nd.metadata(fresh[0])['values'], [special])
            cfg = {'dns': {'proxy-server-nameserver': list(nd.NODE_DNS_RESOLVERS)}}
            nd.apply_mihomo(cfg, fresh)
            self.assertEqual(cfg['dns']['proxy-server-nameserver-policy'], {'edge.airport.example':[special]})
            self.assertEqual(cfg['dns']['proxy-server-nameserver'], list(nd.NODE_DNS_RESOLVERS))
            surge = '[Proxy]\n台湾 001 = trojan, edge.airport.example, 443, password=dummy\n'
            self.assertIn('server:'+special, nd.apply_surge_profile(surge, fresh))

    def test_generic_primary_still_probes_for_real_doh(self):
        from unittest.mock import Mock
        nodes = [node()]
        primary = 'dns:\n  proxy-server-nameserver: [1.1.1.1]\n'
        full = 'proxies:\n  - {name: A, server: edge.airport.example, port: 443}\ndns:\n  proxy-server-nameserver-policy:\n    edge.airport.example: https://resolver-a.example/dns-query\n'
        fetch = Mock(return_value=full)
        nd.enrich_subscription(primary, nodes, 'https://airport.example/sub', fetch, lambda _: None)
        self.assertEqual(nd.metadata(nodes[0])['values'], ['https://resolver-a.example/dns-query'])
        fetch.assert_called_once()

    def test_runner_ipv6_probe_success_and_failure(self):
        from unittest.mock import MagicMock
        with patch.dict(os.environ, {}, clear=False):
            with patch.object(nd.socket, 'create_connection', side_effect=[OSError(), MagicMock()]) as connect:
                self.assertTrue(nd.configure_runner_ipv6(lambda _: None))
                self.assertEqual(os.environ['AGGREGATOR_RUNNER_IPV6'], '1'); self.assertEqual(connect.call_count, 2)
            with patch.object(nd.socket, 'create_connection', side_effect=OSError()) as connect:
                self.assertFalse(nd.configure_runner_ipv6(lambda _: None))
                self.assertEqual(os.environ['AGGREGATOR_RUNNER_IPV6'], '0'); self.assertEqual(connect.call_count, 2)

    def test_detection_ipv6_both_real_config_paths(self):
        from clash import generate_config
        from location import generate_mihomo_config
        special = with_hint(node(), 'https://resolver-a.example/dns-query')
        for flag in ('0','1'):
            with patch.dict(os.environ, {'AGGREGATOR_CAPTURE_NODE_DNS':'1', 'AGGREGATOR_RUNNER_IPV6':flag}):
                with tempfile.TemporaryDirectory() as d:
                    generate_config(d,[dict(special)],'test.yaml')
                    live = yaml.safe_load((Path(d)/'test.yaml').read_text('utf-8'))
                geo, _ = generate_mihomo_config([dict(special)], [18081], 18080)
                for cfg in (live,geo):
                    self.assertEqual(cfg['ipv6'], flag=='1')
                    self.assertEqual(cfg['dns']['ipv6'], flag=='1')
                    self.assertTrue(cfg['tcp-concurrent'])
                    self.assertEqual(cfg['dns']['proxy-server-nameserver-policy'], {'edge.airport.example':['https://resolver-a.example/dns-query']})
                    self.assertEqual(cfg['dns']['proxy-server-nameserver'], list(nd.NODE_DNS_RESOLVERS))


if __name__=='__main__': unittest.main()
