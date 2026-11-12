"""Offline regressions: reliable incremental discovery, durable Gist checkpoints."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'subscribe'))
from scan_state import ScanState, GistCheckpoint, STATE_FILE, VERSION, site_key
import discovery
import collect_safety as safety


def hosts(count=5):
    return {f'https://site{i}.example.org': discovery.AirportRecord(f'https://site{i}.example.org') for i in range(count)}


class RegistryTests(unittest.TestCase):
    def test_first_run_scans_every_discovered_site_without_scheduling_limit(self):
        state=ScanState.load('')
        subset, stats=state.select(hosts(14), budget=9000, now=10000000)
        self.assertEqual(len(subset),14)
        self.assertEqual((stats['new'],stats['remaining']),(14,0))

    def test_next_scan_works_on_unchecked_sites_before_any_retries(self):
        state=ScanState.load('')
        catalog=hosts(14)
        a,summary=state.select(catalog,budget=9,now=10000000)
        state.mark_sites(a,[],now=10000000)
        b,summary=state.select(catalog,budget=9,now=10000001)
        self.assertEqual(len(b),5)
        self.assertFalse(set(a)&set(b))
        self.assertEqual(summary['waiting'],9)

    def test_discovered_but_not_tested_are_persisted(self):
        state=ScanState.load('')
        state.remember_discoveries(hosts(14))
        first,_=state.select(hosts(14),budget=9,now=10000000)
        state.mark_sites(first,[],now=10000000)
        restored=ScanState.load(state.encode())
        self.assertEqual(len(restored.known_sites()),14)
        # Even if next crawl no longer lists these sites, they remain in Gist.
        from_history={u:None for u in restored.known_sites()}
        second,_=restored.select(from_history,budget=9,now=10000001)
        self.assertEqual(len(second),5)
        self.assertFalse(set(first)&set(second))

    def test_failed_sites_retry_after_cooldown_not_forever(self):
        state=ScanState.load('')
        data=hosts(1)
        state.mark_sites(data,[],now=10000000)
        self.assertFalse(state.select(data,budget=9,now=10000000+6*86400)[0])
        self.assertEqual(len(state.select(data,budget=9,now=10000000+8*86400)[0]),1)

    def test_valid_site_does_not_register_again_next_refresh_cycle(self):
        state=ScanState.load('')
        data=hosts(1)
        state.mark_sites(data,data,now=10000000)
        self.assertFalse(state.select(data,budget=9,now=10000000+2*3600)[0])
        self.assertTrue(state.select(data,budget=9,now=10000000+4*86400)[0])

    def test_exclusion_host_and_case_insensitive_dedup(self):
        state=ScanState.load('')
        data={'https://SITE.example.org': 1,'http://site.example.org':2,'https://new.example.org':3}
        selected,_=state.select(data,excluded_hosts={'site.example.org'},budget=9,now=10000000)
        self.assertEqual(list(selected),['https://new.example.org'])
        self.assertEqual(site_key('https://SITE.example.org'),site_key('http://site.example.org'))

    def test_untrusted_private_site_is_not_probed(self):
        for url in ("https://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
                    "https://host.internal", "http://localhost", "http://[::1]:443"):
            self.assertEqual(site_key(url), "", url)
        self.assertTrue(site_key("https://public.example.org"))

    def test_roundtrip_and_no_secret_raw_data(self):
        state=ScanState.load('')
        state.mark_sites({'https://site.example.org/private?token=SECRET':None},[],now=10000000)
        state.mark_nodes([{'password':'SECRET','server':'server.example.org'}],
                         identity=lambda _: 'a'*64, verified_label=lambda _:False,now=10000000)
        raw=state.encode()
        self.assertNotIn('SECRET',raw)
        self.assertIn('site.example.org',raw)  # public site origin only
        self.assertNotIn('private?token=',raw)
        self.assertEqual(ScanState.load(raw),state)

    def test_invalid_state_fails_closed(self):
        # Stage 10 checkpoint format is VERSION=2. Earlier tests wrongly
        # rejected an empty, structurally valid v2 checkpoint.
        self.assertEqual(VERSION, 2)
        valid = {'v': VERSION, 'sites': {}, 'nodes': {}}
        self.assertEqual(ScanState.load(json.dumps(valid)), ScanState({}, {}))
        with self.assertRaises(ValueError): ScanState.load('{bad')
        for invalid in (
            {'v': 1, 'sites': {}, 'nodes': {}},
            {'v': VERSION + 1, 'sites': {}, 'nodes': {}},
            {'v': VERSION, 'sites': {}, 'nodes': None},
            {'v': VERSION, 'sites': {'foo': [1, 'bad', 0, '']}, 'nodes': {}},
            {'v': VERSION, 'sites': {'a'*64: [1, 'bad', 0, 'https://127.0.0.1']}, 'nodes': {}},
            {'v': VERSION, 'sites': {}, 'nodes': {'a'*64: [0, 'madeup', 0]}},
        ):
            with self.subTest(state=invalid), self.assertRaises(ValueError):
                ScanState.load(json.dumps(invalid))

    def test_checkpoint_current_schema_roundtrip(self):
        state = ScanState({}, {})
        state.remember_discoveries({'https://host.example.org/sensitive?token=secret': None})
        state.mark_sites({'https://host.example.org': None}, [], now=1000000)
        state.mark_nodes([{'server': 'private.example.org', 'password': 'never-expose'}],
                         identity=lambda _: 'b'*64, verified_label=lambda _: False, now=1000000)
        raw = state.encode()
        self.assertEqual(json.loads(raw)['v'], VERSION)
        self.assertEqual(ScanState.load(raw), state)
        self.assertNotIn('secret', raw)
        self.assertNotIn('never-expose', raw)

    def test_merge_retains_most_recent_record(self):
        a=ScanState({'a'*64:[100,'bad',2,'']}, {})
        b=ScanState({'a'*64:[90,'ready',0,''], 'b'*64:[120,'ready',0,'']}, {})
        a.merge(b)
        self.assertEqual(a.sites['a'*64],[100,'bad',2,''])
        self.assertEqual(len(a.sites),2)


class CheckpointTests(unittest.TestCase):
    def test_state_only_patch_cannot_overwrite_published_files(self):
        baseline={'clash.yaml':'old verified','subscribes.txt':'https://old.example/sub'}
        remote=copy.deepcopy(baseline)
        calls=[]
        def read(*args): return ('v1',copy.deepcopy(remote))
        def write(content):
            calls.append(json.loads(content))
            remote[STATE_FILE]=content
        cp=GistCheckpoint('abcdef','TEST_TOKEN',baseline,reader=read,writer=write)
        cp.state.mark_sites({'https://foo.example.org':None},[],now=10000000)
        cp.save()
        self.assertEqual(remote['clash.yaml'],'old verified')
        self.assertEqual(remote['subscribes.txt'],'https://old.example/sub')
        self.assertEqual(len(calls),1)

    def test_external_publication_change_aborts_without_state_write(self):
        baseline={'clash.yaml':'old'}
        writes=[]
        cp=GistCheckpoint('abcdef','secret',baseline,
                          reader=lambda *_:('v2',{'clash.yaml':'someone else'}),
                          writer=lambda content:writes.append(content))
        with self.assertRaises(safety.PublicationError): cp.save()
        self.assertEqual(writes,[])

    def test_bad_remote_checkpoint_does_not_get_overwritten(self):
        baseline={'clash.yaml':'old'}
        writes=[]
        cp=GistCheckpoint('abcdef','secret',baseline,
                          reader=lambda *_:('v2',{'clash.yaml':'old',STATE_FILE:'corrupted'}),
                          writer=lambda content:writes.append(content))
        with self.assertRaises(safety.PublicationError): cp.save()
        self.assertEqual(writes,[])


class CollectorTests(unittest.TestCase):
    def test_checkpoint_per_batch_including_dead_sites(self):
        source=Mock()
        source.name='fake'
        source.persist=False
        source.crawl.return_value=list(hosts(5).values())
        resolver=Mock();resolver.resolve.side_effect=lambda domain:domain
        validator=Mock();validator.validate.side_effect=lambda domain, *_: (domain.endswith('site0.example.org'), '/api/v1/')
        collector=discovery.AirportCollector([source],discovery.CollectOptions(
            max_candidates=99,display=False),resolver,validator)
        state=ScanState.load('')
        checkpoint=Mock()
        result=collector.collect_incremental(state,checkpoint,chunk_size=2)
        self.assertEqual(len(result),1)
        self.assertEqual(checkpoint.save.call_count,4)  # initial catalogue + 3 probe batches
        self.assertEqual(len(state.sites),5)
        self.assertEqual(sum(x[1]=='ready' for x in state.sites.values()),1)
        self.assertEqual(sum(x[1]=='bad' for x in state.sites.values()),4)
        # A second run without elapsed cooldown discovers but does not probe.
        validator.validate.reset_mock()
        result=collector.collect_incremental(state,checkpoint,chunk_size=2)
        validator.validate.assert_not_called()
        self.assertEqual(result,{})
        self.assertEqual(checkpoint.save.call_count,5)  # second scan saves catalogue only

    def test_refresh_uses_existing_subscriptions_no_airport_discovery(self):
        from unittest.mock import patch
        import collect
        with patch.object(collect,'DATA_BASE','/tmp/stage10-no-such-dir'), \
             patch('collect.check_status',return_value=(True,False)), \
             patch('collect.collect_airport') as fresh:
            tasks=collect.assign('converter',refresh=True,
                                 existing_subscriptions={'https://sub.example.org/data'},
                                 subscribes_file='subscribes.txt',display=False)
            self.assertEqual(len(tasks),1)
            fresh.assert_not_called()


if __name__=='__main__': unittest.main()
