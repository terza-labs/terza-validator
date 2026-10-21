import asyncio
import dataclasses
import json
import tempfile
import time
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from terza_validator import (Chain, Evidence, Inconclusive, Offer, GENESIS, FAMILIES, challenge,
                             grade, score, weights, fetch, validate_config, verify_directory,
                             parse_offers, organic, key_id)


def offer(h='miner', model='model', stats=None):
    return Offer(f'admitted_{h}_1_0', h, model, 1, 2, time.time()+3600, 0, stats or {}, 1024)


GATEWAY = Ed25519PrivateKey.from_private_bytes(b'g'*32)
GATEWAY_PUB = GATEWAY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
CONFIG = {'network':'test','netuid':1,'models':['model'],'gateway_url':'https://terza.si',
          'gateway_public_keys':[GATEWAY_PUB],'api_key_file':'/private/key.json'}


def directory(offers, key=GATEWAY, **overrides):
    payload = json.dumps({'scheme':'terza-directory-v1','generated_at':int(time.time()*1000),
                          'network':'test','netuid':1,'offers':offers, **overrides})
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {'keyId':key_id(pub),'payload':payload,
            'signature':key.sign(b'terza-directory-v1\n'+payload.encode()).hex()}


def listed(hotkey='m', model='model', **extra):
    return {'offer_id':f'admitted_{hotkey}_1_0','hotkey':hotkey,'model_id':model,'protocols':['chat'],
            'input_price_per_m':'1','output_price_per_m':'2','max_input_tokens':4096,'max_output_tokens':1024,
            'quote_valid_until':'2999-01-01T00:00:00Z','stats_24h':{'requests':0},**extra}


def samples(ok=True):
    return [dict(round=str(i//3),family=FAMILIES[i%3], started=time.time(),
                 ok=int(ok),available=1,latency=1) for i in range(9)]


class ValidatorTests(unittest.TestCase):
    def test_nonce_replay_and_exact_json(self):
        for family in FAMILIES:
            _, answer = challenge(family)
            response = {'model':'model','choices':[{'finish_reason':'stop','message':{'content':json.dumps(answer)}}]}
            self.assertTrue(grade(response,answer,'model'))
            _, fresh = challenge(family)
            self.assertFalse(grade(response,fresh,'model'))
            response['model']='other'
            self.assertFalse(grade(response,answer,'model'))

    def test_quality_gates(self):
        good=samples()
        self.assertGreater(score(good)[0],0)
        self.assertEqual(score(good[:8])[0],0)
        self.assertEqual(score(samples(False))[0],0)
        for row in good: row['started']-=301
        self.assertEqual(score(good)[0],0)

    def test_outage_and_mixed_quality(self):
        good=samples()
        bad=samples()
        for row in bad[:2]: row.update(ok=0,available=0,latency=20)
        self.assertLess(score(bad)[0], score(good)[0])
        bad[2]['ok']=0
        self.assertEqual(score(bad)[0],0)

    def test_quote_revision_and_expiry(self):
        a=offer(); b=dataclasses.replace(a,offer_id='admitted_miner_2_0')
        self.assertNotEqual(a.fingerprint,b.fingerprint)
        class E:
            def recent(self,f): return samples() if f==a.fingerprint else []
            def hard(self,s): return []
        self.assertEqual(weights([b],E(),['model'])[0],{})
        a.expires=time.time()-1
        self.assertEqual(weights([a],E(),['model'])[0],{})

    def test_model_budget_and_price_bounded(self):
        class E:
            def recent(self,f): return samples()
            def hard(self,s): return []
        a=offer('a'); b=offer('b'); b.input_price=b.output_price=.0000001
        result,_=weights([a,b],E(),['model'])
        self.assertLess(result['b']/result['a'],1.34)
        self.assertAlmostEqual(sum(result.values()),1)
        # Unselected models must not enter the reward allocation.
        result,_=weights([a,offer('b','unselected')],E(),['model'])
        self.assertEqual(result,{'a':1})

    def test_private_destination_rejected(self):
        for url in ('http://example.com','https://127.0.0.1:8443','https://user:pw@example.com','https://example.com/a'):
            with self.assertRaises(ValueError): fetch({**CONFIG,'gateway_url':url},'GET','/')
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):fetch(CONFIG,'GET','/')
        with self.assertRaises(ValueError):fetch({**CONFIG,'local':True},'GET','/')

    def test_config_requires_pinned_gateway(self):
        validate_config(dict(CONFIG))
        for bad in ({'gateway_public_keys':[]},{'api_key_file':''},{'gateway_url':'http://terza.si'}):
            with self.assertRaises(ValueError):validate_config({**CONFIG,**bad})

    def test_directory_signature_freshness_and_subnet(self):
        data=verify_directory(directory([listed()]),[GATEWAY_PUB],CONFIG)
        self.assertEqual([o.offer_id for o in parse_offers(data,CONFIG)],['admitted_m_1_0'])
        doc=directory([listed()]); doc['payload']=doc['payload'].replace('"1"','"0.0000001"')
        with self.assertRaises(ValueError):verify_directory(doc,[GATEWAY_PUB],CONFIG)
        stranger=Ed25519PrivateKey.from_private_bytes(b's'*32)
        with self.assertRaises(ValueError):verify_directory(directory([],key=stranger),[GATEWAY_PUB],CONFIG)
        with self.assertRaises(ValueError):verify_directory(directory([]),[GATEWAY_PUB],CONFIG,now=time.time()+3600)
        with self.assertRaises(ValueError):verify_directory(directory([],netuid=2),[GATEWAY_PUB],CONFIG)
        with self.assertRaises(ValueError):verify_directory(directory([],network='finney'),[GATEWAY_PUB],CONFIG)

    def test_directory_filters_offers(self):
        data={'offers':[listed('a'),listed('b',model='other'),listed('c',protocols=['embeddings']),
                        listed('d',quote_valid_until='2000-01-01T00:00:00Z'),listed('e',max_output_tokens=64)]}
        self.assertEqual([o.hotkey for o in parse_offers(data,CONFIG)],['a'])

    def test_hard_tasks_grade_exactly(self):
        import random
        from terza_validator import HARD_FAMILIES, hard_task
        for family in HARD_FAMILIES:
            for seed in range(5):
                prompt, answer = hard_task(family, random.Random(seed))
                ok = {'model':'m','choices':[{'finish_reason':'stop','message':{'content':json.dumps({'nonce':'n','answer':answer})}}]}
                self.assertTrue(grade(ok,{'nonce':'n','answer':answer},'m'),family)
                self.assertFalse(grade(ok,{'nonce':'n','answer':str(answer)+'0'},'m'),family)
            _, expected = challenge(family)
            self.assertIn('Think carefully', _)

    def test_capability_verdicts(self):
        from terza_validator import capability, HARD_MIN_SAMPLES
        ref={'hard_accuracy':.75,'median_reasoning_tokens':278,'median_latency_seconds':4.6}
        def rows(k,n,reasoning=280,latency=5):
            return [{'ok':int(i<k),'reasoning':reasoning,'latency':latency} for i in range(n)]
        self.assertEqual(capability(rows(30,40),None)[1]['capability'],'uncalibrated')
        self.assertEqual(capability(rows(1,HARD_MIN_SAMPLES-1),ref)[0],1)
        self.assertEqual(capability(rows(30,40),ref),(1.,capability(rows(30,40),ref)[1]))
        self.assertEqual(capability(rows(30,40),ref)[1]['capability'],'consistent')
        # Phase 1: gpt-5.4-nano 2/40 and gpt-5.4-mini 3/40 are rejected outright.
        for k in (2,3):self.assertEqual(capability(rows(k,40),ref)[0],0)
        # gpt-5-nano: 23/40 is not conclusive on accuracy but its profile is.
        factor,metrics=capability(rows(23,40,reasoning=2816,latency=16.6),ref)
        self.assertEqual((factor,metrics['capability']),(.5,'profile_mismatch'))
        self.assertEqual(capability(rows(30,40,reasoning=0),ref)[1]['capability'],'profile_mismatch')
        self.assertEqual(capability(rows(30,40,latency=40),ref)[1]['capability'],'consistent','latency alone never flags')

    def test_hard_evidence_is_separate_and_scheduled(self):
        with tempfile.TemporaryDirectory() as d:
            e=Evidence(d+'/e.sqlite'); o=offer()
            self.assertTrue(e.hard_due(o.subject))
            answered=lambda o,p,deadline:({'model':'model','usage':{'completion_tokens':300,'completion_tokens_details':{'reasoning_tokens':280}},
                                           'choices':[{'finish_reason':'stop','message':{'content':'{}'}}]},4.0)
            e.sample(o,'mul','r',answered)
            self.assertEqual(e.recent(o.fingerprint),[],'hard probes never enter the basic quality score')
            hard=e.hard(o.subject); self.assertEqual((len(hard),hard[0]['reasoning']),(1,280))
            self.assertFalse(e.hard_due(o.subject))
            renewed=dataclasses.replace(o,offer_id='admitted_miner_2_0',expires=o.expires+1)
            self.assertEqual(len(e.hard(renewed.subject)),1,'history survives quote renewal')
            e.db.close()

    MEDIA = {'operations': {
        'image_to_video': {'inputs': {'first_frame': {'min': 1, 'max': 1}}, 'params': {'duration_seconds': {'allowed': [10, 5]},
                           'resolution': {'allowed': ['1080p', '720p']}, 'audio': {'allowed': [True, False]}}, 'output': 'video'},
        'video_extend': {'inputs': {'source_video': {'min': 1, 'max': 1}}, 'output': 'video'}},
        'rates': [{'operation': 'image_to_video', 'when': {'resolution': '1080p'}, 'unit': 'second', 'usd': '0.12'},
                  {'operation': 'image_to_video', 'unit': 'second', 'usd': '0.06'}, {'operation': 'video_extend', 'unit': 'task', 'usd': '1'}]}

    def test_media_probe_plan_is_the_cheapest_declared(self):
        from terza_validator import media_plan, probe_png
        plan = media_plan(self.MEDIA)
        self.assertEqual((plan['operation'], plan['params']), ('image_to_video', {'duration_seconds': 5, 'resolution': '720p', 'audio': False, 'count': 1}))
        self.assertAlmostEqual(plan['reserve'], .06 * 5 * 1.05)
        self.assertEqual([i['role'] for i in plan['inputs']], ['first_frame'])
        png = probe_png(8)
        self.assertTrue(png.startswith(b'\x89PNG\r\n\x1a\n') and b'IEND' in png)
        self.assertIsNone(media_plan({'operations': {'video_extend': self.MEDIA['operations']['video_extend']}, 'rates': self.MEDIA['rates']}),
                          'operations needing video input are not probed')

    def test_media_offers_parse_and_unprobeable_are_skipped(self):
        media = listed('v', model='model', protocols=['media'], media=self.MEDIA)
        blind = listed('w', model='model', protocols=['media'], media={'operations': {'video_extend': self.MEDIA['operations']['video_extend']}, 'rates': self.MEDIA['rates']})
        offers = parse_offers({'offers': [media, blind, listed('a')]}, CONFIG)
        self.assertEqual([(o.hotkey, o.kind) for o in offers], [('v', 'media'), ('a', 'text')])

    def test_media_probe_lifecycle_and_scoring(self):
        from terza_validator import media_score, MEDIA_PROBE_TIMEOUT
        with tempfile.TemporaryDirectory() as d:
            e = Evidence(d + '/e.sqlite')
            o = dataclasses.replace(offer('v'), kind='media', media=self.MEDIA)
            self.assertTrue(e.media_due(o.subject))
            tasks = iter(['t1', 't2', 't3', 't4'])
            for _ in range(4):
                e.media_submit(o, 'r', lambda off, plan: next(tasks))
            self.assertFalse(e.media_due(o.subject), 'one pending probe at a time')
            def lookup(task):
                return {'t1': {'status': 'succeeded', 'created_at': 100, 'completed_at': 160},
                        't2': {'status': 'failed', 'error': {'code': 'nonconforming_output'}},
                        't3': {'status': 'failed', 'error': {'code': 'gateway_failed'}},
                        't4': {'status': 'running'}}[task]
            e.media_finalize(lookup)
            done = {s['task']: s['status'] for s in e.db.execute("SELECT task, status FROM samples").fetchall()}
            self.assertEqual(done, {'t1': 'passed', 't2': 'nonconforming_output', 't3': 'inconclusive', 't4': 'pending'})
            e.media_finalize(lookup, now=time.time() + MEDIA_PROBE_TIMEOUT + 1)
            self.assertEqual(e.db.execute("SELECT status FROM samples WHERE task='t4'").fetchone()[0], 'timeout')
            def boom(off, plan): raise Inconclusive('gateway_402')
            e.media_submit(o, 'r', boom)
            self.assertEqual(len(e.media(o.subject)), 3, 'inconclusive probes never count')
            e.db.close()
        good = [{'ok': 1, 'latency': 60, 'started': time.time()} for _ in range(4)]
        self.assertGreater(media_score(good, {})[0], 0)
        self.assertEqual(media_score(good[:2], {})[0], 0)
        self.assertEqual(media_score(good + [{'ok': 0, 'latency': 20, 'started': time.time()}], {})[0], 0, 'availability below 90%')
        self.assertEqual(media_score(good, {'succeeded': 8, 'nonconforming': 2})[0], 0, 'organic conformance below 90%')

    def test_usage_hook_disabled_and_bounded(self):
        from terza_validator import blend_usage, usage_volume, USAGE_WEIGHT
        self.assertEqual(USAGE_WEIGHT, 0)
        busy={'buyer_charged_usd':'9.5','distinct_buyers':5}
        a=offer('a'); b=offer('b',stats=busy)
        q={'a':.5,'b':.5}
        self.assertEqual(blend_usage(q,[a,b]),q, 'disabled hook must not change weights')
        mixed=blend_usage(q,[a,b],weight=.5)
        self.assertAlmostEqual(mixed['b'],.75); self.assertAlmostEqual(sum(mixed.values()),1)
        self.assertEqual(usage_volume({'buyer_charged_usd':'100','distinct_buyers':2}),0, 'buyer floor')
        # Usage cannot rescue an offer without quality weight.
        self.assertEqual(blend_usage({'a':1},[a,offer('c',stats=busy)],weight=.5),{'a':1})
        with self.assertRaises(ValueError):blend_usage(q,[a,b],weight=.9)

    def test_organic_traffic(self):
        self.assertEqual(organic({'requests':5})[0],1)
        self.assertEqual(organic({'requests':100,'succeeded':98,'usage_rejected':2})[0],0)
        self.assertAlmostEqual(organic({'requests':100,'succeeded':90,'miner_failed':10})[0],.9)
        class E:
            def recent(self,f): return samples()
            def hard(self,s): return []
        result,_=weights([offer('a'),offer('b',stats={'requests':100,'succeeded':50,'usage_rejected':50})],E(),['model'])
        self.assertEqual(result,{'a':1})

    def test_persistent_failures_and_config_binding(self):
        with tempfile.TemporaryDirectory() as d:
            e=Evidence(d+'/e.sqlite')
            o=offer()
            def fail(*_):raise TimeoutError()
            asyncio.run(asyncio.to_thread(e.sample,o,'sorting','round',fail))
            self.assertEqual(e.recent(o.fingerprint)[0]['ok'],0)
            def broke(*_):raise Inconclusive('gateway_402')
            e.sample(o,'arithmetic','round',broke)
            self.assertEqual(len(e.recent(o.fingerprint)),1, 'validator-side problems never count against a miner')
            c={'netuid':1,'validator_hotkey':'v','models':['m']}
            e.bind_config(c)
            with self.assertRaises(ValueError):e.bind_config({**c,'netuid':2})
            e.db.close()

    def test_mainnet_and_root_refused(self):
        for net,uid in [('finney',1),('test',0),('test',65536)]:
            with self.assertRaises(ValueError):validate_config({'network':net,'netuid':uid,'models':['m']})


class FakeChainClient:
    def __init__(self):
        self._substrate=self
        self.genesis=GENESIS
        self.hotkeys={'v':7,'m':0}
        self.permit=True
        self.minimum=1
        self.rate=0
    async def block_hash(self,b):return self.genesis if b==0 else 'block'
    async def finalized_block(self):return 100
    async def query(self,desc,params,block):
        key=desc[1]
        if key=='NetworksAdded':return True
        if key=='Uids':return self.hotkeys.get(params[1])
        if key=='Keys':return next((h for h,u in self.hotkeys.items() if u==params[1]),None)
        if key=='ValidatorPermit':return [False]*7+[self.permit]
        if key=='CommitRevealWeightsEnabled':return False
        if key=='WeightsVersionKey':return 1
        if key=='LastUpdate':return [99]*8
        if key=='WeightsSetRateLimit':return self.rate
        if key=='MinAllowedWeights':return self.minimum
        if key=='MaxWeightsLimit':return 65535
        raise AssertionError(key)


class ChainTests(unittest.IsolatedAsyncioTestCase):
    async def test_uid_zero_and_guards(self):
        f=FakeChainClient(); c=Chain(f,1); o=offer('m')
        self.assertEqual(await c.preflight('v',{'m':1},[o]),{0:1})
        f.permit=False
        with self.assertRaises(ValueError):await c.preflight('v',{'m':1},[o])
        f.permit=True; f.rate=10
        with self.assertRaises(ValueError):await c.preflight('v',{'m':1},[o])
        f.rate=0; f.minimum=2
        with self.assertRaises(ValueError):await c.preflight('v',{'m':1},[o])
        f.minimum=1; f.hotkeys['m']=1
        with self.assertRaises(ValueError):await c.preflight('v',{'m':1},[o])
        f.genesis='mainnet'
        with self.assertRaises(ValueError):await c.snapshot()

    async def test_self_and_empty(self):
        c=Chain(FakeChainClient(),1)
        with self.assertRaises(ValueError):await c.preflight('v',{},[])
        with self.assertRaises(ValueError):await c.preflight('v',{'v':1},[dataclasses.replace(offer('v'),uid=7)])




class SubmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_finalized_and_uncertain_do_not_resubmit(self):
        import types
        import bittensor as bt
        from terza_validator import run
        for crash in (False, True):
            with tempfile.TemporaryDirectory() as d:
                ev=Evidence(d+'/e.sqlite'); o=offer('m')
                for i,s in enumerate(samples()):
                    ev.db.execute('INSERT INTO samples(challenge,round,fingerprint,family,started,ok,available,latency) VALUES(?,?,?,?,?,?,?,?)',
                                  (str(i),s['round'],o.fingerprint,s['family'],s['started'],1,1,1))
                ev.db.commit()
                ev.sample=lambda *args:None
                c={'netuid':1,'models':['model'],'validator_hotkey':'v','wallet_name':'validator',
                   'wallet_hotkey':'validator','wallet_path':d,'password_file':'not-used'}
                f=FakeChainClient(); f.calls=0
                async def plan(*args):return types.SimpleNamespace(ok=True)
                async def execute(*args,**kwargs):
                    f.calls+=1
                    self.assertTrue(kwargs['wait_for_finalization'])
                    if crash:raise TimeoutError()
                    return types.SimpleNamespace(success=True,to_dict=lambda:{'success':True,'block_hash':'final'})
                f.plan=plan;f.execute=execute
                class Context:
                    async def __aenter__(self):return f
                    async def __aexit__(self,*args):pass
                wallet=types.SimpleNamespace(hotkey=types.SimpleNamespace(ss58_address='v'),
                   hotkey_file=types.SimpleNamespace(get_keypair=lambda **kwargs:None))
                with patch('bittensor.Subtensor',return_value=Context()), patch('bittensor.wallet.Wallet',return_value=wallet), \
                     patch('terza_validator.load_offers',return_value=[o]),patch('terza_validator.private_json',return_value={'validator_hotkey_password':'private'}):
                    report=await run(c,ev,True)
                    self.assertEqual(report['status'],'unknown' if crash else 'finalized')
                    self.assertEqual(f.calls,1)
                    if crash:
                        with self.assertRaises(ValueError):await run(c,ev,True)
                        self.assertEqual(f.calls,1)
                ev.db.close()

if __name__=='__main__': unittest.main()
