from base64 import b32decode

import os

from twisted.trial import unittest
from twisted.internet import defer
from twisted.python import log

from foolscap import Tub, Referenceable
from foolscap.eventual import fireEventually, flushEventualQueue
from twisted.application import service
from allmydata.introducer.client import IntroducerClient, ClientAdapter_v1
from allmydata.introducer.server import IntroducerService
# test compatibility with old introducer .tac files
from allmydata.introducer import IntroducerNode
from allmydata.introducer import old
from allmydata.util import idlib, fileutil, pollmixin
import common_util as testutil
from allmydata import bless
from allmydata.scripts.admin import make_keypair

class FakeNode(Referenceable):
    pass

class LoggingMultiService(service.MultiService):
    def log(self, msg, **kw):
        log.msg(msg, **kw)

class Node(testutil.SignalMixin, unittest.TestCase):
    def test_loadable(self):
        basedir = "introducer.IntroducerNode.test_loadable"
        os.mkdir(basedir)
        q = IntroducerNode(basedir)
        d = fireEventually(None)
        d.addCallback(lambda res: q.startService())
        d.addCallback(lambda res: q.when_tub_ready())
        d.addCallback(lambda res: q.stopService())
        d.addCallback(flushEventualQueue)
        return d

class ServiceMixin:
    def setUp(self):
        self.parent = LoggingMultiService()
        self.parent.startService()
    def tearDown(self):
        log.msg("TestIntroducer.tearDown")
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d

class Introducer(ServiceMixin, unittest.TestCase, pollmixin.PollMixin):

    def test_create(self):
        ic = IntroducerClient(None, "introducer.furl", "my_nickname",
                              "my_version", "oldest_version", {})

    def test_listen(self):
        i = IntroducerService()
        i.setServiceParent(self.parent)

    def test_duplicate_publish(self):
        i = IntroducerService()
        self.failUnlessEqual(len(i.get_announcements()), 0)
        self.failUnlessEqual(len(i.get_subscribers()), 0)
        furl1 = "pb://62ubehyunnyhzs7r6vdonnm2hpi52w6y@192.168.69.247:36106,127.0.0.1:36106/gydnpigj2ja2qr2srq4ikjwnl7xfgbra"
        furl2 = "pb://ttwwooyunnyhzs7r6vdonnm2hpi52w6y@192.168.69.247:36111,127.0.0.1:36106/ttwwoogj2ja2qr2srq4ikjwnl7xfgbra"
        ann1 = (furl1, "storage", "RIStorage", "nick1", "ver23", "ver0")
        ann1b = (furl1, "storage", "RIStorage", "nick1", "ver24", "ver0")
        ann2 = (furl2, "storage", "RIStorage", "nick2", "ver30", "ver0")
        i.remote_publish(ann1)
        self.failUnlessEqual(len(i.get_announcements()), 1)
        self.failUnlessEqual(len(i.get_subscribers()), 0)
        i.remote_publish(ann2)
        self.failUnlessEqual(len(i.get_announcements()), 2)
        self.failUnlessEqual(len(i.get_subscribers()), 0)
        i.remote_publish(ann1b)
        self.failUnlessEqual(len(i.get_announcements()), 2)
        self.failUnlessEqual(len(i.get_subscribers()), 0)

class FakeRemoteServiceConnector:
    remote_host = None
    rref = None
    last_connect_time = None
    last_loss_time = None
    def __init__(self, furl):
        self.furl = furl
        self.started = False
        self.stopped = False
        self.disconnected = False
    def startConnecting(self):
        self.started = True
    def stopConnecting(self):
        self.stopped = True
    def disconnect(self):
        self.disconnected = False

class NonConnectingIntroducerClient(IntroducerClient):
    def make_connector(self, furl):
        return FakeRemoteServiceConnector(furl)

class Client(unittest.TestCase):
    def test_duplicate_receive_v1(self):
        ic = NonConnectingIntroducerClient(None,
                                           "introducer.furl", "my_nickname",
                                           "my_version", "oldest_version", {})
        ic.subscribe_to("storage")
        furl1 = "pb://62ubehyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:36106/gydnpigj2ja2qr2srq4ikjwnl7xfgbra"
        furl2 = "pb://ttwwooyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:36106/ttwwoogj2ja2qr2srq4ikjwnl7xfgbra"
        ann1 = (furl1, "storage", "RIStorage", "nick1", "ver23", "ver0")
        ann1b = (furl1, "storage", "RIStorage", "nick1", "ver24", "ver0")
        ca = ClientAdapter_v1(ic)

        ca.remote_announce([ann1])
        connectors = ic._connectors.values()
        self.failUnlessEqual(len(connectors), 1)
        c = connectors[0]
        self.failUnless(c.started)
        self.failIf(c.stopped)
        self.failIf(c.disconnected)
        s = ic.get_all_services()
        self.failUnlessEqual(len(s), 1)
        bo = s[0]["blessed_announcement"].get_leaf()
        self.failUnlessEqual(bo["my-version"], "ver23")

        # now send a duplicate announcement
        ca.remote_announce([ann1])
        connectors = ic._connectors.values()
        self.failUnlessEqual(len(connectors), 1)
        self.failUnlessIdentical(connectors[0], c)
        self.failUnless(c.started)
        self.failIf(c.stopped)
        self.failIf(c.disconnected)
        s = ic.get_all_services()
        self.failUnlessEqual(len(s), 1)
        bo = s[0]["blessed_announcement"].get_leaf()
        self.failUnlessEqual(bo["my-version"], "ver23")

        # and a replacement announcement: same FURL, new other stuff. Since
        # the FURL hasn't changed, the connector should remain the same
        ca.remote_announce([ann1b])
        connectors = ic._connectors.values()
        self.failUnlessEqual(len(connectors), 1)
        self.failUnlessIdentical(connectors[0], c)
        self.failUnless(c.started)
        self.failIf(c.stopped)
        self.failIf(c.disconnected)
        # test that the other stuff changed
        s = ic.get_all_services()
        self.failUnlessEqual(len(s), 1)
        bo = s[0]["blessed_announcement"].get_leaf()
        self.failUnlessEqual(bo["my-version"], "ver24")

    def test_duplicate_receive_v2(self):
        ic1 = NonConnectingIntroducerClient(None,
                                            "introducer.furl", "my_nickname",
                                            "ver23", "oldest_version", {})
        # we use a second client just to create a different-looking
        # announcement
        ic2 = NonConnectingIntroducerClient(None,
                                           "introducer.furl", "my_nickname",
                                           "ver24","oldest_version",{})
        ic1.subscribe_to("storage")
        furl1 = "pb://62ubehyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:36106/gydnp"
        furl1a = "pb://62ubehyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:7777/gydnp"
        furl2 = "pb://ttwwooyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:36106/ttwwoo"

        privkey_vs, pubkey_vs = make_keypair()
        blesser_privkey_vs, blesser_pubkey_vs = make_keypair()
        blesser = bless.PrivateKeyBlesser(privkey_vs, blesser_privkey_vs)

        # ann1: ic1, furl1
        # ann1a: ic1, furl1a (same SturdyRef, different connection hints)
        # ann1b: ic2, furl1
        # ann2: ic2, furl2

        d = ic1.create_announcement(furl1, "storage", "RIStorage", blesser)
        def _created1(ann1):
            self.ann1 = ann1
            return ic1.create_announcement(furl1a, "storage", "RIStorage",
                                           blesser)
        d.addCallback(_created1)
        def _created1a(ann1a):
            self.ann1a = ann1a
            return ic2.create_announcement(furl1, "storage", "RIStorage",
                                           blesser)
        d.addCallback(_created1a)
        def _created1b(ann1b):
            self.ann1b = ann1b
            return ic2.create_announcement(furl2, "storage", "RIStorage",
                                           blesser)
        d.addCallback(_created1b)
        def _created2(ann2):
            self.ann2 = ann2
        d.addCallback(_created2)

        def _ready(res):
            ic1.remote_announce_v2([self.ann1])
            connectors = ic1._connectors.values()
            self.failUnlessEqual(len(connectors), 1)
            c = connectors[0]
            self.failUnless(c.started)
            self.failIf(c.stopped)
            self.failIf(c.disconnected)
            self.failUnlessEqual(c.furl, furl1)
            s = ic1.get_all_services()
            self.failUnlessEqual(len(s), 1)
            bo = s[0]["blessed_announcement"].get_leaf()
            self.failUnlessEqual(bo["my-version"], "ver23")

            # now send a duplicate announcement
            ic1.remote_announce_v2([self.ann1])
            connectors = ic1._connectors.values()
            self.failUnlessEqual(len(connectors), 1)
            self.failUnlessIdentical(connectors[0], c)
            self.failUnless(c.started)
            self.failIf(c.stopped)
            self.failIf(c.disconnected)
            self.failUnlessEqual(c.furl, furl1)
            s = ic1.get_all_services()
            self.failUnlessEqual(len(s), 1)
            bo = s[0]["blessed_announcement"].get_leaf()
            self.failUnlessEqual(bo["my-version"], "ver23")

            # and a replacement announcement: same FURL, new other stuff.
            # Since the FURL hasn't changed, the connector should remain the
            # same
            ic1.remote_announce_v2([self.ann1b])
            connectors = ic1._connectors.values()
            self.failUnlessEqual(len(connectors), 1)
            self.failUnlessIdentical(connectors[0], c)
            self.failUnless(c.started)
            self.failIf(c.stopped)
            self.failIf(c.disconnected)
            self.failUnlessEqual(c.furl, furl1)
            # test that the other stuff changed
            s = ic1.get_all_services()
            self.failUnlessEqual(len(s), 1)
            bo = s[0]["blessed_announcement"].get_leaf()
            self.failUnlessEqual(bo["my-version"], "ver24")

            # and a replacement announcement with a FURL that uses different
            # connection hints. The old connector should be replaced with a
            # new one.
            ic1.remote_announce_v2([self.ann1a])
            connectors = ic1._connectors.values()
            self.failUnlessEqual(len(connectors), 1)
            c2 = connectors[0]
            self.failIfIdentical(c, c2)
            self.failUnless(c.started)
            self.failUnless(c.stopped)
            self.failUnlessEqual(c.furl, furl1)
            self.failUnless(c2.started)
            self.failIf(c2.stopped)
            self.failUnlessEqual(c2.furl, furl1a)
            # test that the other stuff didn't change
            s = ic1.get_all_services()
            self.failUnlessEqual(len(s), 1)
            bo = s[0]["blessed_announcement"].get_leaf()
            self.failUnlessEqual(bo["my-version"], "ver23")

        d.addCallback(_ready)
        return d



class SystemTestMixin(ServiceMixin, pollmixin.PollMixin):

    def setUp(self):
        ServiceMixin.setUp(self)
        self.central_tub = tub = Tub()
        #tub.setOption("logLocalFailures", True)
        #tub.setOption("logRemoteFailures", True)
        tub.setServiceParent(self.parent)
        l = tub.listenOn("tcp:0")
        portnum = l.getPortnum()
        tub.setLocation("localhost:%d" % portnum)

    def do_system_test(self):

        # we have 5 clients who publish themselves as storage servers, and a
        # sixth which does which not. All 6 clients subscribe to hear about
        # storage. When the connections are fully established, all six nodes
        # should have 5 connections each.

        NUM_STORAGE = 5

        clients = []
        tubs = {}
        for i in range(6):
            tub = Tub()
            #tub.setOption("logLocalFailures", True)
            #tub.setOption("logRemoteFailures", True)
            tub.setServiceParent(self.parent)
            l = tub.listenOn("tcp:0")
            portnum = l.getPortnum()
            tub.setLocation("localhost:%d" % portnum)

            n = FakeNode()
            node_furl = tub.registerReference(n)

            log.msg("creating client %d: %s" % (i, tub.getShortTubID()))
            if i == 0:
                c = old.IntroducerClient_V1(tub, self.introducer_furl,
                                            "nickname-%d" % i,
                                            "version", "oldest")
            else:
                c = IntroducerClient(tub, self.introducer_furl,
                                     "nickname-%d" % i,
                                     "version", "oldest",
                                     {"component": "component-v1"})

            if i < NUM_STORAGE:
                if i == 1:
                    # add a blesser
                    privkey_vs, pubkey_vs = make_keypair()
                    blesser = bless.PrivateKeyBlesser(privkey_vs)
                    c.publish(node_furl, "storage", "ri_name", blesser)
                else:
                    c.publish(node_furl, "storage", "ri_name")
            else:
                # the last one does not publish anything
                pass

            if i == 0:
                # the V1 client published a 'stub_client' record (somewhat
                # after it published the 'storage' record), so the introducer
                # could see its version. Match that behavior.
                c.publish(node_furl, "stub_client", "stub_ri_name")

            if i == 2:
                # publish something that nobody cares about
                boring_furl = tub.registerReference(Referenceable())
                c.publish(boring_furl, "boring", "ri_name")

            c.subscribe_to("storage")

            c.setServiceParent(self.parent)
            clients.append(c)
            tubs[c] = tub

        def _wait_for_all_connections():
            for c in clients:
                if len(c.get_all_connections()) < NUM_STORAGE:
                    return False
            return True
        d = self.poll(_wait_for_all_connections)

        def _check1(res):
            log.msg("doing _check1")
            for c in clients:
                self.failUnless(c.connected_to_introducer())
                self.failUnlessEqual(len(c.get_all_connections()), NUM_STORAGE)
                if isinstance(c, old.IntroducerClient_V1):
                    self.failUnlessEqual(len(c.get_all_connectors()),
                                         NUM_STORAGE)
                else:
                    # the get_all_connections() API was amended to take a
                    # for_service_name= argument, but the old one doesn't
                    # have this.
                    self.failUnlessEqual(len(c.get_all_connections("storage")),
                                         NUM_STORAGE)
                    # and get_all_connectors was renamed to get_all_services
                    self.failUnlessEqual(len(c.get_all_services()),
                                         NUM_STORAGE)
                self.failUnlessEqual(len(c.get_all_peerids()), NUM_STORAGE)
                nodeid0 = b32decode(tubs[clients[0]].tubID.upper())
                self.failUnlessEqual(c.get_nickname_for_peerid(nodeid0),
                                     "nickname-0")
                nodeid1 = b32decode(tubs[clients[1]].tubID.upper())
                self.failUnlessEqual(c.get_nickname_for_peerid(nodeid1),
                                     "nickname-1")
            self.check_introducer(self.introducer)
        d.addCallback(_check1)

        origin_c = clients[0]
        def _disconnect_somebody_else(res):
            # now disconnect somebody's connection to someone else
            current_counter = origin_c.counter
            victim_nodeid = b32decode(tubs[clients[1]].tubID.upper())
            log.msg(" disconnecting %s->%s" %
                    (tubs[origin_c].tubID,
                     idlib.shortnodeid_b2a(victim_nodeid)))
            origin_c.debug_disconnect_from_peerid(victim_nodeid)
            log.msg(" did disconnect")

            # then wait until something changes, which ought to be them
            # noticing the loss
            def _compare():
                return current_counter != origin_c.counter
            return self.poll(_compare)

        d.addCallback(_disconnect_somebody_else)

        # and wait for them to reconnect
        d.addCallback(lambda res: self.poll(_wait_for_all_connections))
        def _check2(res):
            log.msg("doing _check2")
            for c in clients:
                self.failUnlessEqual(len(c.get_all_connections()), NUM_STORAGE)
        d.addCallback(_check2)

        origin_c2 = clients[1]
        def _disconnect_yourself(res):
            # now disconnect somebody's connection to themselves.
            current_counter = origin_c2.counter
            victim_nodeid = b32decode(tubs[origin_c2].tubID.upper())
            log.msg(" disconnecting %s->%s" %
                    (tubs[origin_c2].tubID,
                     idlib.shortnodeid_b2a(victim_nodeid)))
            origin_c2.debug_disconnect_from_peerid(victim_nodeid)
            log.msg(" did disconnect from self")

            def _compare():
                return current_counter != origin_c2.counter
            return self.poll(_compare)
        d.addCallback(_disconnect_yourself)

        d.addCallback(lambda res: self.poll(_wait_for_all_connections))
        def _check3(res):
            log.msg("doing _check3")
            for c in clients:
                if isinstance(c, old.IntroducerClient_V1):
                    self.failUnlessEqual(len(c.get_all_connections()),
                                         NUM_STORAGE)
                else:
                    self.failUnlessEqual(len(c.get_all_connections("storage")),
                                         NUM_STORAGE)
        d.addCallback(_check3)
        def _shutdown_introducer(res):
            # now shut down the introducer. We do this by shutting down the
            # tub it's using. Nobody's connections (to each other) should go
            # down. All clients should notice the loss, and no other errors
            # should occur.
            log.msg("shutting down the introducer")
            return self.central_tub.disownServiceParent()
        d.addCallback(_shutdown_introducer)
        def _wait_for_introducer_loss():
            for c in clients:
                if c.connected_to_introducer():
                    return False
            return True
        d.addCallback(lambda res: self.poll(_wait_for_introducer_loss))

        def _check4(res):
            log.msg("doing _check4")
            for c in clients:
                if isinstance(c, old.IntroducerClient_V1):
                    self.failUnlessEqual(len(c.get_all_connections()),
                                         NUM_STORAGE)
                else:
                    self.failUnlessEqual(len(c.get_all_connections("storage")),
                                         NUM_STORAGE)
                self.failIf(c.connected_to_introducer())
        d.addCallback(_check4)
        return d

class SystemTest(SystemTestMixin, unittest.TestCase):

    def test_system(self):
        i = self.introducer = IntroducerService()
        i.setServiceParent(self.parent)
        self.introducer_furl = self.central_tub.registerReference(i)
        return self.do_system_test()

    def check_introducer(self, i):
        anns = i.get_announcements()
        # one 'storage' announcement for each client, plus one 'boring' ann
        NUM_STORAGE = 5
        self.failUnlessEqual(len(anns), NUM_STORAGE+1)
        storage = [bo
                   for (bo,since) in anns
                   if str(bo.get_leaf()["service-name"]) == "storage"]
        self.failUnlessEqual(len(storage), NUM_STORAGE)
        for bo in storage:
            # make sure the v1_to_v2 conversion works
            self.failUnlessEqual(str(bo.get_leaf()["my-version"]), "version")

        boring = [bo
                  for (bo,since) in anns
                  if str(bo.get_leaf()["service-name"]) == "boring"]
        self.failUnlessEqual(len(boring), 1)
        self.failUnlessEqual(boring[0].get_leaf()["nickname"], u"nickname-2")
        self.failUnlessEqual(boring[0].get_leaf()["app-versions"],
                             {u"component": u"component-v1"})

        subs = i.get_subscribers()
        self.failUnlessEqual(len(subs["storage"]), 6)
        self.failUnlessEqual(len(subs.get("boring",{})), 0)
        for (rref, (sinfo, when)) in subs["storage"].items():
            self.failIfEqual(sinfo, None) # should be present for even v1 subs
            self.failUnlessEqual(sinfo["version"], 0)
            self.failUnlessEqual(str(sinfo["my-version"]), "version")
            self.failUnless("nickname" in sinfo)
            # the v1 sub will have an empty app-versions
            if str(sinfo["nickname"]) != "nickname-0":
                self.failUnlessEqual(sinfo["app-versions"],
                                     {u"component": u"component-v1"})


class SystemTestOldIntroducer(SystemTestMixin, unittest.TestCase):

    def test_system_oldserver(self):
        i = self.introducer = old.IntroducerService_V1()
        i.setServiceParent(self.parent)
        self.introducer_furl = self.central_tub.registerReference(i)
        return self.do_system_test()

    def check_introducer(self, i):
        anns = i.get_announcements()
        # one 'storage' announcement for each client, plus one 'boring' ann,
        # plus a 'stub_client' for each normal announcement
        NUM_STORAGE = 5
        self.failUnlessEqual(len(anns), 2*(NUM_STORAGE+1))
        storage = [ann
                   for (index,(ann,when)) in anns.items()
                   if index[1] == "storage"]
        self.failUnlessEqual(len(storage), NUM_STORAGE)
        for ann in storage:
            # make sure the v2_to_v1 conversion works
            (furl, service_name, ri_name, nickname, ver, oldest) = ann
            self.failUnlessEqual(ver, "version")

        boring = [ann
                   for (index,(ann,when)) in anns.items()
                   if index[1] == "boring"]
        self.failUnlessEqual(len(boring), 1)
        (furl, service_name, ri_name, nickname, ver, oldest) = boring[0]
        self.failUnlessEqual(nickname, "nickname-2")

        subs = i.get_subscribers()
        self.failUnlessEqual(len(subs["storage"]), 6)
        self.failUnlessEqual(len(subs.get("boring",{})), 0)

class Blessings(pollmixin.PollMixin, testutil.StallMixin, ServiceMixin,
                unittest.TestCase):

    def setUp(self):
        ServiceMixin.setUp(self)
        self.central_tub = tub = Tub()
        tub.setServiceParent(self.parent)
        l = tub.listenOn("tcp:0")
        portnum = l.getPortnum()
        tub.setLocation("localhost:%d" % portnum)

    def test_blessings(self):
        # 5 servers: two publish announcements blessed with key A, one with
        # key B, one is unblessed, and one is old v1

        # 4 clients: one uses blessing A, one uses blessing B, one uses no
        # blessing, one is old v1

        i = self.introducer = IntroducerService()
        i.setServiceParent(self.parent)
        self.introducer_furl = self.central_tub.registerReference(i)

        self.create_nodes()
        d = self.wait_for_startup()
        # give all the connections a chance to settle
        d.addCallback(self.stall, 1.0)
        d.addCallback(self.check_connections)

        return d

    def create_nodes(self):
        self.servers = []
        self.clients = []
        nodekey0_vs, ignored = make_keypair()
        nodekey1_vs, ignored = make_keypair()
        nodekey2_vs, ignored = make_keypair()
        privkey_vs_a, pubkey_vs_a = make_keypair()
        privkey_vs_b, pubkey_vs_b = make_keypair()

        for i in range(5):
            tub = Tub()
            tub.setServiceParent(self.parent)
            l = tub.listenOn("tcp:0")
            portnum = l.getPortnum()
            tub.setLocation("localhost:%d" % portnum)

            n = FakeNode()
            node_furl = tub.registerReference(n)

            log.msg("creating server %d: %s" % (i, tub.getShortTubID()))
            if i in (0,1,2,3):
                s = IntroducerClient(tub, self.introducer_furl,
                                     "server-%d" % i,
                                     "version", "oldest",
                                     {"component": "component-v1"})
            else:
                s = old.IntroducerClient_V1(tub, self.introducer_furl,
                                            "server-%d" % i,
                                            "version", "oldest")

            if i in (0,):
                # bless with key A
                blesser = bless.PrivateKeyBlesser(nodekey0_vs, privkey_vs_a)
                s.publish(node_furl, "service", "ri_name", blesser)
            elif i in (1,):
                # bless with key A also. Note the nodekey is different.
                blesser = bless.PrivateKeyBlesser(nodekey1_vs, privkey_vs_a)
                s.publish(node_furl, "service", "ri_name", blesser)
            elif i in (2,):
                # bless with key B
                blesser = bless.PrivateKeyBlesser(nodekey2_vs, privkey_vs_b)
                s.publish(node_furl, "service", "ri_name", blesser)
            elif i in (3,):
                # no blessing
                s.publish(node_furl, "service", "ri_name")
            elif i in (4,):
                # old v1 client, no concept of blessing
                s.publish(node_furl, "service", "ri_name")
                # the V1 client published a 'stub_client' record (somewhat
                # after it published the 'storage' record), so the introducer
                # could see its version. Match that behavior.
                s.publish(node_furl, "stub_client", "stub_ri_name")


            s.setServiceParent(self.parent)
            self.servers.append(s)

        for i in range(4):
            tub = Tub()
            tub.setServiceParent(self.parent)
            l = tub.listenOn("tcp:0")
            portnum = l.getPortnum()
            tub.setLocation("localhost:%d" % portnum)

            n = FakeNode()
            node_furl = tub.registerReference(n)

            log.msg("creating client %d: %s" % (i, tub.getShortTubID()))
            if i in (0,1,2):
                c = IntroducerClient(tub, self.introducer_furl,
                                     "client-%d" % i,
                                     "version", "oldest",
                                     {"component": "component-v1"})
            else:
                c = old.IntroducerClient_V1(tub, self.introducer_furl,
                                            "client-%d" % i,
                                            "version", "oldest")

            if i == 0:
                checker = bless.PublicKeyBlessingChecker(pubkey_vs_a)
                c.subscribe_to("service", checker)
            elif i == 1:
                checker = bless.PublicKeyBlessingChecker(pubkey_vs_b)
                c.subscribe_to("service", checker)
            elif i == 2:
                # no blessing required
                c.subscribe_to("service")
            elif i == 3:
                # old v1 client, no concept of blessing. v1 clients publish a
                # 'stub_client' record, do it before the subscription (versus
                # the previous test that does it afterwards) to exercise a
                # different code path
                stub_furl = tub.registerReference(Referenceable())
                c.publish(stub_furl, "stub_client", "stub_ri_name")
                c.subscribe_to("service")

            c.setServiceParent(self.parent)
            self.clients.append(c)

    def wait_for_startup(self):
        # count announcements received
        def check():
            for c in self.clients:
                if c.announcement_counter != 5:
                    return False
            return True
        return self.poll(check, timeout=30)

    def check_connections(self, ign):
        # s0=A, s1=A, s2=B, s3=nil, s4=nil
        # c0=A, c1=B, c2=*, c3=*

        def _getpeers(i):
            return self.clients[i].get_permuted_peers("service", "si")
        def _get_wanted_services(c):
            return [d
                    for d in c.get_all_services()
                    if d["sufficiently_blessed"]]
        cnull = self.clients[0].get_all_services("unknown-service")
        self.failIf(cnull, cnull)
        cnull = self.clients[0].get_all_connections("unknown-service")
        self.failIf(cnull, cnull)
        cnull = self.clients[0].get_acceptable_peers("unknown-service")
        self.failIf(cnull, cnull)

        c0 = _get_wanted_services(self.clients[0])
        self.failUnlessEqual(len(c0), 2)
        self.failUnlessEqual(sorted([c["nickname"] for c in c0]),
                             [u"server-0", u"server-1"])
        self.failUnlessEqual(len(_getpeers(0)), 2)

        c1 = _get_wanted_services(self.clients[1])
        self.failUnlessEqual(len(c1), 1)
        self.failUnlessEqual(sorted([c["nickname"] for c in c1]),
                             [u"server-2"])
        self.failUnlessEqual(len(_getpeers(1)), 1)

        c2 = _get_wanted_services(self.clients[2])
        self.failUnlessEqual(len(c2), 5)
        self.failUnlessEqual(sorted([c["nickname"] for c in c2]),
                             [u"server-0", u"server-1", u"server-2",
                              u"server-3", u"server-4"])
        self.failUnlessEqual(len(_getpeers(2)), 5)

        c3 = self.clients[3].get_all_connectors()
        self.failUnlessEqual(len(c3), 5)
        self.failUnlessEqual(len(_getpeers(3)), 5)

class Upgrade(pollmixin.PollMixin, testutil.StallMixin, ServiceMixin,
              unittest.TestCase):
    # two clients (v1, v2), one server (v1), one introducer. Make sure that
    # upgrading the server from v1 to v2 doesn't result in multiple
    # client-to-server connections.

    def setUp(self):
        ServiceMixin.setUp(self)
        self.central_tub = tub = Tub()
        tub.setServiceParent(self.parent)
        l = tub.listenOn("tcp:0")
        portnum = l.getPortnum()
        tub.setLocation("localhost:%d" % portnum)

    def test_upgrade(self):

        i = self.introducer = IntroducerService()
        i.setServiceParent(self.parent)
        self.introducer_furl = self.central_tub.registerReference(i)

        self.create_nodes()
        d = self.wait_for_startup(1)
        # give all the connections a chance to settle
        d.addCallback(self.stall, 1.0)
        d.addCallback(self.upgrade_server)
        d.addCallback(self.check_connections)

        return d

    def test_upgrade_oldintroducer(self):

        i = self.introducer = old.IntroducerService_V1()
        i.setServiceParent(self.parent)
        self.introducer_furl = self.central_tub.registerReference(i)

        self.create_nodes()
        d = self.wait_for_startup(1)
        # give all the connections a chance to settle
        d.addCallback(self.stall, 1.0)
        d.addCallback(self.upgrade_server)
        d.addCallback(self.check_connections)

        return d

    def create_nodes(self):
        self.clients = []

        self.tubdir = self.mktemp()
        fileutil.make_dirs(self.tubdir)
        tub = Tub(certFile=os.path.join(self.tubdir, "tub.pem"))
        tub.setServiceParent(self.parent)
        l = tub.listenOn("tcp:0")
        portnum = l.getPortnum()
        self.server_portnum = portnum
        tub.setLocation("localhost:%d" % portnum)

        n = FakeNode()
        node_furl = tub.registerReference(n)

        # create the server
        self.server_tub = tub
        self.server = s = old.IntroducerClient_V1(tub, self.introducer_furl,
                                                  "server-0",
                                                  "version", "oldest")

        # old v1 client, no concept of blessing
        s.publish(node_furl, "service", "ri_name")
        # the V1 client published a 'stub_client' record (somewhat
        # after it published the 'storage' record), so the introducer
        # could see its version. Match that behavior.
        s.publish(node_furl, "stub_client", "stub_ri_name")

        s.setServiceParent(self.parent)


        for i in range(2):
            tub = Tub()
            tub.setServiceParent(self.parent)
            l = tub.listenOn("tcp:0")
            portnum = l.getPortnum()
            tub.setLocation("localhost:%d" % portnum)

            n = FakeNode()
            node_furl = tub.registerReference(n)

            log.msg("creating client %d: %s" % (i, tub.getShortTubID()))
            if i == 0:
                c = old.IntroducerClient_V1(tub, self.introducer_furl,
                                            "client-%d" % i,
                                            "version", "oldest")
            else:
                c = IntroducerClient(tub, self.introducer_furl,
                                     "client-%d" % i,
                                     "version", "oldest",
                                     {"component": "component-v1"})

            if i == 0:
                # old v1 client, no concept of blessing. v1 clients publish a
                # 'stub_client' record, do it before the subscription (versus
                # the previous test that does it afterwards) to exercise a
                # different code path
                stub_furl = tub.registerReference(Referenceable())
                c.publish(stub_furl, "stub_client", "stub_ri_name")

            c.subscribe_to("service")

            c.setServiceParent(self.parent)
            self.clients.append(c)

    def wait_for_startup(self, target_count):
        # count announcements received
        def check():
            for c in self.clients:
                if c.announcement_counter != 1:
                    return False
            return True
        return self.poll(check, timeout=30)

    def upgrade_server(self, res):
        # shut down both the IntroducerClient and its Tub, so that the
        # RemoteReferences go down.
        d = defer.maybeDeferred(self.server.disownServiceParent)
        d.addCallback(lambda res: self.server_tub.disownServiceParent())
        def _disconnected(res):
            nodekey_vs, ignored = make_keypair()
            blesskey_vs, ignored = make_keypair()

            # Create a new Tub with the same key and port as the old one
            tub = Tub(certFile=os.path.join(self.tubdir, "tub.pem"))
            tub.setServiceParent(self.parent)
            tub.listenOn("tcp:%d" % self.server_portnum)
            tub.setLocation("localhost:%d" % self.server_portnum)

            s = IntroducerClient(tub, self.introducer_furl,
                                 "server-0",
                                 "version", "oldest",
                                 {"component": "component-v1"})
            blesser = bless.PrivateKeyBlesser(nodekey_vs, blesskey_vs)
            n = FakeNode()
            node_furl = tub.registerReference(n)
            s.publish(node_furl, "service", "ri_name", blesser)
            s.setServiceParent(self.parent)
            return self.wait_for_startup(2)
        d.addCallback(_disconnected)
        d.addCallback(self.stall, 1.0)
        return d

    def check_connections(self, res):
        c0 = self.clients[0].get_all_connections()
        self.failUnlessEqual(len(c0), 1, c0)
        c1 = self.clients[1].get_all_connections()
        self.failUnlessEqual(len(c1), 1, c1)

