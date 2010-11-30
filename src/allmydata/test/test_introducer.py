
import os, re
from base64 import b32decode

from twisted.trial import unittest
from twisted.internet import defer
from twisted.python import log

from foolscap.api import Tub, Referenceable, fireEventually, flushEventualQueue
from twisted.application import service
from allmydata.interfaces import InsufficientVersionError
from allmydata.introducer.client import IntroducerClient, ClientAdapter_v1
from allmydata.introducer.server import IntroducerService
from allmydata.introducer import old
# test compatibility with old introducer .tac files
from allmydata.introducer import IntroducerNode
from allmydata.util import pollmixin, ecdsa
import allmydata.test.common_util as testutil

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
        ic = IntroducerClient(None, "introducer.furl", u"my_nickname",
                              "my_version", "oldest_version", {})
        self.failUnless(isinstance(ic, IntroducerClient))

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



class Client(unittest.TestCase):
    def test_duplicate_receive_v1(self):
        ic = IntroducerClient(None,
                              "introducer.furl", u"my_nickname",
                              "my_version", "oldest_version", {})
        announcements = []
        ic.subscribe_to("storage",
                        lambda nodeid,ann_d: announcements.append(ann_d))
        furl1 = "pb://62ubehyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:36106/gydnpigj2ja2qr2srq4ikjwnl7xfgbra"
        ann1 = (furl1, "storage", "RIStorage", "nick1", "ver23", "ver0")
        ann1b = (furl1, "storage", "RIStorage", "nick1", "ver24", "ver0")
        ca = ClientAdapter_v1(ic)

        ca.remote_announce([ann1])
        d = fireEventually()
        def _then(ign):
            self.failUnlessEqual(len(announcements), 1)
            self.failUnlessEqual(announcements[0]["nickname"], u"nick1")
            self.failUnlessEqual(announcements[0]["my-version"], "ver23")
            self.failUnlessEqual(ic._debug_counts["inbound_announcement"], 1)
            self.failUnlessEqual(ic._debug_counts["new_announcement"], 1)
            self.failUnlessEqual(ic._debug_counts["update"], 0)
            self.failUnlessEqual(ic._debug_counts["duplicate_announcement"], 0)
            # now send a duplicate announcement: this should not notify clients
            ca.remote_announce([ann1])
            return fireEventually()
        d.addCallback(_then)
        def _then2(ign):
            self.failUnlessEqual(len(announcements), 1)
            self.failUnlessEqual(ic._debug_counts["inbound_announcement"], 2)
            self.failUnlessEqual(ic._debug_counts["new_announcement"], 1)
            self.failUnlessEqual(ic._debug_counts["update"], 0)
            self.failUnlessEqual(ic._debug_counts["duplicate_announcement"], 1)
            # and a replacement announcement: same FURL, new other stuff.
            # Clients should be notified.
            ca.remote_announce([ann1b])
            return fireEventually()
        d.addCallback(_then2)
        def _then3(ign):
            self.failUnlessEqual(len(announcements), 2)
            self.failUnlessEqual(ic._debug_counts["inbound_announcement"], 3)
            self.failUnlessEqual(ic._debug_counts["new_announcement"], 1)
            self.failUnlessEqual(ic._debug_counts["update"], 1)
            self.failUnlessEqual(ic._debug_counts["duplicate_announcement"], 1)
            # test that the other stuff changed
            self.failUnlessEqual(announcements[-1]["nickname"], u"nick1")
            self.failUnlessEqual(announcements[-1]["my-version"], "ver24")
        d.addCallback(_then3)
        return d

    def test_duplicate_receive_v2(self):
        ic1 = IntroducerClient(None,
                               "introducer.furl", u"my_nickname",
                               "ver23", "oldest_version", {})
        # we use a second client just to create a different-looking
        # announcement
        ic2 = IntroducerClient(None,
                               "introducer.furl", u"my_nickname",
                               "ver24","oldest_version",{})
        announcements = []
        def _received(nodeid, ann_d):
            announcements.append( (nodeid, ann_d) )
        ic1.subscribe_to("storage", _received)
        furl1 = "pb://62ubehyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:36106/gydnp"
        furl1a = "pb://62ubehyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:7777/gydnp"
        furl2 = "pb://ttwwooyunnyhzs7r6vdonnm2hpi52w6y@127.0.0.1:36106/ttwwoo"

        privkey = ecdsa.SigningKey.generate()
        pubkey = privkey.get_verifying_key()
        pubkey_hex = pubkey.to_string().encode("hex")

        # ann1: ic1, furl1
        # ann1a: ic1, furl1a (same SturdyRef, different connection hints)
        # ann1b: ic2, furl1
        # ann2: ic2, furl2

        self.ann1 = ic1.create_announcement(furl1, "storage", "RIStorage",
                                            privkey)
        self.ann1a =  ic1.create_announcement(furl1a, "storage", "RIStorage",
                                              privkey)
        self.ann1b = ic2.create_announcement(furl1, "storage", "RIStorage",
                                             privkey)
        self.ann2 = ic2.create_announcement(furl2, "storage", "RIStorage",
                                            privkey)

        ic1.remote_announce_v2([self.ann1]) # queues eventual-send
        d = fireEventually()
        def _then1(ign):
            self.failUnlessEqual(len(announcements), 1)
            nodeid,ann_d = announcements[0]
            self.failUnlessEqual(nodeid.encode("hex"), pubkey_hex)
            self.failUnlessEqual(ann_d["FURL"], furl1)
            self.failUnlessEqual(ann_d["my-version"], "ver23")
        d.addCallback(_then1)

        # now send a duplicate announcement. This should not fire the
        # subscriber
        d.addCallback(lambda ign: ic1.remote_announce_v2([self.ann1]))
        d.addCallback(fireEventually)
        def _then2(ign):
            self.failUnlessEqual(len(announcements), 1)
        d.addCallback(_then2)

        # and a replacement announcement: same FURL, new other stuff. The
        # subscriber *should* be fired.
        d.addCallback(lambda ign: ic1.remote_announce_v2([self.ann1b]))
        d.addCallback(fireEventually)
        def _then3(ign):
            self.failUnlessEqual(len(announcements), 2)
            nodeid,ann_d = announcements[-1]
            self.failUnlessEqual(nodeid.encode("hex"), pubkey_hex)
            self.failUnlessEqual(ann_d["FURL"], furl1)
            self.failUnlessEqual(ann_d["my-version"], "ver24")
        d.addCallback(_then3)

        # and a replacement announcement with a different FURL (it uses
        # different connection hints)
        d.addCallback(lambda ign: ic1.remote_announce_v2([self.ann1a]))
        d.addCallback(fireEventually)
        def _then4(ign):
            self.failUnlessEqual(len(announcements), 3)
            nodeid,ann_d = announcements[-1]
            self.failUnlessEqual(nodeid.encode("hex"), pubkey_hex)
            self.failUnlessEqual(ann_d["FURL"], furl1a)
            self.failUnlessEqual(ann_d["my-version"], "ver23")
        d.addCallback(_then4)

        # now add a new subscription, which should be called with the
        # backlog. The introducer only records one announcement per index, so
        # the backlog will only have the latest message.
        announcements2 = []
        def _received2(nodeid, ann_d):
            announcements2.append( (nodeid, ann_d) )
        d.addCallback(lambda ign: ic1.subscribe_to("storage", _received2))
        d.addCallback(fireEventually)
        def _then5(ign):
            self.failUnlessEqual(len(announcements2), 1)
            nodeid,ann_d = announcements2[-1]
            self.failUnlessEqual(nodeid.encode("hex"), pubkey_hex)
            self.failUnlessEqual(ann_d["FURL"], furl1a)
            self.failUnlessEqual(ann_d["my-version"], "ver23")
        d.addCallback(_then5)
        return d

class SystemTestMixin(ServiceMixin, pollmixin.PollMixin):

    def create_tub(self, portnum=0):
        tubfile = os.path.join(self.basedir, "tub.pem")
        self.central_tub = tub = Tub(certFile=tubfile)
        #tub.setOption("logLocalFailures", True)
        #tub.setOption("logRemoteFailures", True)
        tub.setOption("expose-remote-exception-types", False)
        tub.setServiceParent(self.parent)
        l = tub.listenOn("tcp:%d" % portnum)
        self.central_portnum = l.getPortnum()
        if portnum != 0:
            assert self.central_portnum == portnum
        tub.setLocation("localhost:%d" % self.central_portnum)

class SystemTest(SystemTestMixin, unittest.TestCase):

    def do_system_test(self, create_introducer, check_introducer):
        self.create_tub()
        introducer = create_introducer()
        introducer.setServiceParent(self.parent)
        iff = os.path.join(self.basedir, "introducer.furl")
        tub = self.central_tub
        ifurl = self.central_tub.registerReference(introducer, furlFile=iff)
        self.introducer_furl = ifurl

        # we have 5 clients who publish themselves as storage servers, and a
        # sixth which does which not. All 6 clients subscriber to hear about
        # storage. When the connections are fully established, all six nodes
        # should have 5 connections each.
        self.NUM_STORAGE = 5
        self.NUM_CLIENTS = 6

        clients = []
        tubs = {}
        received_announcements = {}
        subscribing_clients = []
        publishing_clients = []
        privkeys = {}

        for i in range(self.NUM_CLIENTS):
            tub = Tub()
            #tub.setOption("logLocalFailures", True)
            #tub.setOption("logRemoteFailures", True)
            tub.setOption("expose-remote-exception-types", False)
            tub.setServiceParent(self.parent)
            l = tub.listenOn("tcp:0")
            portnum = l.getPortnum()
            tub.setLocation("localhost:%d" % portnum)

            log.msg("creating client %d: %s" % (i, tub.getShortTubID()))
            if i == 0:
                c = old.IntroducerClient_v1(tub, self.introducer_furl,
                                            u"nickname-%d" % i,
                                            "version", "oldest")
            else:
                c = IntroducerClient(tub, self.introducer_furl,
                                     u"nickname-%d" % i,
                                     "version", "oldest",
                                     {"component": "component-v1"})
            received_announcements[c] = {}
            def got(serverid, ann_d, announcements):
                announcements[serverid] = ann_d
            c.subscribe_to("storage", got, received_announcements[c])
            subscribing_clients.append(c)

            node_furl = tub.registerReference(Referenceable())
            if i < self.NUM_STORAGE:
                if i == 1:
                    # sign the announcement
                    privkey = privkeys[c] = ecdsa.SigningKey.generate()
                    c.publish(node_furl, "storage", "ri_name", privkey)
                else:
                    c.publish(node_furl, "storage", "ri_name")
                publishing_clients.append(c)
            else:
                # the last one does not publish anything
                pass

            if i == 0:
                # the V1 client published a 'stub_client' record (somewhat
                # after it published the 'storage' record), so the introducer
                # could see its version. Match that behavior.
                c.publish(node_furl, "stub_client", "stub_ri_name")

            if i == 2:
                # also publish something that nobody cares about
                boring_furl = tub.registerReference(Referenceable())
                c.publish(boring_furl, "boring", "ri_name")

            c.setServiceParent(self.parent)
            clients.append(c)
            tubs[c] = tub

        # we can't really know when a live system is idle: there may be a
        # message on the wire. If we shut down the Tub, we can know (i.e.
        # dead==stable). But until then, the best we can do is figure out
        # which messages are supposed to be sent, identify a way to measure
        # when they've been received, and poll until those measurements
        # report completion.

        def _wait_until_clients_are_idle(ign):
            def _clients_are_idle():
                for c in subscribing_clients + publishing_clients:
                    if c._debug_outstanding:
                        return False
                if introducer._debug_outstanding:
                    return False
                return True
            return self.poll(_clients_are_idle)

        d = defer.succeed(None)

        def _wait_for_all_connections(ign):
            def _got_all_connections():
                for c in subscribing_clients:
                    if len(received_announcements[c]) < self.NUM_STORAGE:
                        return False
                return True
            return self.poll(_got_all_connections)
        d.addCallback(_wait_for_all_connections)
        d.addCallback(_wait_until_clients_are_idle)

        def _check1(res):
            log.msg("doing _check1")
            check_introducer(introducer)

            for c in clients:
                self.failUnless(c.connected_to_introducer())
            for c in subscribing_clients:
                cdc = c._debug_counts
                self.failUnless(cdc["inbound_message"])
                self.failUnlessEqual(cdc["inbound_announcement"],
                                     self.NUM_STORAGE)
                self.failUnlessEqual(cdc["wrong_service"], 0)
                self.failUnlessEqual(cdc["duplicate_announcement"], 0)
                self.failUnlessEqual(cdc["update"], 0)
                self.failUnlessEqual(cdc["new_announcement"],
                                     self.NUM_STORAGE)
                anns = received_announcements[c]
                self.failUnlessEqual(len(anns), self.NUM_STORAGE)

                nodeid0 = b32decode(tubs[clients[0]].tubID.upper())
                ann_d = anns[nodeid0]
                nick = ann_d["nickname"]
                self.failUnlessEqual(type(nick), unicode)
                self.failUnlessEqual(nick, u"nickname-0")
            for c in publishing_clients:
                cdc = c._debug_counts
                expected = 1
                if c in [clients[0], # stub_client
                         clients[2], # boring
                         ]:
                    expected = 2
                self.failUnlessEqual(cdc["outbound_message"], expected)
            log.msg("_check1 done")
        d.addCallback(_check1)

        # force an introducer reconnect, by shutting down the Tub it's using
        # and starting a new Tub (with the old introducer). Everybody should
        # reconnect and republish, but the introducer should ignore the
        # republishes as duplicates. However, because the server doesn't know
        # what each client does and does not know, it will send them a copy
        # of the current announcement table anyway.

        d.addCallback(lambda _ign: log.msg("shutting down introducer's Tub"))
        d.addCallback(lambda _ign: self.central_tub.disownServiceParent())

        def _wait_for_introducer_loss(ign):
            def _introducer_lost():
                for c in clients:
                    if c.connected_to_introducer():
                        return False
                return True
            return self.poll(_introducer_lost)
        d.addCallback(_wait_for_introducer_loss)

        def _restart_introducer_tub(_ign):
            log.msg("restarting introducer's Tub")

            dc = introducer._debug_counts
            self.expected_count = dc["inbound_message"] + self.NUM_STORAGE+2
            self.expected_subscribe_count = dc["inbound_subscribe"] + self.NUM_CLIENTS
            introducer._debug0 = dc["outbound_message"]
            for c in subscribing_clients:
                cdc = c._debug_counts
                c._debug0 = cdc["inbound_message"]

            self.create_tub(self.central_portnum)
            newfurl = self.central_tub.registerReference(introducer,
                                                         furlFile=iff)
            assert newfurl == self.introducer_furl
        d.addCallback(_restart_introducer_tub)

        def _wait_for_introducer_reconnect():
            # wait until:
            #  all clients are connected
            #  the introducer has received publish messages from all of them
            #  the introducer has received subscribe messages from all of them
            #  the introducer has sent (duplicate) announcements to all of them
            #  all clients have received (duplicate) announcements
            dc = introducer._debug_counts
            for c in clients:
                if not c.connected_to_introducer():
                    return False
            if dc["inbound_message"] < self.expected_count:
                return False
            if dc["inbound_subscribe"] < self.expected_subscribe_count:
                return False
            for c in subscribing_clients:
                cdc = c._debug_counts
                if cdc["inbound_message"] < c._debug0+1:
                    return False
            return True
        d.addCallback(lambda res: self.poll(_wait_for_introducer_reconnect))
        d.addCallback(lambda _ign: log.msg(" reconnected"))
        d.addCallback(_wait_until_clients_are_idle)

        def _check2(res):
            log.msg("doing _check2")
            # assert that the introducer sent out new messages, one per
            # subscriber
            dc = introducer._debug_counts
            self.failUnlessEqual(dc["inbound_message"], 2*(self.NUM_STORAGE+2))
            # the stub_client announcement does not count as a duplicate
            self.failUnlessEqual(dc["inbound_duplicate"], self.NUM_STORAGE+1)
            self.failUnlessEqual(dc["inbound_update"], 0)
            self.failUnlessEqual(dc["outbound_message"],
                                 introducer._debug0 + len(subscribing_clients))
            for c in clients:
                self.failUnless(c.connected_to_introducer())
            for c in subscribing_clients:
                cdc = c._debug_counts
                self.failUnlessEqual(cdc["duplicate_announcement"], self.NUM_STORAGE)
        d.addCallback(_check2)

        # Then force an introducer restart, by shutting down the Tub,
        # destroying the old introducer, and starting a new Tub+Introducer.
        # Everybody should reconnect and republish, and the (new) introducer
        # will distribute the new announcements, but the clients should
        # ignore the republishes as duplicates.

        d.addCallback(lambda _ign: log.msg("shutting down introducer"))
        d.addCallback(lambda _ign: self.central_tub.disownServiceParent())
        d.addCallback(_wait_for_introducer_loss)
        d.addCallback(lambda _ign: log.msg("introducer lost"))

        def _restart_introducer(_ign):
            log.msg("restarting introducer")
            self.create_tub(self.central_portnum)

            for c in subscribing_clients:
                # record some counters for later comparison. Stash the values
                # on the client itself, because I'm lazy.
                cdc = c._debug_counts
                c._debug1 = cdc["inbound_announcement"]
                c._debug2 = cdc["inbound_message"]
                c._debug3 = cdc["new_announcement"]
            newintroducer = create_introducer()
            self.expected_message_count = self.NUM_STORAGE+2
            self.expected_announcement_count = self.NUM_STORAGE*self.NUM_CLIENTS
            self.expected_subscribe_count = self.NUM_CLIENTS
            newfurl = self.central_tub.registerReference(newintroducer,
                                                         furlFile=iff)
            assert newfurl == self.introducer_furl
        d.addCallback(_restart_introducer)

        def _wait_for_introducer_reconnect2():
            # wait until:
            #  all clients are connected
            #  the introducer has received publish messages from all of them
            #  the introducer has received subscribe messages from all of them
            #  the introducer has sent announcements for everybody to everybody
            #  all clients have received all the (duplicate) announcements
            # at that point, the system should be quiescent
            dc = introducer._debug_counts
            for c in clients:
                if not c.connected_to_introducer():
                    return False
            if dc["inbound_message"] < self.expected_message_count:
                return False
            if dc["outbound_announcements"] < self.expected_announcement_count:
                return False
            if dc["inbound_subscribe"] < self.expected_subscribe_count:
                return False
            for c in subscribing_clients:
                cdc = c._debug_counts
                if cdc["inbound_announcement"] < c._debug1+self.NUM_STORAGE:
                    return False
            return True
        d.addCallback(lambda res: self.poll(_wait_for_introducer_reconnect2))
        d.addCallback(_wait_until_clients_are_idle)

        def _check3(res):
            log.msg("doing _check3")
            for c in clients:
                self.failUnless(c.connected_to_introducer())
            for c in subscribing_clients:
                cdc = c._debug_counts
                self.failUnless(cdc["inbound_announcement"] > c._debug1)
                self.failUnless(cdc["inbound_message"] > c._debug2)
                # there should have been no new announcements
                self.failUnlessEqual(cdc["new_announcement"], c._debug3)
                # and the right number of duplicate ones. There were
                # NUM_STORAGE from the servertub restart, and there should be
                # another NUM_STORAGE now
                self.failUnlessEqual(cdc["duplicate_announcement"],
                                     2*self.NUM_STORAGE)

        d.addCallback(_check3)
        return d


    def test_system(self):
        self.basedir = "introducer/SystemTest/system"
        os.makedirs(self.basedir)
        return self.do_system_test(IntroducerService, self.check_introducer)
    test_system.timeout = 480 # occasionally takes longer than 350s on "draco"

    def check_introducer(self, introducer):
        dc = introducer._debug_counts
        # each storage server publishes a record, plus a "stub_client"
        # and a "boring"
        self.failUnlessEqual(dc["inbound_message"], self.NUM_STORAGE+2)
        self.failUnlessEqual(dc["inbound_duplicate"], 0)
        self.failUnlessEqual(dc["inbound_update"], 0)
        self.failUnlessEqual(dc["inbound_subscribe"], self.NUM_CLIENTS)
        # the number of outbound messages is tricky.. I think it depends
        # upon a race between the publish and the subscribe messages.
        self.failUnless(dc["outbound_message"] > 0)
        # each client subscribes to "storage", and each server publishes
        self.failUnlessEqual(dc["outbound_announcements"],
                             self.NUM_STORAGE*self.NUM_CLIENTS)

class TooNewServer(IntroducerService):
    VERSION = { "http://allmydata.org/tahoe/protocols/introducer/v999":
                 { },
                "application-version": "greetings from the crazy future",
                }

class NonV1Server(SystemTestMixin, unittest.TestCase):
    # if the 1.3.0 client connects to a server that doesn't provide the 'v1'
    # protocol, it is supposed to provide a useful error instead of a weird
    # exception.

    def test_failure(self):
        self.basedir = "introducer/NonV1Server/failure"
        os.makedirs(self.basedir)
        self.create_tub()
        i = TooNewServer()
        i.setServiceParent(self.parent)
        self.introducer_furl = self.central_tub.registerReference(i)

        tub = Tub()
        tub.setOption("expose-remote-exception-types", False)
        tub.setServiceParent(self.parent)
        l = tub.listenOn("tcp:0")
        portnum = l.getPortnum()
        tub.setLocation("localhost:%d" % portnum)

        c = IntroducerClient(tub, self.introducer_furl,
                             u"nickname-client", "version", "oldest", {})
        announcements = {}
        def got(serverid, ann_d):
            announcements[serverid] = ann_d
        c.subscribe_to("storage", got)

        c.setServiceParent(self.parent)

        # now we wait for it to connect and notice the bad version

        def _got_bad():
            return bool(c._introducer_error) or bool(c._publisher)
        d = self.poll(_got_bad)
        def _done(res):
            self.failUnless(c._introducer_error)
            self.failUnless(c._introducer_error.check(InsufficientVersionError))
        d.addCallback(_done)
        return d

class DecodeFurl(unittest.TestCase):
    def test_decode(self):
        # make sure we have a working base64.b32decode. The one in
        # python2.4.[01] was broken.
        furl = 'pb://t5g7egomnnktbpydbuijt6zgtmw4oqi5@127.0.0.1:51857/hfzv36i'
        m = re.match(r'pb://(\w+)@', furl)
        assert m
        nodeid = b32decode(m.group(1).upper())
        self.failUnlessEqual(nodeid, "\x9fM\xf2\x19\xcckU0\xbf\x03\r\x10\x99\xfb&\x9b-\xc7A\x1d")


# add tests of StorageFarmBroker: if it receives duplicate announcements, it
# should leave the Reconnector in place, also if it receives
# same-FURL-different-misc, but if it receives same-nodeid-different-FURL, it
# should tear down the Reconnector and make a new one. This behavior used to
# live in the IntroducerClient, and thus used to be tested by test_introducer

# copying more tests from old branch:

#  update do_system_test() to include one (i==0) old.IntroducerClient_V1, and
#  to have one signed publisher (i==1), and to have one client publish
#  something that nobody cares about (i==2). Run it twice, once with a new
#  introducer, and again with an old introducer.

#  then also add Upgrade test
