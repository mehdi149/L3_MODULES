#!/usr/bin/env python

"""A Python implementation of RIPv2."""


import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER 
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3 , ofproto_v1_2
from ryu.ofproto import ofproto_v1_0, nx_match
from ryu.ofproto import ether, inet
from ryu.lib.packet import (packet, ethernet, arp, icmp, icmpv6, ipv4, ipv6,udp)
from ryu.lib import mac
from ryu.lib import dpid as dpid_lib
from ryu.lib import port_no as portno_lib
from ryu.lib import ofctl_v1_0
from ryu.topology import switches
from ryu.topology import event
import netaddr
from ryu.topology.api import get_all_switch, get_all_link, get_switch, get_link
import router
import copy
import gevent, gevent.server
from telnetsrv.green import TelnetHandler, command
import thread
from multiprocessing import Process
import serveur
from threading import Thread
import threading
from ryu.lib import hub
import os

FORMAT = '%(name)s[%(levelname)s]%(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)

import struct
import sys
import optparse
import binascii
import logging
import logging.config
import random
import datetime
import traceback
import functools
import logging

FORMAT = '%(name)s[%(levelname)s]%(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)

try:
    import ipaddr
    from twisted.internet import protocol
    from twisted.internet import reactor
    from twisted.python import log
    import twisted.python.failure
except ImportError:
    sys.stderr.write("ERROR: Could not find all required libraries. See the System Setup section on this page: %s" % "http://code.google.com/p/python-ripv2/wiki/UsingPythonRIPv2\n")
    sys.stderr.write("Exception was:\n")
    raise


import util
class RIP(protocol.DatagramProtocol,app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    """An implementation of RIPv2 using the twisted asynchronous networking
    framework."""

    MAX_ROUTES_PER_UPDATE = 25
    JITTER_VALUE = 2
    DEFAULT_UPDATE_TIMER = 30

    def __init__(self, port,sys, user_routes=None
                 ,requested_ifaces=None, log_config="logging.conf",
                 base_timer=None):
        """port -- The UDP port to listen and send on.
        user_routes -- A list of routes to advertise.
        router_obj -- Contain routing table and list of interfaces.
        requested_ifaces -- A list of interface names to send updates out of.
            If None, use all interfaces.
        log_config -- The logging config file.
        base_timer -- Influences update/garbage/timeout timers"""
        #self.init_logging(log_config)
        #self.log.info("RIP is starting up...")
        logger.info('RIP is starting up...')
        self._suppress_triggered_updates = False
        
        suppress_reactor_not_running = functools.partial(util.suppress_reactor_not_running, logfunc=logger.info)
        log.addObserver(suppress_reactor_not_running)

        if not base_timer:
            base_timer = self.DEFAULT_UPDATE_TIMER

        self.update_timer = base_timer
        self.garbage_timer = base_timer * 4
        self.timeout_timer = base_timer * 6
       
        logger.info('Using timers: Update: %d, gc: %d, timeout: %d',self.update_timer, self.garbage_timer,
                        self.timeout_timer)

        self._route_change = False
        self._gc_started = False
         
        '''if sys.platform == "linux2":
            self.sys = sysiface.LinuxSystem(log_config=log_config)
        elif sys.platform.startswith("win"):
            self.sys = sysiface.WindowsSystem(log_config=log_config)
        else:
            raise(NotSupported("No support for current OS."))'''
       
        self.sys=sys
        self.port = port
        self._routes = []

        # Nexthop of 0.0.0.0 tells receivers to use the source IP on the
        # packet for the nexthop address. See RFC 2453 section 4.4.
        nexthop = "0.0.0.0"

        if user_routes:
            metric = 1
            tag = 0

            for route in user_routes:
                parsed_rt = ipaddr.IPv4Network(route)
                rte = RIPRouteEntry(address=parsed_rt.ip.exploded,
                                    mask=parsed_rt.netmask.exploded,
                                    nexthop=nexthop,
                                    metric=metric,
                                    tag=tag,
                                    imported=True)
                #self.log.debug5("Trying to add user route %s" % rte)
                logger.info("Trying to add user route %s",rte)
                self.try_add_route(rte, nexthop, False)

        for net_mask,entry in self.sys.get_local_routes(proto='RIP').iteritems():
            # Windows includes all local routes, including /32 routes
            # for local interfaces, in its main routing table. Filter
            # most of those out.
            logger.info("route finded in local router (%s,%s)",net_mask[0],net_mask[1])
            net = net_mask[0]
            mask = net_mask[1]
            next_hop = entry.gw
            metric = entry.metric
            rte = RIPRouteEntry(address=net,
                                    mask=mask,
                                    nexthop=next_hop,
                                    metric=metric,
                                    tag=0,
                                    imported=True)
            self.try_add_route(rte, nexthop, False)

        self.activate_ifaces(requested_ifaces)
        self._last_update_time = datetime.datetime.now()


        # reactor and timer
      
        #new_pid=os.fork()
        self.generate_periodic_update()
        self._check_route_timeouts()
        self.send_request()
        #gevent.spawn(reactor.run())
        #reactor.listenMulticast(port, self)
        #hub.spawn(reactor.run())

    def send_request(self):
        """Send a multicast request message out of each active interface."""
        logger.info("Send Request: get_active_ifaces")
        hdr = RIPHeader(cmd=RIPHeader.TYPE_REQUEST, ver=2)
        rte = [ RIPRouteEntry(afi=0, address="0.0.0.0", mask=0, tag=0,
                 metric=RIPRouteEntry.MAX_METRIC, nexthop="0.0.0.0") ]
        request = RIPPacket(hdr=hdr, rtes=rte).serialize()

        for iface in self.get_active_ifaces():
            self.send_update(request, iface.ip_addr)

    def stopProtocol(self):
        logger.info("RIP is shutting down.")
        self.cleanup()

    def _act_on_routes_before_time(self, action, cond, timer):
        """Take an action on a route if its timeout is less than a given time.
        Doesn't count routes that don't meet the given condition (cond) or
        if their timeout is set to None.

        timer is a number of seconds that will determine when the next call
        time should be.

        Returns the next time this function should be called based on the
        rt.timeout values, or returns None if no values were greater than
        timer."""
        logger.info("#####################Actes On Routes Before Time##############################")
        now = datetime.datetime.now()
        timeout_delta = datetime.timedelta(seconds=timer)
        before_time = now - timeout_delta
        lowest_timer = before_time

        for rt in self._routes:
            if not cond(rt):
                continue
            if rt.timeout == None:
                continue

            if rt.timeout < before_time:
                logger.info("garbage collect")
                action(rt)
            else:
                lowest_timer = max(lowest_timer, rt.timeout)

        if lowest_timer == before_time:
            return None
        else:
            return (lowest_timer + timeout_delta - now).total_seconds() + 1

    def _start_garbage_collection(self, rt):
        if rt.garbage:
            #self.log.debug2("Route was already on GC: %s" % rt)
            logger.info("Route was already on GC: %s",rt)
            
            return

        #self.log.debug2("Starting garbage collection for route %s" % rt)
        logger.info("Starting garbage collection for route %s",rt)
        rt.changed = True
        rt.garbage = True
        rt.init_timeout()
        rt.metric = RIPRouteEntry.MAX_METRIC
        self.sys.modify_route(rt)
        self._route_change = True
        self._init_garbage_collection_timer()

    def _check_route_timeouts(self):
        #self.log.debug2("Checking route timeouts...")
        logger.info("Checking route timeouts...")
        action = self._start_garbage_collection
        cond = lambda x: not x.garbage

        next_call_time = self._act_on_routes_before_time(action, cond,
                                              self.timeout_timer)
        logger.info("Next Call TIME : %s ",next_call_time)
        if self._route_change:
            self._send_triggered_update()

        if not next_call_time:
            next_call_time = self.timeout_timer

        #self.log.debug2("Checking timeouts again in %d second(s)" % next_call_time)
        logger.info("Checking timeouts again in %d second(s)",next_call_time)
        threading.Timer(next_call_time, self._check_route_timeouts).start() 
        #reactor.callLater(next_call_time, self._check_route_timeouts)

    def _init_garbage_collection_timer(self):
        if self._gc_started:
            return
        self._gc_started = True
        threading.Timer(self.garbage_timer,self._collect_garbage_routes).start() 
        #reactor.callLater(self.garbage_timer, self._collect_garbage_routes)

    def _collect_garbage_routes(self):
        #self.log.debug2("Collecting garbage routes...")
        logger.info("Collecting garbage routes...")
        action = lambda x: setattr(x, "marked_for_deletion", True)
        cond = lambda x: x.garbage

        # XXX FIXME GC's next_call_time is 1 second when there is a group
        # of routes to be deleted. Fix this so it will be lenient enough to
        # encompass the whole group if possible.
        next_call_time = self._act_on_routes_before_time(action, cond,
                                               self.garbage_timer)

        # Check for deletion flag and *safely* delete those routes
        for rt in self._routes[:]:
            if rt.marked_for_deletion:
                self._uninstall_route(rt)

        if not next_call_time:
            #self.log.debug2("No more routes on GC.")
            logger.info("No more routes on GC.")
            self._gc_started = False
        else:
            self.log.debug2("GC running again in %d second(s)" %
                            next_call_time)
            threading.Timer(next_call_time,self._collect_garbage_routes).start() 
            #reactor.callLater(next_call_time, self._collect_garbage_routes)

    def _uninstall_route(self, rt):
        #self.log.debug2("Deleting route: %s" % rt)
        logger.info("Deleting route: %s",rt)
        self.sys.uninstall_route(rt.network.ip.exploded, rt.network.prefixlen)
        self._routes.remove(rt)

    def init_logging(self, log_config):
        # debug1 is less verbose, debug5 is more verbose.
        for (level, name) in [ (10, "DEBUG1"),
                               (9,  "DEBUG2"),
                               (8,  "DEBUG3"),
                               (7,  "DEBUG4"),
                               (6,  "DEBUG5"),
                             ]:
            util.create_new_log_level(level, name)

        logging.config.fileConfig(log_config, disable_existing_loggers=True)
        self.log = logging.getLogger("RIP")

    def activate_ifaces(self, requested_ifaces):
        """Enable RIP processing on the given IPs/interfaces.
        requested_ifaces -- A list of IP addresses to use"""
        if not requested_ifaces:
            raise(ValueError("Need one or more interface IPs to listen on."))

        for req_iface in requested_ifaces:
            activated_iface = False
            logger.info("request interface : %s type: %s", req_iface , type(req_iface))
            for index,port in self.sys.ports.iteritems():
                logger.info("request interface : %s type: %s", req_iface , type(req_iface))
                if req_iface == port.ip_addr:
                    port.proto_active = 'RIP'
                    activated_iface = True
                    break
            if activated_iface == False:
                raise(ValueError("Requested IP %s is unusable. "
                      " (Is it assigned to this machine on an interface that "
                      "is 'up'?)" % req_iface))

    '''def startProtocol(self):
        for port in self.sys.ports:
            if port.proto_active='RIP':
                # send igmp report group
                self.transport.joinGroup("224.0.0.9",port.ip_addr)'''

    def generate_update(self, triggered=False, ifaces=None,
                        dst_ip="224.0.0.9", dst_port=None, split_horizon=True):
        logger.info("Send an update message across the network.")
        if not dst_port:
            dst_port = self.port

        self._last_update_time = datetime.datetime.now()
        logger.info("Sending an update. Triggered = %s.",triggered)
        hdr = RIPHeader(cmd=RIPHeader.TYPE_RESPONSE, ver=2).serialize()

        if not ifaces:
            logger.info("get all active iface")
            ifaces_to_use = [iface for iface in self.get_active_ifaces()]
            print ifaces_to_use
            logger.info("length interface to use %s :",len(ifaces_to_use))
        else:
            ifaces_to_use = ifaces

        for iface in ifaces_to_use:
            msg = hdr
            #self.log.debug4("Preparing update for interface %s" %iface.phy_iface.name)
            logger.info("Preparing update for interface %s",iface.name)
            route_count = 0
            logger.info("Number Of routes : %s",len(self._routes))
            for rt in self._routes:
                logger.info("Trying to add route to update: %s.",rt)
                
                if split_horizon and rt.nexthop in ipaddr.IPv4Network(iface.ip_addr):
                    logger.info("Split horizon prevents sending route.")
                    continue
                if triggered and not rt.changed:
                    logger.info("Route not changed. Skipping.")
                    continue

                # Use 0.0.0.0 as the nexthop unless the nexthop router is
                # a different router on the same subnet. Since split horizon
                # is always used, this should only happen when a route is
                # imported by this RIP process in a manner that is not
                # currently implemented -- all imported routes are given
                # a nexthop of 0.0.0.0.
                saved_nexthop = rt.nexthop.exploded
                if rt.nexthop in ipaddr.IPv4Network(iface.ip_addr) and \
                   rt.nexthop != ipaddr.IPv4Network(iface.ip_addr):
                    logger.info("NOT Adding route to update.")
                    nexthop = rt.nexthop.exploded
                else:
                    
                    nexthop = "0.0.0.0"
                rt.set_nexthop(nexthop)
                msg += rt.serialize()
                rt.set_nexthop(saved_nexthop)
                logger.info("Adding route to update.")
                route_count += 1
                if route_count == self.MAX_ROUTES_PER_UPDATE:
                    logger.info("Max routes per update reached."
                                   " Sending an update...")
                    logger.info("Adding route to update 2.")
                    self.send_update(msg, iface.ip_addr,
                                     dst_ip, dst_port)
                    msg = hdr
                    route_count = 0

            if len(msg) > RIPHeader.SIZE:
                self.send_update(msg, iface.ip_addr, dst_ip, dst_port)

        if triggered:
            for rt in self._routes:
                rt.changed = False
    # reactor and timer
    def generate_periodic_update(self):
        self.generate_update()
        threading.Timer(self.get_update_interval(), self.generate_periodic_update).start() 
        #reactor.callLater(self.get_update_interval(),self.generate_periodic_update)
    # reactor and timer
    def get_update_interval(self):
        """Get the amount of time until the next update. This is equal to
        the default update timer +/- a number of a seconds to create update
        jitter."""
        return self.update_timer + random.randrange(-self.JITTER_VALUE,
                                                     self.JITTER_VALUE)

    def get_active_ifaces(self):
        """Return active logical interfaces."""
        logger.info("length self.sys.ports : %s",len(self.sys.ports))
        for index,port in self.sys.ports.iteritems():
            
            if port.proto_active == 'RIP':
                logger.info("return port : %s",port.name)
                yield port

    def send_update(self, msg, src_iface_ip, dst_ip="224.0.0.9",
                    dst_port=None):
        if not dst_port:
            dst_port = self.port
        # send ofpacket out
        logger.info("send update from %s",src_iface_ip)
        in_port_no,port = self.sys.get_port_by_ip(src_iface_ip)
        eth_src=port.mac_addr
        eth_dest= '01:00:5e:00:00:09'
     
        e = ethernet.ethernet(dst = eth_dest, src = eth_src,
                                ethertype = ether.ETH_TYPE_IP)
        pkt_ipv4 = ipv4.ipv4(dst=dst_ip,
                     src=src_iface_ip,
                     proto=inet.IPPROTO_UDP)
        udp_pkt = udp.udp(src_port=dst_port, dst_port=dst_port, total_length=0, csum=0)
        
        datapath = self.sys.datapath
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(pkt_ipv4)
        p.add_protocol(udp_pkt)
        p.add_protocol(msg)
        print vars(p)
        p.serialize()
        print p
        #p+=msg
        data = p.data
        print in_port_no
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port_no)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data) 
        logger.info("sended packet")
        datapath.send_msg(out)
        #self.transport.setOutgoingInterface(src_iface_ip)
        #self.transport.write(msg, (dst_ip, dst_port))

    def datagramReceived(self, data, host_and_port):
        host = host_and_port[0]
        port = host_and_port[1]
        logger.info("port gived is %s",port)
        logger.info("Processing a datagram from host %s.", host)
        link_local = False
        host_local = False
        #host = ipaddr.IPv4Address(host)
        for index,port in self.sys.ports.iteritems():
            link_local = True
            #if host in port.ip_addr:
                #link_local = True
            if port.ip_addr == host:
                host_local = True
            if host_local or link_local:
                local_iface=port
                break
        port = host_and_port[1]
        if not link_local:
            logger.info("Ignoring advertisement from non link-local host.")
            return

        if host_local:
            logger.info("Ignoring message from local system.")
            return

        try:
            msg = RIPPacket(data=data, src_ip=host)
            logger.info(msg)
        except FormatException:
            logger.info("RIP packet with invalid format received.")
            logger.info("Hex dump:")
            logger.info(binascii.hexlify(data))
            logger.info("Traceback:")
            logger.info(traceback.format_exc())
            return

        if msg.hdr.cmd == RIPHeader.TYPE_REQUEST:
            logger.info("process request")
            self.process_request(msg, host, port, local_iface)
        elif msg.hdr.cmd == RIPHeader.TYPE_RESPONSE:
            logger.info("Port_gived : %s Self.port : %s",port,self.port)
            if port != self.port:
                logger.info("Advertisement source port was not the RIP "
                               "port. Ignoring.")
                return
            self.process_response(msg, host)
        else:
            logger.info("Received a packet with a command field that was "
                          "not REQUEST or RESPONSE from %s:%d. Command = %d",
                           (host, port, msg.hdr.cmd))
            return

    def process_request(self, msg, host, port, local_iface):
        # See RFC 2453 section 3.9.1
        if not msg.rtes:
            return
        elif len(msg.rtes) == 1   and \
             msg.rtes[0].afi == 0 and \
             msg.rtes[0].metric == RIPRouteEntry.MAX_METRIC:
            self._send_whole_response(host, port, local_iface)
        else:
            self._send_partial_response(host, port, msg)

    def _send_whole_response(self, host, port, local_iface):
        """Provide the metric and nexthop address for known routes. Split
        horizon processing is performed. This is the "whole-table" case from
        RFC 2453 section 3.9.1."""
        self.generate_update(ifaces=[local_iface], dst_ip=host,
                             dst_port=port)

    def _send_partial_response(self, host, port, msg):
        """Provide the metric and nexthop address for every RTE in msg. No
        split horizon is performed. This is the "specific" case from RFC 2453
        section 3.9.1."""
        logger.info("send partial response")
        for rt in msg.rtes:
            matching_rt = self.get_route(rt.network.ip.exploded,
                                         rt.network.netmask.exploded)
            if not matching_rt:
                rt.metric = RIPRouteEntry.MAX_METRIC
            else:
                rt.metric = matching_rt.metric

        msg.hdr.cmd = RIPHeader.TYPE_RESPONSE
             # send ofpacket out
        in_port_no,port = self.sys.get_port_by_ip(src_iface_ip)
        eth_src=port.mac_addr
        eth_dest= '01:00:5e:00:00:09'
     
        e = ethernet.ethernet(dst = eth_dst, src = eth_src,
                                ethertype = ether.ETH_TYPE_IP)
        pkt_ipv4 = ipv4.ipv4(dst=str(host.exploded),
                     src=src_iface_ip,
                     proto=inet.IPPROTO_UDP)
        udp_pkt = udp.udp(src_port=dst_port, dst_port=dst_port, total_length=0, csum=0)
        
        datapath = self.sys.datapath
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(pkt_ipv4)
        p.add_protocol(udp_pkt)
        #p.add_protocol(msg)
        p.serialize()
        p+=msg.serialize()
        data = p.data 
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port_no)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data) 
        datapath.send_msg(out)

        #self.transport.write(msg.serialize(), (host.exploded, port))

    def process_response(self, msg, host):
        logger.info("response received by %s",host)
        for rte in msg.rtes:
            rte.metric = min(rte.metric + 1, RIPRouteEntry.MAX_METRIC)
            self.try_add_route(rte, host)
        if self._route_change:
            logger.info("route change TRUE")
            self.handle_route_change()

    def handle_route_change(self):
        if self._suppress_triggered_updates:
            return
        self._suppress_triggered_updates = True

        current_time = datetime.datetime.now()
        trigger_suppression_timeout = \
                            datetime.timedelta(seconds=random.randrange(1, 5))

        if self._last_update_time + trigger_suppression_timeout < \
           current_time:
            self._send_triggered_update()
        else:
            threading.Timer(trigger_suppression_timeout.total_seconds(),self._send_triggered_update).start()
            #reactor.callLater(trigger_suppression_timeout.total_seconds(),self._send_triggered_update)

    def _send_triggered_update(self):
        self.generate_update(triggered=True)
        self._route_change = False
        self._suppress_triggered_updates = False

    def try_add_route(self, rte, host, install=True):
        """Install a route via the given host. If install is False, the
        route is not added to the system routing table and a triggered
        update is not requested."""
        logger.info("try_add_route: Received %s",rte)
        bestroute = self.get_route(rte.network.ip.exploded,
                                   rte.network.netmask.exploded)
        logger.info("set next hop best route : %s ",bestroute)
        rte.set_nexthop(host)
        if not bestroute:
            logger.info("Not Best route")
            if rte.metric == RIPRouteEntry.MAX_METRIC:
                return

            rte.changed = True
            logger.info("appended route ")
            self._routes.append(rte)

            if not install:
                logger.info("not install")
                return
            self._route_change = True
            # replace with self.sys.update_routing_table
            entry_rip = router.rip_entry(rte.metric,rte.nexthop)
            self.sys.update_routing_table((rte.network.ip.exploded,rte.network.prefixlen),entry_rip)
            #self.sys.install_route(rte.network.ip.exploded,rte.network.prefixlen, rte.metric,rte.nexthop)
        else:
            if rte.nexthop == bestroute.nexthop:
                if bestroute.metric != rte.metric:
                    if bestroute.metric != RIPRouteEntry.MAX_METRIC and \
                       rte.metric >= RIPRouteEntry.MAX_METRIC:
                        self._start_garbage_collection(bestroute)
                    else:
                        self.update_route(bestroute, rte)
                elif not bestroute.garbage:
                    bestroute.init_timeout()
            elif rte.metric < bestroute.metric:
                logger.info("Found better route to %s via %s in %d",rte.network.exploded, rte.nexthop, rte.metric)
                self.update_route(bestroute, rte)

    def update_route(self, oldrt, newrt):
        logger.info("RIPSERV: Update Route")
        oldrt.init_timeout()
        oldrt.garbage = False
        oldrt.changed = True
        oldrt.metric = newrt.metric
        oldrt.nexthop = newrt.nexthop
        self.sys.modify_route(oldrt)
        self._route_change = True

    def get_route(self, net, mask):
        logger.info("RIPSERV: get Route")
        for rt in self._routes:
            if (net == rt.network.ip.exploded) and \
               (mask == rt.network.netmask.exploded):
                return rt
        return None

    def cleanup(self):
        """Clean up any system changes made while running (uninstall
        routes etc.)."""
        # XXX This should probably all be part of sys.
        logger.info("Cleaning up.")
        self.sys.cleanup()
        for rt in self._routes:
            if rt.nexthop.exploded != "0.0.0.0":
                self.sys.uninstall_route(rt.network.ip.exploded,
                                          rt.network.prefixlen)


class ModifyRouteError(Exception):
    def __init__(self, operation, output=None):
        self.operation = operation
        self.output = output


class RIPPacket(object):
    def __init__(self, data=None, hdr=None, rtes=None, src_ip=None):
        """Create a RIP packet either from the binary data received from the
        network, or from a RIP header and RTE list."""
        if data and src_ip:
            self._init_from_net(data, src_ip)
        elif hdr and rtes:
            self._init_from_host(hdr, rtes)
        else:
            raise(ValueError)

    def __repr__(self):
        return "RIPPacket: Command %d, Version %d, number of RTEs %d." % \
                (self.hdr.cmd, self.hdr.ver, len(self.rtes))

    def _init_from_net(self, data, src_ip):
        """Init from data received from the network."""
        # Quick check for malformed data
        datalen = len(data)
        if datalen < RIPHeader.SIZE:
            raise(FormatException)

        malformed_rtes = (datalen - RIPHeader.SIZE) % RIPRouteEntry.SIZE
        if malformed_rtes:
            raise(FormatException)

        numrtes = (datalen - RIPHeader.SIZE) / RIPRouteEntry.SIZE
        self.hdr = RIPHeader(data[0:RIPHeader.SIZE])

        self.rtes = []
        rte_start = RIPHeader.SIZE
        rte_end = RIPHeader.SIZE + RIPRouteEntry.SIZE
        for i in range(numrtes):
            self.rtes.append(RIPRouteEntry(rawdata=data[rte_start:rte_end],
                                              src_ip=src_ip))
            rte_start += RIPRouteEntry.SIZE
            rte_end += RIPRouteEntry.SIZE

    def _init_from_host(self, hdr, rtes):
        """Init using a header and rte list provided by the application."""
        if hdr.ver != 2:
            raise(ValueError("Only version 2 is supported."))
        self.hdr = hdr
        self.rtes = rtes

    def serialize(self):
        """Return a bytestring representing this packet in a form that
        can be transmitted across the network."""

        # Always re-pack in case the header or rtes have changed.
        packed = self.hdr.serialize()
        for rte in self.rtes:
            packed += rte.serialize()
        return packed


class RIPHeader(object):
    FORMAT = ">BBH"
    SIZE = struct.calcsize(FORMAT)
    TYPE_REQUEST = 1
    TYPE_RESPONSE = 2

    def __init__(self, rawdata=None, cmd=None, ver=None):
        self.packed = None
        if cmd and ver:
            self._init_from_host(cmd, ver)
        elif rawdata:
            self._init_from_net(rawdata)
        else:
            raise(ValueError)

    def __repr__(self):
        return "RIPHeader(cmd=%d, ver=%d)" % (self.cmd, self.ver)

    def _init_from_net(self, rawdata):
        """Init from data received from the network."""
        header = struct.unpack(self.FORMAT, rawdata)

        self.cmd = header[0]
        self.ver = header[1]
        zero = header[2]
        if zero != 0:
            raise(FormatException)

    def _init_from_host(self, cmd, ver):
        """Init from data provided by the application."""
        if cmd != 1 and cmd != 2:
            raise(ValueError)
        else:
            self.cmd = cmd

        if ver != 1 and ver != 2:
            raise(ValueError)
        else:
            self.ver = ver

    def serialize(self):
        # Always re-pack
        return struct.pack(self.FORMAT, self.cmd, self.ver, 0)


class RIPSimpleAuthEntry(object):
    """Simple plain text password authentication as defined in RFC 1723
    section 3.1."""
    FORMAT = ">HH16s"
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, rawdata=None, password=None):
        """password should be the plain text password to use and must not
        be longer than 16 bytes."""
        if rawdata and password != None:
            raise(ValueError("only one of rawdata or password are allowed."))
        elif rawdata:
            self._init_from_net(rawdata)
        elif password != None:
            self.afi = 0xffff
            self.auth_type = 0x0002
            self.password = password
        else:
            raise(ValueError("rawdata or password must be provided."))

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        if len(password) > 16:
            raise(ValueError("Password too long (>16 bytes)."))
        self._password = password

    def _init_from_net(self, rawdata):
        rte = struct.unpack(self.FORMAT, rawdata)
        self.afi = rte[0]
        self.auth_type = rte[1]
        self.password = rte[2]

    def serialize(self):
        return struct.pack(self.FORMAT, self.afi, self.auth_type,
                           self.password)


class RIPRouteEntry(object):
    FORMAT = ">HHIIII"
    SIZE = struct.calcsize(FORMAT)
    MIN_METRIC = 0
    MAX_METRIC = 16

    def __init__(self, rawdata=None, address=None, mask=None, nexthop=None,
                 metric=None, tag=0, src_ip=None, imported=False, afi=2):
        self.packed = None
        self.changed = False
        self.imported = imported
        self.init_timeout()
        self.garbage = False
        self.marked_for_deletion = False

        if rawdata and src_ip:
            self._init_from_net(rawdata, src_ip)
        elif address and \
             nexthop and \
             mask   != None and \
             metric != None and \
             tag    != None:
            self._init_from_host(address, mask, nexthop, metric, tag, afi)
        else:
            raise(ValueError)

    def _init_from_host(self, address, mask, nexthop, metric, tag, afi):
        """Init from data provided by the application."""
        self.afi = afi
        self.set_network(address, mask)
        self.set_nexthop(nexthop)
        self.metric = metric
        self.tag = tag

    def set_network(self, address, mask):
        # If the given address and mask is not a network ID, make it one by
        # ANDing the addr and mask.
        network = ipaddr.IPv4Network(address + "/" + str(mask))
        self.network = ipaddr.IPv4Network(network.network.exploded + "/" +
                                          str(network.prefixlen))

    def set_nexthop(self, nexthop):
        self.nexthop = ipaddr.IPv4Address(nexthop)

    def init_timeout(self):
        """Sets a timer to the current time. The timer is used as either the
        "timeout" timer, or the garbage collection timer depending on whether
        or not self.garbage is set."""
        if self.imported:
            self.timeout = None
        else:
            self.timeout = datetime.datetime.now()

    def _init_from_net(self, rawdata, src_ip):
        """Init from data received on the network."""
        self.packed = None
        rte = struct.unpack(self.FORMAT, rawdata)
        self.afi = rte[0]
        self.tag = rte[1]
        address = ipaddr.IPv4Address(rte[2])
        mask = ipaddr.IPv4Address(rte[3])

        self.set_nexthop(rte[4])
        self.metric = rte[5]

        if self.nexthop.exploded == "0.0.0.0":
            self.set_nexthop(src_ip)
        self.set_network(address.exploded, mask.exploded)

        # Validation
        if not (self.MIN_METRIC <= self.metric <= self.MAX_METRIC):
            raise(FormatException)

    def __repr__(self):
        return "RIPRouteEntry(address=%s, mask=%s, nexthop=%s, metric=%d, " \
               "tag=%d)" % (self.network.ip.exploded, self.network.netmask.exploded, self.nexthop, self.metric, self.tag)

    def __eq__(self, other):
        if self.afi     == other.afi      and \
           self.network == other.network  and \
           self.nexthop == other.nexthop  and \
           self.metric  == other.metric   and \
           self.tag     == other.tag:
            return True
        else:
            return False

    def serialize(self):
        """Format into typical RIPv2 header format suitable to be sent
        over the network. This is the updated header from RFC 2453
        section 4."""

        # Always re-pack
        return struct.pack(self.FORMAT, self.afi, self.tag,
                                      self.network.network._ip,
                                      self.network.netmask._ip,
                                      self.nexthop._ip, self.metric)

class _RIPException(Exception):
    def __init__(self, message=""):
        self.message = message


class FormatException(_RIPException):
    pass


class NotSupported(_RIPException):
    pass



