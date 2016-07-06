import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER 
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3 , ofproto_v1_2
from ryu.ofproto import ofproto_v1_0, nx_match
from ryu.ofproto import ether, inet
from ryu.lib.packet import (packet, ethernet, arp, icmp, icmpv6, ipv4, ipv6, ospf)
from ryu.lib import mac
from ryu.lib import dpid as dpid_lib
from ryu.lib import port_no as portno_lib
from ryu.lib import ofctl_v1_0
from ryu.topology import switches
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link, get_switch, get_link
import gevent, gevent.server
from telnetsrv.green import TelnetHandler, command
import thread, threading, time, datetime, signal, sys, struct, netaddr, router, copy, dijkstra
import signal, sys
from ryu.lib import hub
import l3_routing as l3
import logging

FORMAT = '%(name)s[%(levelname)s]%(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)

DB_DESC = {}
lsa_header=[]
req = []
class OSPF(object):
	
      def __init__(self, routers, router_id, net_addr, mask, area_id='0.0.0.0', neighbors=None): 
	self.routers 	    = routers
	self.router_id	    = router_id 
	self.area_id 	    = area_id
	self.mask 	    = mask 
	self.neighbors 	    = []
	self.hello_interval =  10
	self.dead_interval  =  40
	self.database       = {}
	self.net_mask 	    = (net_addr, mask)
	signal.signal(signal.SIGALRM, self.send_ospf_hello)
	self.create_db()
        self.call()
	self.essai = False
	self.forwarding_table= {}
	self.dead_neighbor = {}
	threading.Timer(40,self.fct_dead_interval).start()
	self.create_lsa_header()
      # ==========
      # OSPF begin
      # ==========

      def send_ospf_hello(self,signum, frame):
	ospf_hello = ospf.OSPFHello(router_id = self.router_id ,neighbors = self.neighbors)
	rtr = self.routers
	datapath = rtr.datapath	
        hello = ospf_hello.serialize()
	p = packet.Packet()
        e = ethernet.ethernet(dst = '01:00:5e:00:00:05',src = '00:0c:29:d4:10:d7', ethertype = ether.ETH_TYPE_IP)
	f = ipv4.ipv4(dst='224.0.0.5',
                     src='172.16.33.191',
                     proto=inet.IPPROTO_OSPF)
	p.add_protocol(e)
	p.add_protocol(f)
	p.add_protocol(hello)
	p.serialize()
	print " ================= P.DATA =========== "
	print p.data
	print " ================= P.DATA =========== "
	actions = [datapath.ofproto_parser.OFPActionOutput(1)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=p.data) 

	datapath.send_msg(out)
	self.call()

	

      # =================
      # handle OSPF hello
      # =================

      def handle_ospf_hello(self, msg, pkt, ospf_pkt):
        logger.info("#### handle Ospf hello####")
        print ospf_pkt
	print self.neighbors
	datapath=msg.datapath
	ofproto=datapath.ofproto
	parser=datapath.ofproto_parser
	
	self.dead_neighbor[ospf_pkt.router_id] = time.time()
 	if ospf_pkt.router_id not in self.neighbors:
	   self.neighbors.append(ospf_pkt.router_id)
           # add Adjacency
	#if self.router_id in ospf_pkt.neighbors and self.essai == False: # send Database
	   self.send_dbd_packet()
	   


      def fct_dead_interval(self):
	for neighbor, its_time in self.dead_neighbor.iteritems():
	 	print self.dead_neighbor
		print its_time
	 	print time.time()
		if  time.time()-its_time > 40:
		   self.delete_from_db(neighbor)
		   self.neighbors.remove(neighbor)
	threading.Timer(40,self.fct_dead_interval).start()

      def delete_from_db(self,id_to_delete):
	 self.essai = False
	 for index, type_lsa in DB_DESC.iteritems():
	    if id_to_delete == type_lsa.header.adv_router:
		del DB_DESC[index]



      def handle_dbd_packet(self,msg, pkt,ospf_pkt_dbd): # not done yet 
	   print ' ================================== handle dbd packet =================================='	   
	   i=0
           print lsa_header
           print ospf_pkt_dbd.lsa_headers
	   for i in range(len(ospf_pkt_dbd.lsa_headers)):
	      print i   
	      if ospf_pkt_dbd.lsa_headers[i] not in lsa_header:
                 req.append(ospf.OSPFLSReq.Request(type_=ospf.OSPF_ROUTER_LSA,id_=ospf_pkt_dbd.lsa_headers[i].id_,adv_router=ospf_pkt_dbd.lsa_headers[i].adv_router))
           print req
           self.send_ls_req_routerLSA(ospf_pkt_dbd,req)
           
      def create_db(self):
	var = len(DB_DESC)
	DB_DESC[var] = ospf.RouterLSA(id_=self.router_id,adv_router=self.router_id, links=[ospf.RouterLSA.Link(id_=self.net_mask[0], data=self.net_mask[1], type_=ospf.LSA_LINK_TYPE_TRANSIT, metric=10)])
	


      def create_lsa_header(self):
	for index, h in DB_DESC.iteritems():
	   lsa_header.append(h.header)
        return lsa_header
        print'###################################################'
	

      def call(self):
	signal.setitimer(signal.ITIMER_REAL, self.hello_interval)


      def send_dbd_packet(self):
	   self.essai = True
           print lsa_header	   
	   ospf_db_msg = ospf.OSPFDBDesc(router_id = self.router_id , i_flag = 1, ms_flag=1, lsa_headers = lsa_header)
	   rtr = self.routers
	   datapath = rtr.datapath	
           #hello = ospf_db_msg.serialize_tail()
	   p = packet.Packet()
           e = ethernet.ethernet(dst = '01:00:5e:00:00:05',src = '00:0c:29:d4:10:d7', ethertype = ether.ETH_TYPE_IP)
	   f = ipv4.ipv4(dst='224.0.0.5',
                     src='172.16.33.191',
                     proto=inet.IPPROTO_OSPF)
	   p.add_protocol(e)
	   p.add_protocol(f)
	   p.add_protocol(ospf_db_msg)
	   p.serialize()
	   actions = [datapath.ofproto_parser.OFPActionOutput(1)]
           out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=p.data) 

	   datapath.send_msg(out)
      def send_ls_req_routerLSA(self,ospf_pkt_dbd,req):
           msg = ospf.OSPFLSReq(router_id=self.router_id,lsa_requests=req)
           rtr = self.routers
	   datapath = rtr.datapath
	   p = packet.Packet()
           e = ethernet.ethernet(dst = '01:00:5e:00:00:05',src = '00:0c:29:d4:10:d7', ethertype = ether.ETH_TYPE_IP)
	   f = ipv4.ipv4(dst='224.0.0.5',
                     src='172.16.33.191',
                     proto=inet.IPPROTO_OSPF)
	   p.add_protocol(e)
	   p.add_protocol(f)
	   p.add_protocol(msg)
	   p.serialize()
	   actions = [datapath.ofproto_parser.OFPActionOutput(1)]
           out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=p.data) 

	   datapath.send_msg(out)
	   
	  
      def handle_ls_req_packet(self,msg, pkt,ospf_pkt_ls_req):  
	   print ' ================================== send lsu =================================='
      	   print ' ================================== send lsu =================================='
	   print ' ================================== send lsu =================================='
	   print ' ================================== send lsu =================================='
           self.send_ls_update(ospf_pkt_ls_req)


           


      def send_ls_update(self,ospf_pkt_ls_req):
           print '######################################'
	   print '#####################'
           print ospf_pkt_ls_req.lsa_requests   
           i=0
           j=0    
           index=[]       
           while j < len(ospf_pkt_ls_req.lsa_requests):  
              while i < len(lsa_header):    
                 if ospf_pkt_ls_req.lsa_requests[j].adv_router == lsa_header[i].adv_router and ospf_pkt_ls_req.lsa_requests[j].id == lsa_header[i].id_ and ospf_pkt_ls_req.lsa_requests[j].type_ == lsa_header[i].type_:
                    index.append(i)
                 i +=1
              j+=1
           #if a,ospf_pkt_ls_req.lsa_requests in 
           update=[]
           for i in index:
              update.append(DB_DESC[i])
           msg = ospf.OSPFLSUpd(router_id=self.router_id, lsas=update)
           rtr = self.routers
	   datapath = rtr.datapath
	   p = packet.Packet()
           e = ethernet.ethernet(dst = '01:00:5e:00:00:05',src = '00:0c:29:d4:10:d7', ethertype = ether.ETH_TYPE_IP)
	   f = ipv4.ipv4(dst='224.0.0.5',
                     src='172.16.33.191',
                     proto=inet.IPPROTO_OSPF)
	   p.add_protocol(e)
	   p.add_protocol(f)
	   p.add_protocol(msg)
	   p.serialize()
	   actions = [datapath.ofproto_parser.OFPActionOutput(1)]
           out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=p.data) 

	   datapath.send_msg(out)
	   
      def send_ls_ack(self,ospf_pkt_ls_up):

           ### if success add 
           i=0
           ack=[]
           print ospf_pkt_ls_up.lsas
           while i < len(ospf_pkt_ls_up.lsas):
              ack.append(ospf_pkt_ls_up.lsas[i].header)
              i+=1
           msg = ospf.OSPFLSAck(router_id=self.router_id,
                             lsa_headers=ack)
           rtr = self.routers
	   datapath = rtr.datapath
	   p = packet.Packet()
           e = ethernet.ethernet(dst = '01:00:5e:00:00:05',src = '00:0c:29:d4:10:d7', ethertype = ether.ETH_TYPE_IP)
	   f = ipv4.ipv4(dst='224.0.0.5',
                     src='172.16.33.191',
                     proto=inet.IPPROTO_OSPF)
	   p.add_protocol(e)
	   p.add_protocol(f)
	   p.add_protocol(msg)
	   p.serialize()
	   actions = [datapath.ofproto_parser.OFPActionOutput(1)]
           out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=p.data) 
           datapath.send_msg(out)

	   dist, previous = self.shortest_path()

	   self.update_fwd_table(dist, previous)

      def update_fwd_table(self,dist, via):
	  for to, via in via.iteritems(): 
	     self.forwarding_table[to] = (via, dist[via])

	  print " UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED " 
	  print " UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED " 
	  print " UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED "

	  print self.forwarding_table
	  print " UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED " 
	  print " UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED " 
	  print " UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED UPDATED "

      def handle_lsa_update(self, msg, pkt, ospf_pkt_lsupdate):
	
	  print ospf_pkt_lsupdate
	  print DB_DESC
	  print ospf_pkt_lsupdate.lsas
	  self.essai = False
	  for i in ospf_pkt_lsupdate.lsas:
	    var = len(DB_DESC)
	    DB_DESC[var] = i
	    self.send_ls_ack(ospf_pkt_lsupdate)


      def shortest_path(self):
	d = dijkstra.Graph()
	for index, type_lsa in DB_DESC.iteritems():
	   print DB_DESC
	   d.add_e(self.router_id, type_lsa.header.adv_router, type_lsa.links[0].metric)
	   print type_lsa.links[0].metric
	return d.s_path(self.router_id)
	  

# ===========
# LINK TYPES
# ===========











	

 

