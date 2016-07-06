import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER 
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3 , ofproto_v1_2
from ryu.ofproto import ofproto_v1_0, nx_match
from ryu.ofproto import ether, inet
from ryu.lib.packet import (packet, ethernet, arp, icmp, icmpv6, ipv4, ipv6)
from ryu.lib import mac
from ryu.lib import dpid as dpid_lib
from ryu.lib import port_no as portno_lib
from ryu.lib import ofctl_v1_0
from ryu.topology import switches
from ryu.topology import event
import netaddr
from ryu.topology.api import get_all_switch, get_all_link, get_switch, get_link
import router
from proto.rip import ripserv
import copy
import gevent, gevent.server
from telnetsrv.green import TelnetHandler, command
import thread
import serveur
from ryu.lib import hub
import os
import ipaddr

FORMAT = '%(name)s[%(levelname)s]%(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)


ID_FLW_ROUTING=0
ID_FLW_ARP_R = 2
ID_FLW_ARP = 1
ID_FLW_MAC = 3

FLOW_IDLE_TIMEOUT = 60
FLOW_HARD_TIMEOUT = 600

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


class L3_Routing(app_manager.RyuApp):
      OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
      def __init__(self, *args, **kwargs):
          super(L3_Routing,self).__init__(*args, **kwargs)
          self.routers={}
      ## get and store datapath object of each switch connected and instanciate router object            
      @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
      def router_features_handler(self, ev):
          #self.datapaths[ev.msg.datapath.id]={}
          datapath = ev.msg.datapath
          dpid = datapath.id
          print vars(datapath)
          print dpid
          ofproto = datapath.ofproto
          parser = datapath.ofproto_parser
          self.routers[dpid] = router.Router(datapath)
          # install table-miss flow entry
          # We specify NO BUFFER to max_len of the output action due to
          # OVS bug. At this moment, if we specify a lesser number, e.g.,
          # 128, OVS will send Packet-In with invalid buffer_id and
          # truncated packet data. In that case, we cannot output packets
          # correctly.
          match = parser.OFPMatch()
          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
          
          self.add_flow(datapath, 0, match, actions)
          self.add_flow(datapath,0,match,actions,1)
          self.add_flow(datapath,0,match,actions,2)
          self.add_flow(datapath,0,match,actions,3)
          # install  initial rules
          self.install_initial_rules(datapath)
          static_entry1 = router.static_entry('172.16.33.191',1)
          self.routers[dpid].update_routing_table(('172.16.33.0',24),static_entry1)
          static_entry2 = router.static_entry('192.168.1.40',2)
          self.routers[dpid].update_routing_table(('192.168.1.0',24),static_entry2)
        #update list of ports (name , hw_addr) 
      def install_initial_rules(self,datapath):
          # install eigrp rule if packet with proto = 0x58 send it to the controller 
          ofproto = datapath.ofproto
          parser = datapath.ofproto_parser
          match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ip_proto=0x58)
          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
          self.add_flow(datapath,0,match,actions)
          # install rip rule if packet with udp_src = 520 send it to the controller
          match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ip_proto=inet.IPPROTO_UDP,udp_src=520)
          self.add_flow(datapath,0,match,actions)
          match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
          self.add_flow(datapath,0,match,actions)
          
      @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
      def port_add_handler(self, event):
          """
             event handler triggered when port added.
             get Switch instance and create a Port object.
          """
          print "######################## port status ###########################"
          print vars(event)
          msg = event.msg
          dpid =msg.datapath.id
          try: 
             self.routers[dpid].add_port(event.port.port_no,netaddr.EUI(event.port.hw_addr),event.port.name)
             logger.info('port %s added ',event.port.name)
             logger.info('port added, port_no=%s (dpid=%s)', portno_lib.port_no_to_str(port.port_no), dpid_lib.dpid_to_str(port.dpid))
          except:
                pass
         # add flow method
      def add_flow(self, datapath, priority, match, actions,table_id=0): 
          ofproto = datapath.ofproto
          parser = datapath.ofproto_parser
          inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
          mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, table_id = table_id,instructions=inst)
          datapath.send_msg(mod)
         
      def find_packet(self, pkt, target):
        """
            try to extract the packet and find for specific
            protocol.
        """
        for packet in pkt.protocols:
            try:
                if packet.protocol_name == target:
                    return packet
            except AttributeError:
                pass
        return None
      # update IF_MNGT , list_of_ports of each router
      @set_ev_cls(event.EventSwitchEnter)
      def handler_switch_enter(self, ev):
          print vars(ev.switch.dp)
          rtr = self.routers[ev.switch.dp.id]
          address = ev.switch.dp.address
          dpid=ev.switch.dp.id
          print "############### SWITCH INFO ####################"
          print ("#####################PORTS############################")
          print len(ev.switch.dp._ports)
          for index,port in ev.switch.dp._ports.iteritems():
              print port.hw_addr 
              port=rtr.add_port(port.port_no,port.hw_addr,port.name) 
              if port.name == 'eth0':
                 port.ip_addr = '172.16.33.191'
                 port.netmask= 24
                 logger.info("proto RIP stated in child process")
                
                 #rtr.start_proto('OSPF','10.10.10.10', '192.168.66.0', '255.255.255.0')
                 #self.routers[ev.switch.dp.id].start_proto('EIGRP','172.16.33.191')
              if port.name == 'eth1':
                 logger.info("activate proto in lxcbr0")
                 port.proto_active = 'RIP'
                 port.ip_addr='192.168.1.40'
                 self.routers[ev.switch.dp.id].start_proto('RIP','192.168.1.40')
                 port.netmask= 24
                 #port.proto_active = 'EIGRP'
                 
          logger.info("length ports : %s",len(rtr.ports))
          '''
            set management interface of router

          '''
          print "###################### Address ###########################"
          print address
          rtr.mngt_if = address
      # handling packet

           
           
      @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) 
      def _packet_in_handler(self, ev):
          
          msg = ev.msg
          table_id = msg.table_id
          print(vars(ev))
          datapath = msg.datapath
          ofproto = datapath.ofproto
          parser = datapath.ofproto_parser
          in_port = msg.match["in_port"]
          pkt = packet.Packet(msg.data)
          eth = pkt.get_protocols(ethernet.ethernet)[0]
          dst = eth.dst
          src = eth.src
          dpid = datapath.id
          rtr = self.routers[dpid]
          print "################ update mac table ##################################### "
          rtr.update_mac_table(eth.src,in_port)
          data = ev.msg.data
          pkt = packet.Packet(data)

          for p in pkt.protocols:
              if isinstance(p, arp.arp):
                 logger.info("###############packet arp#################")
                 self.handle_arp(ev.msg, pkt, p)
              elif isinstance(p, ipv4.ipv4):
                   self.handle_ip(ev.msg, pkt, p)
              elif isinstance(p, ipv6.ipv6):
                   # logger.warning('ipv6 is currently not supported.')
                   pass
              else:
                   pass
          #else:
              #logger.info('Router %s  interface not configured yet', dpid)
      def update_arp_entry(self,dpid, packet):
          """
             update MAC address information in ARP table.
          """
          rtr = self.routers[dpid]
          ether_layer = self.find_packet(packet, 'ethernet')
          ip_layer = self.find_packet(packet, 'ipv4')
          if ip_layer is None:
             ip_layer = self.find_packet(packet, 'arp')
             ip_layer.src = ip_layer.src_ip
             logger.info('update ARP entry: %s - %s (dpid=%s)', ether_layer.src, ip_layer.src, dpid_lib.dpid_to_str(rtr.datapath.id))
            
             print "########### update ARP ######################"
             rtr.update_arp_table(ip_layer.src,ether_layer.src)
              
             '''
             send  flow mod on table id 2 match ip_dest set mac_dst go_table_id mac 
                   
             '''
             
             
             #self.arp_table.setdefault(dpid, {})
             #self.arp_table[dpid][netaddr.IPAddress(ip_layer.src)] = (netaddr.EUI(ether_layer.src), time.time())
 
      def handle_arp_request(self, msg, pkt, arp_pkt):
          """
            called when receiving ARP request from hosts.
            when a host send a request first time,
            it has no MAC address information for its gateway,
            so it will send a ARP request to the switch.
          """
          print "################## handle arp request #####################"
          #switch = self.switches[msg.datapath.id]
          rtr = self.routers[msg.datapath.id]
          print vars(msg)
          in_port_no = msg.match["in_port"]
          req_dst_ip = arp_pkt.dst_ip
          req_src_ip = arp_pkt.src_ip
          #port = switch.ports[in_port_no]

          logger.info('receive ARP request: who has %s? tell %s (dpid=%s)', str(req_dst_ip), str(req_src_ip), dpid_lib.dpid_to_str(msg.datapath.id))

        # handle ARP request for gatewayr
          print type(req_dst_ip)
          print req_dst_ip
          print rtr.ports[in_port_no].ip_addr
          print type(rtr.ports[in_port_no].ip_addr)
          '''if rtr.ports[in_port_no].ip_addr != req_dst_ip:
             logger.warning('cannot reply ARP, please check gateway configuration. (dpid=%s)', dpid_lib.dpid_to_str(msg.datapath.id))
             return'''
          port = rtr.ports[in_port_no]
          datapath = msg.datapath
          reply_src_mac = str(port.mac_addr)
          ether_layer = self.find_packet(pkt, 'ethernet')
          self.update_arp_entry(msg.datapath.id,pkt)
          print "ip_src :",req_dst_ip
          print "ip_dst :",req_src_ip
          print "out_port:",in_port_no
        # pack a ARP reply packet
          e = ethernet.ethernet(dst = ether_layer.src, src = reply_src_mac,
                                ethertype = ether.ETH_TYPE_ARP)
          a = arp.arp(hwtype = arp.ARP_HW_TYPE_ETHERNET,
                    proto = ether.ETH_TYPE_IP,
                    hlen = 6, plen = 4, opcode = arp.ARP_REPLY,
                    src_mac = reply_src_mac, src_ip = req_dst_ip,
                    dst_mac = arp_pkt.src_mac, dst_ip = req_src_ip)
          p = packet.Packet()
          p.add_protocol(e)
          p.add_protocol(a)
          print vars(p)
          p.serialize()
          data = p.data 
          actions = [datapath.ofproto_parser.OFPActionOutput(in_port_no)]
          out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)  
          print "send arp reply"
          datapath.send_msg(out)
          logger.info('ARP replied: %s - %s', reply_src_mac, req_dst_ip)

      def handle_arp_reply(self, msg, pkt, arp_pkt):
          """
            called when receiving ARP reply from hosts.
            the host will send their MAC address back to switch.
            (1) save the MAC address information in ARP table.
            (2) try to resend the packet in the buffer.
            (3) remove the sent packet from the buffer queue.
          """
          logger.info("##############################packet ARP REPLY #############################")
          rtr = self.routers[msg.datapath.id]
          in_port_no = msg.match["in_port"]
          replied_buffer = []
          logger.info('receive ARP reply: from %s (dpid=%s)', str(arp_pkt.src_ip), dpid_lib.dpid_to_str(msg.datapath.id))

          if rtr.ports[in_port_no].ip_addr == arp_pkt.dst_ip:
             self.update_arp_entry(msg.datapath.id, pkt)
             # try to resend the buffered packets
             '''for i in xrange(len(rtr.msg_buffer)):
                msg, pkt, outport_no = rtr.msg_buffer[i]
                if self.deliver_to_host(msg, pkt, outport_no):
                    replied_buffer.append(i)

             replied_buffer.sort(reverse = True)
             for i in replied_buffer:
                rtr.msg_buffer.pop(i)'''


   
      def handle_ip(self, msg, pkt, protocol_pkt):
          """
            handler for IP packet (currently not support ipv6)
            (1) drop non-ipv4 packet.
            (2) drop broadcast packet to 255.255.255.255
            (3) try to deliver packet to the host if output port matched.
          """
          datapath = msg.datapath
          dpid = datapath.id
          table_id = msg.table_id
          rtr = self.routers[dpid]
          if isinstance(protocol_pkt, ipv4.ipv4) == False:
             logger.warning('cannot find ipv4 packet to process')
             return
          icmp_pkt = self.find_packet(pkt, 'icmp')
          if icmp_pkt is not None: 
             print "################ packet icmp ###################"
             self.handle_icmp(msg,pkt,icmp_pkt)
          udp_pkt = self.find_packet(pkt,'udp')
          if udp_pkt is not None:
             if udp_pkt.src_port == 520:
                self.handle_proto(msg,pkt,udp_pkt,'RIP')
          
          ospf_pkt_hello = self.find_packet(pkt, 'OSPFHello')
	  ospf_pkt_dbd  = self.find_packet(pkt,'OSPFDBDesc')
          ospf_pkt_ls_req =self.find_packet(pkt,'OSPFLSReq')
	  ospf_pkt_lsupdate= self.find_packet(pkt, 'OSPFLSUpd')
	  a = rtr.proto['OSPF']
	  if ospf_pkt_hello:
	     a.handle_ospf_hello(msg,pkt,ospf_pkt_hello)
	  if ospf_pkt_dbd:
	     a.handle_dbd_packet(msg, pkt, ospf_pkt_dbd)
             print ospf_pkt_dbd
          if ospf_pkt_ls_req:
             a.handle_ls_req_packet(msg, pkt, ospf_pkt_ls_req)	
	  if ospf_pkt_lsupdate:
	     a.handle_lsa_update (msg,pkt, ospf_pkt_lsupdate)
          #src_switch = self.switches[msg.datapath.id]

          ip_layer = self.find_packet(pkt, 'ipv4')
          if ip_layer.proto == 0x58:
              self.handle_proto(msg,pkt,ip_layer,'EIGRP')
          
          if str(ip_layer.dst) == '255.255.255.255':
             return
          if table_id == ID_FLW_ROUTING:
             logger.info("Router %s : send route not Found",datapath.id)
             return
          if table_id == ID_FLW_ARP:
             logger.info("Router %s : send Arp match not found",datapath.id)
             ipDest = ip_layer.dst
             # find gw 
             index, entry = rtr.get_gw_by_ip(ipDest)
             print entry.port,entry.gw
             #rtr.msg_buffer.append((msg,pkt,entry.port))
             logger.info("output port :%s ",entry.port)
             self.send_arp_request(datapath,entry.port,ipDest)                     
             return 
          if table_id == ID_FLW_ARP_R:
             logger.info("Router %s : send Arp match not found",datapath.id)
             ipDest = ip_layer.dst
             index, entry = rtr.get_gw_by_ip(ipDest)
             logger.info("output port :%s ",entry.port)
             #rtr.msg_buffer.append((msg,pkt,entry.port))
             self.send_arp_request(datapath,entry.port,entry.gw)
             return
             
          else:
              logger.warning('cannot find output port for %s (dpid=%s)', str(ip_layer.dst), dpid_lib.dpid_to_str(msg.datapath.id))
      def handle_arp(self, msg, pkt, arp_pkt):
          """
            called when receiving ARP packet,
            inspect the opcode then call corresponding methods.
          """
          print "########### handle arp ##################"
          logger.info("in_port : %s",msg.match['in_port'])
          if arp_pkt.opcode == arp.ARP_REQUEST:
             self.handle_arp_request(msg, pkt, arp_pkt)
          elif arp_pkt.opcode == arp.ARP_REPLY:
             print "####################### handle arp reply #####################"
             self.handle_arp_reply(msg, pkt, arp_pkt)
          else:
              return
      def send_arp_request(self, datapath, outport_no, dst_ip):
          """
            pack and send ARP request for specific IP address.
          """
          logger.info("outport:%s",outport_no)
          src_mac_addr = str(self.routers[datapath.id].ports[outport_no].mac_addr)
          src_ip = str(self.routers[datapath.id].ports[outport_no].ip_addr)
          dst_ip = str(dst_ip)
          p = packet.Packet()
          e = ethernet.ethernet(dst = mac.BROADCAST_STR,src = src_mac_addr, ethertype = ether.ETH_TYPE_ARP)
          
          a = arp.arp_ip(opcode = arp.ARP_REQUEST, src_mac = src_mac_addr,
                src_ip = src_ip, dst_mac = mac.DONTCARE_STR,
                dst_ip = dst_ip)
          p.add_protocol(e)
          p.add_protocol(a)
          p.serialize()
          actions = [datapath.ofproto_parser.OFPActionOutput(outport_no)]
          out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=p.data)  
          datapath.send_msg(out)
          logger.info('ARP request sent: who has %s? tell %s (dpid=%s)', dst_ip, src_ip, dpid_lib.dpid_to_str(datapath.id))
      def handle_icmp(self,msg,pkt,icmp_pkt):
          dpid = msg.datapath.id
          datapath = msg.datapath
          if icmp_pkt.type != ICMP_ECHO_REQUEST:
             # need forward packet
             return
          eth_layer = self.find_packet(pkt, 'ethernet')
          print vars(eth_layer) 
          ip_layer = self.find_packet(pkt,'ipv4')
          ipDestAddr = netaddr.IPAddress(ip_layer.dst)
          port_in = msg.match['in_port']
          if self.routers[dpid].ports[port_in].ip_addr == str(ipDestAddr):
             
             pkt = packet.Packet()
             print self.routers[dpid].ports[port_in].mac_addr
             print eth_layer.src
             pkt.add_protocol(ethernet.ethernet(ethertype=eth_layer.ethertype,
                                           dst=eth_layer.src,
                                           src=self.routers[dpid].ports[port_in].mac_addr))
             pkt.add_protocol(ipv4.ipv4(dst=ip_layer.src,
                                   src=self.routers[dpid].ports[port_in].ip_addr,
                                   proto=ip_layer.proto))
             pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=icmp_pkt.data))
             pkt.serialize()
             data = pkt.data
             actions = [datapath.ofproto_parser.OFPActionOutput(port_in)]
             out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)  
             datapath.send_msg(out)
             logger.info('send reply icmp to : %s ',ip_layer.src)
      def deliver_to_host(self, msg, pkt, outport_no):
          """
            deliver packet to host if the switch owns that subnet.
            send PacketOut.
          """
          ip_layer = self.find_packet(pkt, 'ipv4')
          dp = msg.datapath
          rtr = self.routers[dp.id]
          ipDestAddr = netaddr.IPAddress(ip_layer.dst)

          logger.info('final switch arrived, try to deliver to %s (dpid=%s)', str(ipDestAddr), dpid_lib.dpid_to_str(msg.datapath.id))

          try:
             mac_addr = rtr.arp_table[ipDestAddr].mac_addr
          except KeyError:
             logger.info('no ARP entry for %s, packet buffered', str(ipDestAddr))
             self.send_arp_request(msg.datapath, outport_no, ipDestAddr)
             rtr.msg_buffer.append((msg, pkt, outport_no))
             return False
          actions = [datapath.ofproto_parser.OFPActionSetField(eth_dst=mac_addr),datapath.ofproto_parser.OFPActionSetField(eth_src=rtr.ports[outport_no].mac_addr),datapath.ofproto_parser.OFPActionOutput(in_port_no)]
          out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)  
          datapath.send_msg(out)
          return True
      def handle_proto(self,msg,pkt,proto_pkt,proto=None):
          ''' this function handle proto packet , ospf, rip '''
          if proto == 'RIP':
             logger.info("RIP PACKET ARRIVED ")
             ''' PARSE PACKET AND SEND IT TO PROTO DATAGRAM RECEIVED '''
             print("######################RIP PACKET###########################")
             print vars(pkt)
             logger.info("length protocols %s",len(pkt.protocols))
             ip_pkt = self.find_packet(pkt,'ipv4')
             ip_src= ip_pkt.src
             print pkt.protocols[len(pkt.protocols)-1]
             rip_pkt = pkt.protocols[len(pkt.protocols)-1]
             dpid = msg.datapath.id
             rtr = self.routers[dpid]
             instance_rip=rtr.proto['RIP']
             instance_rip.datagramReceived(rip_pkt,(ip_src,520))

          if proto == 'EIGRP':
             logger.info("EIGRP PACKET ARRIVED")
             print("######################EIGRP PACKET###########################")
             print vars(pkt)
             logger.info("length protocols %s",len(pkt.protocols))
             ip_src = proto_pkt.src
             print pkt.protocols[len(pkt.protocols)-1]
             eigrp_pkt = pkt.protocols[len(pkt.protocols)-1]
             dpid = msg.datapath.id
             rtr = self.routers[dpid]
             instance_eigrp=rtr.proto['EIGRP']
             instance_eigrp.datagramReceived(eigrp_pkt,(ip_src,0))
             
             
