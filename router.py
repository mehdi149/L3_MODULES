from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
import time
import logging
import patricia
from proto.rip import ripserv
from proto.eigrp import eigrp
from proto.ospf import ospf_mod
import ipaddr
import router
'''
port ==> mac DEFAULT STATIC CONF
port ==> ip  DEFAULT STATIC CONF
MNGT_IF
mac ==> port (MAC)
ip ==> mac (ARP)

'''
FLOW_IDLE_TIMEOUT = 60
FLOW_HARD_TIMEOUT = 600
ID_FLW_ROUTING =0
ID_FLW_ARP = 1
ID_FLW_ARP_R = 2
ID_FLW_MAC = 3

FORMAT = '%(name)s[%(levelname)s]%(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)

class PhysicalInterface(object):
    def __init__(self, name, flags):
        self.name = name
        self._flags = flags

    # TODO Retrieve actual interface info for stubs below.
    # Method will be different for Windows/Linux.
    def get_bandwidth(self):
        """Throughput expressed as picoseconds per kilobyte of data sent."""
        return 100

    def get_delay(self):
        """Delay expressed in 10 microsecond units."""
        return 10

    def get_load(self):
        """Load of the link based on output packets. 1 means a low load.
        255 means a high load."""
        return 1

    def get_reliability(self):
        """Link reliability expressed as a number between 1 and 255. 1 means
        completely unreliable, 255 means completely reliable. 0 is invalid."""
        return 255

    def get_mtu(self):
        return 1500
 
    def is_up(self):
        """Is the interface "up?"""
        return True

    def is_down(self):
        """Is the interface "down?"""
        return not self.is_up()
class static_entry(object):
      def __init__(self,gw,port):
          self.gw=gw
          self.port=port
class rip_entry(object):
      def __init__(self,metric,gw,port=None):
          self.metric = metric
          self.gw = gw
          self.port = port
class mac_entry(object):
      def __init__(self,port,time_entry):
          self.port = port
          self.time_entry = time_entry
class arp_entry(object):
      def __init__(self,mac_addr,time_entry):
          self.mac_addr =mac_addr
          self.time_entry= time_entry
class Port(object):
      def __init__(self,mac_addr,name):
          self.name=name
          self.mac_addr = mac_addr
          self.ip_addr = None
          self.netmask = None
          self.proto_active = None
          self.phy_iface =PhysicalInterface(name,None) 
class lookup(object):
      def __init__(self):
          self.trie= patricia.trie()
      def ipAddrToBin(self,ip_addr):
          print ip_addr
          ip_addr = str(ip_addr)
          print '.'.join([bin(int(x)+256)[3:] for x in ip_addr.split('.')]) 
          
          return '.'.join([bin(int(x)+256)[3:] for x in ip_addr.split('.')])
      def add_prefix(self,key,value,mask):
          key = self.ipAddrToBin(key)
          if mask > 8 and mask <=16:
             nw_mask=mask+1
             print mask
          if mask > 16 and mask <=24 :
             nw_mask=mask+2
             print mask
          if mask > 24:
             nw_mask=mask+3
          key = key[0:nw_mask]
          print key
          self.trie[key]=value
      def get_longest_prefix_match(self,prefix):
          bin_addr = self.ipAddrToBin(prefix)
          index_forward = self.trie.value(self.trie.key(bin_addr))
          return index_forward
class Router(app_manager.RyuApp):
      OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
      def __init__(self,datapath):
          # management ip interface 
          self.mngt_if=None
          # datapath object
          self.datapath=datapath
          # arp table
          self.arp_table={}
          self.mac_to_port={}
          # List of physical port with associated mac and ip address
          self.ports ={}
          self.msg_buffer=[]
          self.routing_table={}
          self.lookup = lookup()
          self.proto ={'RIP':None,'OSPF':None,'EIGRP':None}
      def get_num_port_by_name(self,name):
          for index ,port in self.ports.iteritems():
              if port.name == name:
                 return index
          return False
      def conf_port_by_name(self,name,ip_addr):
          # find port by name
          for index ,port in self.ports.iteritems():
              if port.name == name:
                 port.ip_addr = ip_address
                 return True
          return False
                 
      def if_is_configured(self):
          for index,port in self.ports.iteritems():
              if port.ip_addr is  None:
                 return False
          return True
          
      def ifconfig(self,port_name,ip = None,mask=None):
          self.conf_port_by_name(port_name,ip)
          port_no = self.get_port_by_name(port_name)
          self.update_routing_table((ip,mask),ip,port_no,static=True)
          
      def update_arp_table(self,ip_address,mac):
          print "##########################Update ARP Table ##############################"
          print ip_address
          entry_arp = arp_entry(mac,time.time())
          # add entry to arp_table attribute
          self.arp_table[ip_address]=entry_arp
          # send FLOW MOD to switch 
          # match by destination IP address
          # set mac dest action 
          dp = self.datapath
          ofproto = dp.ofproto
          parser = dp.ofproto_parser
          list_entries = self.is_gw(ip_address)
          print "#################################LIST ENTRIES##############################"
          print list_entries 
          match = parser.OFPMatch(ipv4_dst=ip_address,eth_type=0x0800)
          id_table = ID_FLW_ARP
          actions = [parser.OFPActionSetField(eth_dst=mac)]
          instructions =[parser.OFPInstructionGotoTable(ID_FLW_MAC, type_=None, len_=None)]
          instructions.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions))
          mod = parser.OFPFlowMod(
                    datapath = dp, match = match,
                    priority = 1, table_id = id_table, cookie = 0,
                    instructions = instructions)
          dp.send_msg(mod)
          for index in list_entries:
              logger.info("#################update with rip entry##############")
              mask_ip = ipaddr.IPv4Network(index[0]+'/'+str(index[1])).netmask
              match = parser.OFPMatch(ipv4_dst=(index[0],mask_ip),eth_type=0x0800)
              id_table = ID_FLW_ARP_R
              actions = [parser.OFPActionSetField(eth_dst=mac)]
              instructions =[parser.OFPInstructionGotoTable(ID_FLW_MAC, type_=None, len_=None)]
              instructions.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions))
              mod = parser.OFPFlowMod(
                     datapath = dp, match = match,
                     priority = 1, table_id = id_table, cookie = 0,
                     instructions = instructions)
              dp.send_msg(mod)
         
      def update_mac_table(self,mac_address,port):
          port_hw_addr = self.ports[port].mac_addr
          entry_mac = mac_entry(port,time.time())
          self.mac_to_port[mac_address]=port
          datapath = self.datapath
          ofproto = datapath.ofproto
          parser = datapath.ofproto_parser
          match = parser.OFPMatch(eth_dst=mac_address,eth_type=0x0800)
          actions=[parser.OFPActionSetField(eth_src=port_hw_addr),parser.OFPActionOutput(port)]
          inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
          mod = parser.OFPFlowMod(
                    datapath = datapath, table_id = ID_FLW_MAC, match = match,
                    priority = 1, instructions = inst) 
          datapath.send_msg(mod)
          logger.info('flow added to table %s , match = MacDst:%s , Actions = Output:%s ',ID_FLW_MAC ,mac_address,port)
      def update_routing_table(self,net_mask,entry):
          #PROTO =[STATIC,RIP,OSPF,BGP,...]
          # add to trie
          print "##########################Update Routing Table ##############################"
          print entry.gw
          mask_cidr = net_mask[1]
          if isinstance(net_mask[1],int):
             # convert cidr notation to ip representation
              mask_ip = ipaddr.IPv4Network(net_mask[0]+'/'+str(net_mask[1])).netmask

          self.lookup.add_prefix(net_mask[0],net_mask,net_mask[1])
          # add flow mod
          datapath = self.datapath
          ofproto = datapath.ofproto
          parser = datapath.ofproto_parser
          match = parser.OFPMatch(ipv4_dst=(net_mask[0],mask_ip),eth_type=0x0800)
          if isinstance(entry,router.static_entry):
              tableDest = ID_FLW_ARP
              self.routing_table[net_mask]=entry
              inst = [parser.OFPInstructionGotoTable(ID_FLW_ARP, type_=None, len_=None)]
              
          else:
              gw = entry.gw
              index,entry_stat=self.get_gw_by_ip(gw)
              entry.port=entry_stat.port
              tableDest = ID_FLW_ARP_R
              net_and_mask=(net_mask[0],mask_ip)
              self.routing_table[net_mask]=entry
              inst = [parser.OFPInstructionGotoTable(ID_FLW_ARP_R, type_=None, len_=None)]
               
          mod = parser.OFPFlowMod(
                    datapath = datapath, table_id = ID_FLW_ROUTING, match = match,
                    priority = 1, instructions = inst) 
          datapath.send_msg(mod)
          logger.info('flow added to table %s , match = IPV4_DST:%s , Actions = go_to_table:%s ',ID_FLW_ROUTING ,net_mask,tableDest) 
      def modify_route(self,entry):
          ''' modify route in forwarding table , send flow modify to associtated router'''
          logger.info("modify route in forwarding table , send flow modify to associtated router")
           
      def start_proto(self,proto_name,ip,rtr_id=None,netmask=None):
          if proto_name == 'RIP':
             # instanciate RIP object
             r= ripserv.RIP(520,self,None,[ip])
             self.proto['RIP']=r
          if proto_name == 'EIGRP':
             #instanciate eigrp object
             e = eigrp.EIGRP([ip],None,True,None,self,None,'224.0.0.10',0,kvalues=[ 1, 1, 1, 0, 0 ],rid=3,asn=1) 
             e.run()
             self.proto['EIGRP']=e 
          if proto_name=='OSPF':
	    self.proto['OSPF'] = ospf_mod.OSPF(self, rtr_id, ip, netmask)

       
      def add_port(self,no_port,mac_addr,name):
          port = Port(mac_addr,name)
          self.ports[no_port] = port
          return port
      def get_port_by_ip(self,ip):
          for index,port in self.ports.iteritems():
              if port.ip_addr == ip:
                 return index,port
          return None
           
      def get_gw_by_ip(self,ip_dest):
          index = self.lookup.get_longest_prefix_match(ip_dest)
          return index,self.routing_table[index]
      def get_local_routes(self,proto):
          routes ={}
          ''' For Test adding routes'''
          routes[('172.16.33.0','255.255.255.0')]=rip_entry(1,'192.168.1.40')
          if proto == 'RIP':
             for net_mask,entry in self.routing_table.iteritems():
                 if isinstance(entry,rip_entry):
                    routes[net_mask]=entry
          return routes
       
      def uninstall_route(self,ip_add,prefix_len):
          print "uninstall route"             
          
      def is_gw(self,gw):
          list_entries=[]
          for index, entry in self.routing_table.iteritems():
              if str(gw) == str(entry.gw):
                 list_entries.append(index)
          return list_entries
