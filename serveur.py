#!/usr/bin/python2.7

import socket
import cmd
import gevent, gevent.server
from telnetsrv.green import TelnetHandler, command
import netaddr
import lxc
import time
from ryu.base import app_manager
import threading
from ryu.lib import hub


class Cli(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(Cli, self).__init__(*args, **kwargs)
        hub.spawn(self.loop)

    def loop(self):
        server = gevent.server.StreamServer(("", 8025),
                                            MyTelnetHandler.streamserver_handle)
        server.serve_forever()
class MyTelnetHandler(TelnetHandler):
    WELCOME = "\n tap the command 'choose' to start the config \n"
    
    def __init__(self):
        pass
    @command(['choose'])
    def choose(self, params):
     try:
      dpids={}
      dpids[0]=445566
      dpids[1]=112233
      self.writeresponse('\n select a router from the list')
      for i in dpids:
           self.writeresponse(' router %s : %s \n' %(i+1, dpids[i],))
      dpid_choisi = self.readline()
      self.writeresponse(' Welcome to the router %s config \r' %dpids[int(dpid_choisi)-1])
      self.writeresponse(" Available commands 'Interface', 'Router' , command --help for more informations ")
     except KeyError:
	   self.writeresponse('rooter ID is invalid')
    @command(['echo', 'copy', 'repeat'])
    def command_echo(self, params):
        '''<text to echo>
        Echo text back to the console.

        '''
        self.writeresponse( ' '.join(params) )
    # ===================
    # command : INTERFACE 
    # ===================

    @command(['interface', 'inter', 'int'])
    def interface(self, params):
	c = lxc.Container("Container2") #container name, should be dpid
	try:
	  help = ['help', '--help']
	  if params[0] in help:
	    self.writeresponse('[port, adress, mask] this commands configure the --address to the interface which have the --port')
	  elif len(params) is not 3:
	    self.writeresponse('interface take 3 arguments : port, address, mask')
	  elif len(params) is 3:
	    # launch L3.forwarding. 
	    # ........
	    # ==========================================
	    # add code to do the same thing in the OVS /
	    # ==========================================
	    # check if address is valide

	    ip_addr = netaddr.IPAddress(params[1])
	    mask = netaddr.IPAddress(params[2])
	    if c.running:
		# ===================================
		# updating the iface in the container 
		# ===================================
		c.attach_wait(lxc.attach_run_command,["ifconfig", "eth0", str(ip_addr),"netmask", str(mask)])
		time.sleep(1)
		self.writeresponse('interface updated successfully')
	except IndexError:
	    self.writeresponse('interface take 3 arguments : port, address, mask')

    # =================
    # command : ROUTER  
    # =================

    @command(['router', 'r', 'repeat'])
    def router(self, params):
	c = lxc.Container("Container2")
	try:
	   help = ['help', '--help']
	   protocol = ['rip', 'ospf', 'bgp', 'isis']

	   # all params are in
	   if len(params) is 3:
	     ip_addr = netaddr.IPAddress(params[1])
	     mask    = netaddr.IPAddress(params[2])
	     Nmask   = sum([bin(int(x)).count('1') for x in str(mask).split('.')])

	     # ROUTER --help
	     if params[0] in help:
		self.writeresponse('this command activate --protocol in the --network')
	     
	     if params[0] in protocol: # 3 args : enabling proto 'params[0]' in the network given 'params[1]'
		self.writeresponse('enabling %s in %s ... ' %(params[0], params[1],))
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# ENABLING RIP >>>>
		if params[0] == 'rip':
		  sock.connect(('10.0.3.14',2602))
		  sock.send('zebra\renable \rconf t \rrouter rip \rversion 2 \rnetwork %s/%s \rend \rexit \r' %(ip_addr, Nmask))
		  time.sleep(2)
		  self.writeresponse(sock.recv(2048))
		  time.sleep(2)
		  sock.close()
		  self.writeresponse('%s enabled successfully' %params[0])

		# ENABLING OSPF >>>>
		if params[0] == 'ospf':
		  sock.connect(('10.0.3.14',2604)) # connct to container's mngmt_if 
		  sock.send('zebra\renable \rconf t \rrouter ospf \rversion 2 \rnetwork %s/%s \rend \rexit \r' %(ip_addr, Nmask))
		  time.sleep(2)
		  sock.close()
		  self.writeresponse('%s enabled successfully' %params[0])

		# ENABLING BGP >>>>
		if params[0] == 'bgp':
		  sock.connect(('10.0.3.14',2605))
		  sock.send('zebra\renable \rconf t \rrouter bgp \rversion 2 \rnetwork %s/%s \rend \rexit \r' %(ip_addr, Nmask))
		  time.sleep(2)
		  sock.close()
		  self.writeresponse('%s enabled successfully' %params[0])

		# ENABLING ISIS >>>>
		if params[0] == 'isis':
		  sock.connect(('10.0.3.14',2608))
		  sock.send('zebra\renable \rconf t \rrouter isis \rversion 2 \rnetwork %s/%s \rend \rexit \r' %(ip_addr, Nmask))
		  time.sleep(2)
		  sock.close()
		  self.writeresponse('%s enabled successfully' %params[0])
	     else:
		self.writeresponse('unknown protocol %s' %params[0])
	   else:
		self.writeresponse('Router take exactly 3 argument : --proto [rip, ospf, isis, bgp], --network, --mask')
	except IndexError:
	   self.writeresponse('Router take exactly 3 argument : --proto [rip, ospf, isis, bgp], --network, --mask')




'''
class Commands(cmd.Cmd):
	def __init__(self, sock):
	    cmd.Cmd.__init__(self)
	    self.sock=sock
  	def do_interface(self,interface):
            sock.send(interface)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('', 4444))
sock.listen(2)
dpids={}
dpids[0]=445566
dpids[1]=112233
while True:
	var1, var2 = sock.accept()
	var1.send('choose router \n')
	for i in dpids:
	   var1.send('router %s : %s \n' %(i+1, dpids[i],) )
	var1.send('> ')
	dpid_choosen = var1.recv(2048)
	var1.send('Weclome to the configuration CLI of the router. \n \n Disponible commands : \n=====================\n') 
	var1.send('Interface portNmbr NwAddr => set the NwAddr to the interface with the portNmbr \n \nrouteur %s> ' %(dpids[int(dpid_choosen)-1]))
	interface = var1.recv(2048)
	cmd = Commands(var1)
	cmd.cmdloop()
'''
	
	


	
	

