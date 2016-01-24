from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.libopenflow_01 import *
from pox.lib.revent import *
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer
import time
import random
from pox.lib.util import dpid_to_str
from pox.topology import topology
from pox.lib.revent import *
from pox.lib.addresses import *
import traceback
import pickle
import pox
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpidToStr




switchlist = []
switchpath = defaultdict(lambda:[])


def _handle_ConnectionUp (event):
	# When a switch connects, forget about previous port states
	# _prev[event.dpid].clear()
	global switchlist
	if event.dpid not in switchlist:
		switchlist.append(event.dpid)
		switchpath[event.dpid] = event.connection
	print event.dpid



def _handle_ConnectionDown (event):
	global switchlist
	if event.dpid in switchlist:

		switchlist.remove(event.dpid)
		del switchpath[event.dpid]

	pass


def _handle_PacketIn (event):
	print switchpath[switchlist[1]]
	if (switchlist[0] != None) and (switchlist[1] != None):
		if switchlist[0] == 1:
			s1 = switchlist[0]
			s2 = switchlist[1]
		else:
			s1 = switchlist[1]
			s2 = switchlist[0]

		flow_1 = flow(nw_src = IPAddr('10.0.0.1'), nw_dst = IPAddr('10.0.0.2'), dl_type = 0x800)
		flow_1.flow_mod_port(outport = 1, s = s1)
		flow_1.flow_mod_port(outport = 2, s = s2)
		flow_2 = flow(nw_src = IPAddr('10.0.0.2'), nw_dst = IPAddr('10.0.0.1'), dl_type = 0x800)
		flow_2.flow_mod_port(outport = 2, s = s1)
		flow_2.flow_mod_port(outport = 1, s = s2)
		flow_3 = flow(nw_src = IPAddr('10.0.0.1'), nw_dst = IPAddr('10.0.0.2'), dl_type = 2054)
		flow_3.flow_mod_port(outport = 1, s = s1)
		flow_3.flow_mod_port(outport = 2, s = s2)
		flow_4 = flow(nw_src = IPAddr('10.0.0.2'), nw_dst = IPAddr('10.0.0.1'), dl_type = 2054)
		flow_4.flow_mod_port(outport = 2, s = s1)
		flow_4.flow_mod_port(outport = 1, s = s2)

	pass

class flow (object):
 	"""docstring for flow_establish"""
 	def __init__(self, dl_src = None, dl_dst = None, dl_vlan = None,
				   dl_vlan_pcp = None, dl_type = None, nw_tos = None, nw_proto = None,
				   nw_src = None, nw_dst = None, tp_src = None, tp_dst = None, exception_sign = False):
 		self.match_data = {
 		'dl_src' : dl_src,
 		'dl_dst' : dl_dst,
 		'dl_vlan' : dl_vlan,
 		'dl_vlan_pcp' : dl_vlan_pcp,
 		'dl_type' : dl_type,
 		'nw_tos' : nw_tos,
 		'nw_src' : nw_src,
 		'nw_dst' : nw_dst,
 		'tp_src' : tp_src,
 		'tp_dst' : tp_dst,
 		}
 	def flow_mod_port(self, outport, s):
 		msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
													# idle_timeout=FLOW_IDLE_TIMEOUT
													#hard_timeout=of.OFP_FLOW_PERMANENT
													)

		msg.match.dl_vlan = self.match_data['dl_vlan']
		msg.match.dl_vlan_pcp = self.match_data['dl_vlan_pcp']
		msg.match.dl_src = self.match_data['dl_src'] # Wildcard dst IP
		msg.match.dl_dst = self.match_data['dl_dst']
		msg.match.nw_proto = None
		msg.match.dl_type = self.match_data['dl_type']
		msg.match.nw_tos = self.match_data['nw_tos']
		msg.match.tp_src = self.match_data['tp_src']
		msg.match.tp_dst = self.match_data['tp_dst']
		msg.match.nw_src = self.match_data['nw_src'] # Wildcard dst IP
		msg.match.nw_dst = self.match_data['nw_dst']
		msg.actions.append(of.ofp_action_output(port = outport))
		switchpath[s].send(msg)



def launch():
	def start_flowpr ():

		core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
		core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)
		core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
	core.call_when_ready(start_flowpr, "openflow_discovery")
