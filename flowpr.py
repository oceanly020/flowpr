#coding=utf-8 


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


generated_matrix = []
generated_matrix_new = True


log = core.getLogger()
switchlist = []
switchpath = defaultdict(lambda:[])
adjacency_port = defaultdict(lambda:defaultdict(lambda:[]))
IPv4Table = {}
FLOW_IDLE_TIMEOUT = 10
end_leaf_nodes = set()

class flow_root(object):
	def __init__(self):

		self.nodes_down = set()
		self.context_down = set()
		self.flow_graph = []
		self.generated_matrix_new = True
		self.active_action = False
		# self.end_leaf_sign = False
		# self.may_overlap_nodes = end_leaf_nodes

flow_root = flow_root()

match_data = (
		'nw_src',
 		'nw_dst',
 		'dl_src',
 		'dl_dst',
 		'dl_vlan',
 		'dl_vlan_pcp',
 		'tp_src',
 		'tp_dst',
 		# 'dl_type',
 		'nw_tos')
match_data_addr = (
		'nw_src',
 		'nw_dst',
 		'dl_src',
 		'dl_dst',
 		)      #前面的IP和MAC地址比对
match_data_ord = (
 		'dl_vlan',
 		'dl_vlan_pcp',
 		'tp_src',
 		'tp_dst',
 		# 'dl_type',
 		'nw_tos') #直接比对内容
def lvl_element_init():
	global lvl_element
	for i in range(0,len(match_data)+1):
		tmp = []
		lvl_element.append(tmp)
	lvl_element[0].append(flow_root)
	# print lvl_element
lvl_element = []
lvl_element_init()


def _calc_generated_matrix (): #初始计算生成矩阵,当网络变化,重新计算
 	"""
	calc topo flow_root.flow_graph
	"""
	# global generated_matrix, generated_matrix_new
	def flip (link):
		return Discovery.Link(link[2], link[3], link[0], link[1])

	startTimeStamp1=time.time()


	adj = defaultdict(lambda:defaultdict(lambda:[]))
	# switches = set()
	# Add all links and switches

	for l in core.openflow_discovery.adjacency:
		adj[l.dpid1][l.dpid2].append(l)
		# switches.add(l.dpid1)
		# switches.add(l.dpid2)

	# Cull links -- we want a single symmetric link connecting nodes
	GMN = len(switchlist)#matrix N*N
	if flow_root.generated_matrix_new == True:
		flow_root.flow_graph = []
		for j in range(0, GMN):
			tmp = []
			for i in range(0, GMN):
				tmp.append(60000)
			flow_root.flow_graph.append(tmp)
		flow_root.generated_matrix_new = False
	elif flow_root.generated_matrix_new == False:
		for j in range(0, GMN):
			for i in range(0, GMN):
				flow_root.flow_graph[i][j] = 60000

 	#switchlist = list(switches)#ordered list for matrix,will be globle v

	for s1 in switchlist:
		flow_root.flow_graph[switchlist.index(s1)][switchlist.index(s1)] = 60000
		for s2 in switchlist:
			if s2 not in adj[s1]:
				continue
			flow_root.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = 1
			assert s1 is not s2
	for x in range(1,len(match_data)+1):
		for f in lvl_element[x]:
			f.calc_flow_graph()
	# 	print f.flow_graph
	# 	print f.nodes_up
	# print flow_root.nodes_down

	endTimeStamp4 = time.time()
	print "UpdateTime:",(endTimeStamp4 - startTimeStamp1)*1000,"ms" #UpdateTime
_prev = defaultdict(lambda : defaultdict(lambda : None))



# switchtest = []

def _handle_ConnectionUp (event): #ConnectionUp事件操作
	# When a switch connects, forget about previous port states
	# _prev[event.dpid].clear()
	global switchlist
	if event.dpid not in switchlist:
		switchlist.append(event.dpid)
		switchpath[event.dpid] = event.connection
		flow_root.generated_matrix_new = True




def _handle_ConnectionDown (event):
	global switchlist
	if event.dpid in switchlist:
		switchlist.remove(event.dpid)
		del switchpath[event.dpid]

	pass


def _handle_LinkEvent (event):

	global adjacency_port, switchlist
	if event.added is True:
		s1 = event.link[0]
		s2 = event.link[2]
		if s1 not in adjacency_port:
			adjacency_port[s1][s2] = event.link[1]
		elif s2 not in adjacency_port[s1]:
			adjacency_port[s1][s2] = event.link[1]
		if s2 not in adjacency_port:
			adjacency_port[s2][s1] = event.link[3]
		elif s1 not in adjacency_port[s2]:
			adjacency_port[s2][s1] = event.link[3]


	if event.removed is True:
		s1 = event.link[0]
		s2 = event.link[2]
		if s1 in adjacency_port:
			if s2 in adjacency_port[s1]:
				del adjacency_port[s1][s2]
			if len(adjacency_port[s1]) is 0:
				del adjacency_port[s1]
		if s2 in adjacency_port:
			if s1 in adjacency_port[s2]:
				del adjacency_port[s2][s1]
			if len(adjacency_port[s2]) is 0:
				del adjacency_port[s2]
	# print adjacency_port


	_calc_generated_matrix()
	pass

def dpid_to_mac (dpid):
	return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


def _handle_flow_stats(event):
	# web_bytes = 0
	# web_flows = 0
	# for f in event.stats:

	# 	if f.match.tp_dst == 80 or f.match.tp_src == 80:#pox.openflow.libopenflow_01.ofp_flow_stats object
	# 		web_bytes += f.byte_count
	# 		web_flows += 1
	# 	log.info("Web traffic: %s bytes over %s flows", web_bytes, web_flows)
	pass

def _handle_queue_stats(event):
	# print event.dpid
	pass

def _handle_port_stats(event):
	# print event


	pass
def _handle_table_stats(event):

	# print event.wildcards
	pass

class Entry (object):
	"""
	We use the port to determine which port to forward traffic out of.
	We use the timeout so that if an entry is older than ARP_TIMEOUT, we

	"""
	def __init__ (self, dpid, port):
		# self.timeout = time.time() + ARP_TIMEOUT
		self.port = port
		self.dpid = dpid
		# self.mac = mac

	# def __eq__ (self, other):
	# 	if type(other) == tuple:
	# 		return (self.port,self.mac)==other
	# 	else:
	# 		return (self.port,self.mac)==(other.port,other.mac)
	# def __ne__ (self, other):
	# 	return not self.__eq__(other)

	# def isExpired (self):
	# 	if self.port == of.OFPP_NONE: return False
	# 	return time.time() > self.timeout


def _handle_PacketIn (event):

	global IPv4Table, adjacency_port
	adjacency_port_in = adjacency_port
	packet = event.parsed
	dpid = event.connection.dpid
	inport = event.port
	# print "packet in"

	# print packet.next
	FLOW_IDLE_TIMEOUT = 100




	if isinstance(packet.next, ipv4):# upload the packet flow policy__can simplified by match
		packetflow = packet_flow(packet = packet)
		p = packet.next
		if p.srcip in IPv4Table:
			if IPv4Table[p.srcip] != (inport, p.srcip):
				IPv4Table[p.srcip] = Entry(dpid, inport) #re-recording


			else:
				IPv4Table[p.srcip] = Entry(dpid, inport) #new-recording
		# print packet.next



		if p.dstip != 0:
			if p.dstip in IPv4Table:

				prt = IPv4Table[p.dstip].port
				dpid_dst = IPv4Table[p.dstip].dpid


				path = packetflow.D_path_find(s1 = dpid, s2 = dpid_dst) # clc path
				# path = D_path_find_test # clc path
				if path == False:
					pass
				else:
					if (len(path) == 2) and (path[0] == path[1]):
						msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
											idle_timeout=FLOW_IDLE_TIMEOUT
											#hard_timeout=of.OFP_FLOW_PERMANENT
											)
						msg.actions.append(of.ofp_action_output(port = prt))
						# msg.match.in_port = adjacency_port_in[s][path[path.index(s)+1]]
						in_port = packetflow.in_port
						# msg.match.nw_src = a.protosrc # Wildcard source IP
						# msg.match.nw_dst = a.protodst # Wildcard dst IP
						# msg.match = of.ofp_match.from_packet(packet, in_port)
						msg.match.dl_vlan = packetflow.match_data['dl_vlan']
						msg.match.dl_vlan_pcp = packetflow.match_data['dl_vlan_pcp']
						msg.match.dl_src = packetflow.match_data['dl_src'] # Wildcard dst IP
						msg.match.dl_dst = packetflow.match_data['dl_dst']
						msg.match.nw_proto = packetflow.match_data['nw_proto']
						msg.match.dl_type = packetflow.match_data['dl_type']
						msg.match.nw_tos = packetflow.match_data['nw_tos']
						msg.match.tp_src = packetflow.match_data['tp_src']
						msg.match.tp_dst = packetflow.match_data['tp_dst']
						msg.match.nw_src = packetflow.match_data['nw_src'] # Wildcard dst IP
						msg.match.nw_dst = packetflow.match_data['nw_dst']
						switchpath[path[1]].send(msg)
					else:

						for s in path: # update path

							if s == dpid_dst:
								msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
														idle_timeout=FLOW_IDLE_TIMEOUT
														#hard_timeout=of.OFP_FLOW_PERMANENT
														)
								msg.actions.append(of.ofp_action_output(port = prt))
								# msg.match.in_port = adjacency_port_in[s][path[path.index(s)+1]]

								# msg.match.nw_src = p.srcip # Wildcard source IP
								# msg.match.nw_dst = p.dstip # Wildcard dst IP
								in_port = adjacency_port_in[s][path[path.index(s)+1]]
								# msg.match = of.ofp_match.from_packet(packet, in_port)
								msg.match.dl_vlan = packetflow.match_data['dl_vlan']
								msg.match.dl_vlan_pcp = packetflow.match_data['dl_vlan_pcp']
								msg.match.dl_src = packetflow.match_data['dl_src'] # Wildcard dst IP
								msg.match.dl_dst = packetflow.match_data['dl_dst']
								msg.match.nw_proto = packetflow.match_data['nw_proto']
								msg.match.dl_type = packetflow.match_data['dl_type']
								msg.match.nw_tos = packetflow.match_data['nw_tos']
								msg.match.tp_src = packetflow.match_data['tp_src']
								msg.match.tp_dst = packetflow.match_data['tp_dst']
								msg.match.nw_src = packetflow.match_data['nw_src'] # Wildcard dst IP
								msg.match.nw_dst = packetflow.match_data['nw_dst']


								# print msg.match,s
								switchpath[s].send(msg)



							else:
								if s != dpid:
									msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
														idle_timeout=FLOW_IDLE_TIMEOUT
														#hard_timeout=of.OFP_FLOW_PERMANENT
														)
									outport = adjacency_port[s][path[path.index(s)-1]]
									msg.actions.append(of.ofp_action_output(port = outport))
									# msg.match.in_port = adjacency_port[s][path[path.index(s)+1]]
									# msg.match.nw_src = p.srcip # Wildcard source IP
									# msg.match.nw_dst = p.dstip # Wildcard dst IP
									in_port = adjacency_port[s][path[path.index(s)+1]]
									# msg.match = of.ofp_match.from_packet(packet, in_port)
									msg.match.dl_vlan = packetflow.match_data['dl_vlan']
									msg.match.dl_vlan_pcp = packetflow.match_data['dl_vlan_pcp']
									msg.match.dl_src = packetflow.match_data['dl_src'] # Wildcard dst IP
									msg.match.dl_dst = packetflow.match_data['dl_dst']
									msg.match.nw_proto = packetflow.match_data['nw_proto']
									msg.match.dl_type = packetflow.match_data['dl_type']
									msg.match.nw_tos = packetflow.match_data['nw_tos']
									msg.match.tp_src = packetflow.match_data['tp_src']
									msg.match.tp_dst = packetflow.match_data['tp_dst']
									msg.match.nw_src = packetflow.match_data['nw_src'] # Wildcard dst IP
									msg.match.nw_dst = packetflow.match_data['nw_dst']



									# print msg.match,s
									switchpath[s].send(msg)


								else:
									msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
														idle_timeout=FLOW_IDLE_TIMEOUT
														#hard_timeout=of.OFP_FLOW_PERMANENT
														)
									outport = adjacency_port[s][path[path.index(s)-1]]
									msg.actions.append(of.ofp_action_output(port = outport))


									# msg.match.in_port = inport
									# msg.match.nw_src = p.srcip # Wildcard source IP
									# msg.match.nw_dst = p.dstip # Wildcard dst IP
									# msg.match = of.ofp_match.from_packet(packet, inport)
									msg.match.in_port = packetflow.in_port
									msg.match.dl_vlan = packetflow.match_data['dl_vlan']
									msg.match.dl_vlan_pcp = packetflow.match_data['dl_vlan_pcp']
									msg.match.dl_src = packetflow.match_data['dl_src'] # Wildcard dst IP
									msg.match.dl_dst = packetflow.match_data['dl_dst']
									msg.match.nw_proto = packetflow.match_data['nw_proto']
									msg.match.dl_type = packetflow.match_data['dl_type']
									msg.match.nw_tos = packetflow.match_data['nw_tos']
									msg.match.tp_src = packetflow.match_data['tp_src']
									msg.match.tp_dst = packetflow.match_data['tp_dst']
									msg.match.nw_src = packetflow.match_data['nw_src'] # Wildcard dst IP
									msg.match.nw_dst = packetflow.match_data['nw_dst']



									# print msg.match,s
									switchpath[s].send(msg)

		pass

	elif isinstance(packet.next, arp): # upload the packet flow policy
		startTimeStamp=time.time()
		packetflow = packet_flow(packet = packet)
		endTimeStamp1 = time.time()
		# print packetflow.flow_graph
		# print switchlist
		print "PacketflowEstabelishied:",(endTimeStamp1 - startTimeStamp)*1000,"ms"
		a = packet.next
		if a.prototype == arp.PROTO_TYPE_IP:
			if a.hwtype == arp.HW_TYPE_ETHERNET:
				if a.protosrc != 0:
					if a.protosrc in IPv4Table:
						if IPv4Table[a.protosrc] != (inport, packet.src):
							IPv4Table[a.protosrc] = Entry(dpid, inport) #re-recording


					else:
						IPv4Table[a.protosrc] = Entry(dpid, inport) #new-recording
					# print packet.next


				FLOW_IDLE_TIMEOUT = 10
				if a.protodst != 0:

					if a.protodst in IPv4Table:
						prt = IPv4Table[a.protodst].port
						dpid_dst = IPv4Table[a.protodst].dpid
						# print prt

						startTimeStamp=time.time()
						path = packetflow.D_path_find(s1 = dpid, s2 = dpid_dst) # clc path
						# print path
						endTimeStamp2 = time.time()
						print "PathCalc:",(endTimeStamp2 - startTimeStamp)*1000,"ms"
						startTimeStamp=time.time()
						if path == False:
							pass

						else:
							if (len(path) == 2) and (path[0] == path[1]):
								msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
													idle_timeout=FLOW_IDLE_TIMEOUT
													#hard_timeout=of.OFP_FLOW_PERMANENT
													)
								msg.actions.append(of.ofp_action_output(port = prt))
								# msg.match.in_port = adjacency_port_in[s][path[path.index(s)+1]]
								in_port = packetflow.in_port
								# msg.match.nw_src = a.protosrc # Wildcard source IP
								# msg.match.nw_dst = a.protodst # Wildcard dst IP
								# msg.match = of.ofp_match.from_packet(packet, in_port)

								msg.match.dl_vlan = packetflow.match_data['dl_vlan']
								msg.match.dl_vlan_pcp = packetflow.match_data['dl_vlan_pcp']
								msg.match.dl_src = packetflow.match_data['dl_src'] # Wildcard dst IP
								msg.match.dl_dst = packetflow.match_data['dl_dst']
								msg.match.nw_proto = packetflow.match_data['nw_proto']
								msg.match.dl_type = packetflow.match_data['dl_type']
								msg.match.nw_tos = packetflow.match_data['nw_tos']
								msg.match.tp_src = packetflow.match_data['tp_src']
								msg.match.tp_dst = packetflow.match_data['tp_dst']
								msg.match.nw_src = packetflow.match_data['nw_src'] # Wildcard dst IP
								msg.match.nw_dst = packetflow.match_data['nw_dst']
								switchpath[path[1]].send(msg)

							else:

								for s in path: # update path
									if s == dpid_dst:
										msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
															idle_timeout=FLOW_IDLE_TIMEOUT
															#hard_timeout=of.OFP_FLOW_PERMANENT
															)
										msg.actions.append(of.ofp_action_output(port = prt))
										# msg.match.in_port = adjacency_port_in[s][path[path.index(s)+1]]
										in_port = adjacency_port_in[s][path[path.index(s)+1]]
										# msg.match.nw_src = a.protosrc # Wildcard source IP
										# msg.match.nw_dst = a.protodst # Wildcard dst IP
										msg.match = of.ofp_match.from_packet(packet, in_port)

										msg.match.dl_vlan = packetflow.match_data['dl_vlan']
										msg.match.dl_vlan_pcp = packetflow.match_data['dl_vlan_pcp']
										msg.match.dl_src = packetflow.match_data['dl_src'] # Wildcard dst IP
										msg.match.dl_dst = packetflow.match_data['dl_dst']
										msg.match.nw_proto = packetflow.match_data['nw_proto']
										msg.match.dl_type = packetflow.match_data['dl_type']
										msg.match.nw_tos = packetflow.match_data['nw_tos']
										msg.match.tp_src = packetflow.match_data['tp_src']
										msg.match.tp_dst = packetflow.match_data['tp_dst']
										msg.match.nw_src = packetflow.match_data['nw_src'] # Wildcard dst IP
										msg.match.nw_dst = packetflow.match_data['nw_dst']

										# print msg.match,s
										switchpath[s].send(msg)



									else:
										if s != dpid:
											msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
																idle_timeout=FLOW_IDLE_TIMEOUT
																#hard_timeout=of.OFP_FLOW_PERMANENT
																)
											outport = adjacency_port[s][path[path.index(s)-1]]
											msg.actions.append(of.ofp_action_output(port = outport))
											# msg.match.in_port = adjacency_port[s][path[path.index(s)+1]]
											in_port = adjacency_port[s][path[path.index(s)+1]]
											# msg.match.nw_src = a.protosrc # Wildcard source IP
											# msg.match.nw_dst = a.protodst # Wildcard dst IP
											# msg.match = of.ofp_match.from_packet(packet, in_port)

											msg.match.dl_vlan = packetflow.match_data['dl_vlan']
											msg.match.dl_vlan_pcp = packetflow.match_data['dl_vlan_pcp']
											msg.match.dl_src = packetflow.match_data['dl_src'] # Wildcard dst IP
											msg.match.dl_dst = packetflow.match_data['dl_dst']
											msg.match.nw_proto = packetflow.match_data['nw_proto']
											msg.match.dl_type = packetflow.match_data['dl_type']
											msg.match.nw_tos = packetflow.match_data['nw_tos']
											msg.match.tp_src = packetflow.match_data['tp_src']
											msg.match.tp_dst = packetflow.match_data['tp_dst']
											msg.match.nw_src = packetflow.match_data['nw_src']
											msg.match.nw_dst = packetflow.match_data['nw_dst']

											# print msg.match,s
											switchpath[s].send(msg)


										else:
											msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
																 idle_timeout=FLOW_IDLE_TIMEOUT
																#hard_timeout=of.OFP_FLOW_PERMANENT
																)
											outport = adjacency_port[s][path[path.index(s)-1]]
											msg.actions.append(of.ofp_action_output(port = outport))
											# msg.actions.append(of.ofp_action_nw_addr.set_dst(a.protodst))
											# msg.actions.append(of.ofp_action_nw_addr.set_src(a.protosrc))
											# msg.match = of.ofp_match.from_packet(packet, inport)
											# msg.match = of.ofp_match.from_packet(packet, inport)

											msg.match.in_port = packetflow.in_port
											msg.match.dl_vlan = packetflow.match_data['dl_vlan']
											msg.match.dl_vlan_pcp = packetflow.match_data['dl_vlan_pcp']
											msg.match.dl_src = packetflow.match_data['dl_src'] # Wildcard dst IP
											msg.match.dl_dst = packetflow.match_data['dl_dst']
											msg.match.nw_proto = packetflow.match_data['nw_proto']
											msg.match.dl_type = packetflow.match_data['dl_type']
											msg.match.nw_tos = packetflow.match_data['nw_tos']
											msg.match.tp_src = packetflow.match_data['tp_src']
											msg.match.tp_dst = packetflow.match_data['tp_dst']
											msg.match.nw_src = packetflow.match_data['nw_src'] # Wildcard dst IP
											msg.match.nw_dst = packetflow.match_data['nw_dst']

											# msg.match.in_port = inport
											# msg.match.nw_src = a.protosrc # Wildcard source IP
											# msg.match.nw_dst = a.protodst # Wildcard dst IP

											# print msg.match,s
											switchpath[s].send(msg)
							endTimeStamp3 = time.time()
							print "RuleInstalled:",(endTimeStamp3 - startTimeStamp)*1000,"ms"






def flow_from_packet(packet_flow, packet): # head of match of packet_in
	if isinstance(packet, ofp_packet_in):
		in_port = packet.in_port
		packet = ethernet(packet.data)
	assert assert_type("packet", packet, ethernet, none_ok=False)


	if in_port is not None:
		packet_flow.match.in_port = in_port

	packet_flow.match.dl_src = packet.src
	packet_flow.match.dl_dst = packet.dst
	packet_flow.match.dl_type = packet.type
	p = packet.next
	if isinstance(p, vlan):
	  packet_flow.match.dl_type = p.eth_type
	  packet_flow.match.dl_vlan = p.id
	  packet_flow.match.dl_vlan_pcp = p.pcp
	  p = p.next
	else:
	  packet_flow.match.dl_vlan = OFP_VLAN_NONE
	  packet_flow.match.dl_vlan_pcp = 0

	if isinstance(p, ipv4):
		packet_flow.match.nw_src = p.srcip
		packet_flow.match.nw_dst = p.dstip
		packet_flow.match.nw_proto = p.protocol
		packet_flow.match.nw_tos = p.tos
		p = p.next

		if isinstance(p, udp) or isinstance(p, tcp):
			packet_flow.match.tp_src = p.srcport
			packet_flow.match.tp_dst = p.dstport
		elif isinstance(p, icmp):
			packet_flow.match.tp_src = p.type
			packet_flow.match.tp_dst = p.code
	elif isinstance(p, arp):
		if p.opcode <= 255:
			packet_flow.match.nw_proto = p.opcode
			packet_flow.match.nw_src = p.protosrc
			packet_flow.match.nw_dst = p.protodst

	pass

def request_flowstats():
	for con in core.openflow.connections:

		# con.send(of.ofp_stats_request(body = of.ofp_flow_stats_request()))
		# con.send(of.ofp_stats_request(body = of.ofp_queue_stats_request()))
		# con.send(of.ofp_stats_request(body = of.ofp_port_stats_request()))
		# con.send(of.ofp_stats_request(body = of.ofp_table_stats_request()))

		pass

class packet_flow(object):
	"""docstring for packet_flow"""
	def __init__(self, packet):
		self.match_data = {
 		'dl_src' : None,
 		'dl_dst' : None,
 		'dl_vlan' : None,
 		'dl_vlan_pcp' : None,
 		'dl_type' : None,
 		'nw_tos' : None,
 		'nw_src' : None,
 		'nw_dst' : None,
 		'tp_src' : None,
 		'tp_dst' : None,
 		'nw_proto' : None
 		}
		# self.dl_src = None
		# self.dl_dst = None
		# self.dl_vlan = None
		# self.dl_vlan_pcp = None
		# self.dl_type = None
		# self.nw_tos = None
		# self.nw_proto = None
		# self.nw_dst = None
		# self.tp_src = None
		# self.tp_dst = None
		self.in_port = None
		self.nodes_up = []
		self.flow_graph = self.matrix_assign(matrix = flow_root.flow_graph)
		self.flow_from_packet(packet = packet)
		self.flow_match_intree()
		self.calc_flow_graph()
		self.may_overlap_nodes = set()
		self.calc_max_granule_flow()
		print self.match_data



		# print self.nodes_up[0].flow_graph


	def matrix_assign(self, matrix):
		GMN = len(switchlist)
		matrix_tmp = []
		for j in range(0, GMN):
			tmp = []
			for i in range(0, GMN):
				tmp.append(60000)
			matrix_tmp.append(tmp)
		for j in range(0, GMN):
			for i in range(0, GMN):
				matrix_tmp[j][i] = matrix[j][i]
		return matrix_tmp


	def flow_from_packet(self, packet): # head of match of packet_in
		in_port = None
		if isinstance(packet, ofp_packet_in):
			in_port = packet.in_port
			packet = ethernet(packet.data)
		assert assert_type("packet", packet, ethernet, none_ok=False)


		if in_port is not None:
			self.in_port = in_port

		self.match_data['dl_src'] = packet.src
		self.match_data['dl_dst'] = packet.dst
		self.match_data['dl_type'] = packet.type
		p = packet.next
		if isinstance(p, vlan):
		  self.match_data['dl_type'] = p.eth_type
		  self.match_data['dl_vlan'] = p.id
		  self.match_data['dl_vlan_pcp'] = p.pcp
		  p = p.next
		else:
		  self.match_data['dl_vlan'] = OFP_VLAN_NONE
		  self.match_data['dl_vlan_pcp'] = 0

		if isinstance(p, ipv4):
			self.match_data['nw_src'] = p.srcip
			self.match_data['nw_dst'] = p.dstip
			self.match_data['nw_proto'] = p.protocol
			self.match_data['nw_tos'] = p.tos
			p = p.next

			if isinstance(p, udp) or isinstance(p, tcp):
				self.match_data['tp_src'] = p.srcport
				self.match_data['tp_dst'] = p.dstport
			elif isinstance(p, icmp):
				self.match_data['tp_src'] = p.type
				self.match_data['tp_dst'] = p.code
		elif isinstance(p, arp):
			if p.opcode <= 255:
				self.match_data['nw_proto'] = p.opcode
				self.match_data['nw_src'] = p.protosrc
				self.match_data['nw_dst'] = p.protodst



	def calc_flow_graph(self):
		self.flow_graph = self.matrix_assign(matrix = flow_root.flow_graph)
		nodes_up_len = len(self.nodes_up)
		# self.flow_graph = self.nodes_up[nodes_up_len - 1].flow_graph
		for x in range(1,nodes_up_len + 1):
			i = nodes_up_len - x
			for s1 in switchlist:
				for s2 in switchlist:
					if self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] < self.nodes_up[i].flow_graph[switchlist.index(s1)][switchlist.index(s2)]:
						self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = self.nodes_up[i].flow_graph[switchlist.index(s1)][switchlist.index(s2)]
		self.calc_actions_graph()


	def calc_actions_graph(self):

			p_tmp = 0
			tmp = False
			for f in self.nodes_up:
				if f.active_action == False:
					continue
				else:
					if f.active_action.priority > p_tmp:
						tmp = f.active_action
						p_tmp = f.active_action.priority
			if tmp == False:
				pass
			else:
				self.active_action = tmp
				# print self.active_action
				if self.active_action.action_name == 'Attach_to_Path':
					self.attach_to_path(path = self.active_action.path)
				elif ac.action_name == 'Flow_forbidden':

					self.flow_forbidden(allow_set = ac.allow_set)
	def attach_to_path(self, path):
		path_len = len(path)
		for s in switchlist:
			if s in path:
				if path.index(s) != path_len - 1:
					for s2 in switchlist:
						if s2 == path[path.index(s)+1]:
							pass
						else:
							self.flow_graph[switchlist.index(s)][switchlist.index(s2)] = 60000
				else:
					for s2 in switchlist:
						self.flow_graph[switchlist.index(s)][switchlist.index(s2)] = 60000
			else:
				for s2 in switchlist:
					self.flow_graph[switchlist.index(s)][switchlist.index(s2)] = 60000

		pass
	def flow_forbidden(self, allow_set):
		for s1 in switchlist:
			for s2 in switchlist:
				if s2 not in allow_set:
					self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = 60000
				if s1 not in allow_set:
					self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = 60000

	def flow_match_intree(self): # finf the packet_flow's nodes_up[]
		lvl = len(match_data)
		for x in range(1,len(match_data)+1):
			i = len(match_data)+1 - x
			if lvl_element[i] != None:
				for f in lvl_element[i]:
					contain = True
					for m in match_data_addr:
						if f.match_data[m] == None:
							continue
						elif self.match_data[m] == None:
							contain = False
							break
						elif f.match_data[m].addr != self.match_data[m]:
							contain = False
							break
					if contain == False:
						continue
					for m in match_data_ord:
						if f.match_data[m] != self.match_data[m]:
							if f.match_data[m] != None:
								contain = False
								break
							elif f.match_data[m] == None:
								continue
					if contain == True:
						nodes_up_sign = True
						for f2 in self.nodes_up:
							if f in f2.related_flow:
								nodes_up_sign == False
								break
						if nodes_up_sign == True:
							self.nodes_up.append(f)
		if len(self.nodes_up) == 0:
			self.nodes_up.append(flow_root)

		# for x in range(1,len(match_data)+1):
		# 	pass

	def calc_max_granule_flow(self):
		# rest_none = set()
		# for f in nodes_up:
		# 	for f1 in f.may_overlap_nodes:
		# 		if f1 not in self.may_overlap_nodes:
		# 			self.may_overlap_nodes.add(f1)
		# for f in self.may_overlap_nodes:
		# 	for m in match_data:
		# 		if f.match_data[m] != None:
		# 			rest_none.add(m)
		# for m in match_data:
		# 	if m not in rest_none:
		# 		self.match_data[m] = Nonecore.openflow.addListenerByName("PacketIn", _handle_PacketIn)


		match_data_amend = {
 		'dl_src' : None,
 		'dl_dst' : None,
 		'dl_vlan' : None,
 		'dl_vlan_pcp' : None,
 		'dl_type' : None,
 		'nw_tos' : None,
 		'nw_src' : self.match_data['nw_src'],
 		'nw_dst' : self.match_data['nw_dst'],
 		'tp_src' : None,
 		'tp_dst' : None,
 		}
 		if (len(self.nodes_up) == 1) and (self.nodes_up[0] is flow_root):#find the max granule when the node up is root.
 			for f in flow_root.nodes_down:
 				intersection = True
 				for m in match_data_addr:
 					if f.match_data[m] != None:
 						if match_data_amend[m] != None:
 							if match_data_amend[m] != f.match_data[m].addr:
 								intersection = False
 								break
 				if intersection == False:
 					continue
 				else:
 					for m in match_data_ord:
 						if f.match_data[m] != None:
 							if match_data_amend[m] != None:
 								if match_data_amend[m] != f.match_data[m]:
 									intersection = False
 									break
 				if intersection == True:
 					break_sign = False
 					for m in match_data_addr:
 						if match_data_amend[m] == None:
 							if f.match_data[m] != None:
 								if self.match_data[m] != f.match_data[m].addr:
 									break_sign = True
 									match_data_amend[m] = self.match_data[m]
 									break
 					if break_sign == True:
 						continue
 					else:
 						if match_data_amend[m] == None:
 							if f.match_data[m] != None:
 								if self.match_data[m] != f.match_data[m]:
 									break_sign = True
 									match_data_amend[m] = self.match_data[m]
 				for m in match_data:
 					self.match_data[m] = match_data_amend[m]
 		else:#when the node up is others
 			related_nodes = set()
 			for f in flow_root.nodes_down:
 				related_nodes.add(f)
 			for f in self.nodes_up:#remove the related flow in root nodes down
 				for f1 in f.related_flow:
 					if f1 in related_nodes:
 						related_nodes.remove(f1)
 			for f in self.nodes_up:#
 				for m in match_data:
 					if match_data_amend[m] == None:
 						if f.match_data[m] != None:
 							match_data_amend[m] = self.match_data[m]

 			for f in related_nodes:#find the max granule
 				intersection = True
 				for m in match_data_addr:
 					if f.match_data[m] != None:
 						if match_data_amend[m] != None:
 							if match_data_amend[m] != f.match_data[m].addr:
 								intersection = False
 								break
 				if intersection == False:
 					continue
 				else:
 					for m in match_data_ord:
 						if f.match_data[m] != None:
 							if match_data_amend[m] != None:
 								if match_data_amend[m] != f.match_data[m]:
 									intersection = False
 									break
 				if intersection == True:
 					break_sign = False
 					for m in match_data_addr:
 						if match_data_amend[m] == None:
 							if f.match_data[m] != None:
 								if self.match_data[m] != f.match_data[m].addr:
 									break_sign = True
 									match_data_amend[m] = self.match_data[m]
 									break
 					if break_sign == True:
 						continue
 					else:
 						if match_data_amend[m] == None:
 							if f.match_data[m] != None:
 								if self.match_data[m] != f.match_data[m]:
 									break_sign = True
 									match_data_amend[m] = self.match_data[m]
 			for m in match_data:
 					self.match_data[m] = match_data_amend[m]



 		# match_data_count = {
 		# 'dl_src' : 0,
 		# 'dl_dst' : 0,
 		# 'dl_vlan' : 0,
 		# 'dl_vlan_pcp' : 0,
 		# 'dl_type' : 0,
 		# 'nw_tos' : 0,
 		# 'nw_src' : 0,
 		# 'nw_dst' : 0,
 		# 'tp_src' : 0,
 		# 'tp_dst' : 0,
 		# }
 		# if (len(self.nodes_up) == 1) and (self.nodes_up[0] is flow_root):
 		# 	for x in xrange(1,10):
 		# 		for f in flow_root.nodes_down:
 		# 			for m in match_data:





	def D_path_find(self, s1, s2):
		assert s1 is not s2
		if s1 in switchlist:
			if s2 in switchlist:
				GMN = len(switchlist)
				l_record = defaultdict(lambda:[])
				u_record = defaultdict(lambda:[])
				for s in switchlist:
					l_record[s] = 60000
					u_record[s] = s1
				l_record[s1] = 0
				S_record = []
				S_record.append(s1)
				i = 0
				u_tmp = s1
				while (i < GMN - 1):
					for v in switchlist:
						if v not in S_record:
							if (l_record[v] > (l_record[u_tmp] + self.flow_graph[switchlist.index(u_tmp)][switchlist.index(v)])):
								l_record[v] = l_record[u_tmp] + self.flow_graph[switchlist.index(u_tmp)][switchlist.index(v)]
								u_record[v] = u_tmp
					tmp = 60000
					for v in switchlist:
						if v not in S_record:
							if (l_record[v] < tmp):
								tmp = l_record[v]
								u_tmp = v
					if tmp == 60000:
						break
					S_record.append(u_tmp)
					i = i + 1
				if s2 not in S_record:

					path = False
				# elif:u_record
				else:

					path = []
					path.append(s2)
					tmp = s2
					for i in xrange(0,GMN):
						tmp = u_record[tmp]
						if tmp is s1:
							path.append(s1)
							break
						path.append(tmp)
				print path
				return path


class Tree_node_entry(object):
	"""docstring for Tree_node_entry"""
	def __init__(self):
		self.nodes_down = []
		self.nodes_up = []







class entry_action_flow_forbidden(object):

	def __init__(self, allow_set = None):
		self.action_name = 'Flow_forbidden'
		self.allow_set = set()
		if allow_set == None:
			self.allow_set = None
		else:
			for s in allow_set:
				self.allow_set.add(s)


class entry_action_attach_to_path(object):

	def __init__(self, path = None, priority = 1):
		self.action_name = 'Attach_to_Path'

		self.path = []
		if path == None:
			self.path = None
		else:
			for s in path:
				self.path.append(s)
		self.priority = priority

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
		self.exception = {}
		self.exception_down_related = {}
		self.flow_graph = []
		self.actions_graph = []
		# self.may_overlap_nodes = set()
		# self.dl_src = dl_src
		# self.dl_dst = dl_dst
		# self.dl_vlan = dl_vlan
		# self.dl_vlan_pcp = dl_vlan_pcp
		# self.dl_type = dl_type
		# self.nw_tos = nw_tos
		# self.nw_proto = nw_proto
		# self.nw_dst = nw_dst
		# self.tp_src = tp_src
		# self.tp_dst = tp_dst
		self.end_leaf_sign = True
		self.nodes_down = set()
		self.nodes_up = []
		self.actions = []
		self.level = 0
		self.related_flow = set()
		self.active_action = False
		mark = self.location_find()
		self.calc_flow_graph()
		# if mark == 0:
		# 	self.calc_flow_graph()
		# self.end_leaf_sign = False


	def matrix_assign(self, matrix):
		GMN = len(switchlist)
		matrix_tmp = []
		for j in range(0, GMN):
			tmp = []
			for i in range(0, GMN):
				tmp.append(60000)
			matrix_tmp.append(tmp)
		for j in range(0, GMN):
			for i in range(0, GMN):
				matrix_tmp[j][i] = matrix[j][i]
		return matrix_tmp


	def location_find(self):
		self.nodes_down = set()
		self.nodes_up = []
		self.related_flow = set()
		lvl = len(match_data)
		i = 0
		for x in match_data:
			if self.match_data[x] != None:
				i = i + 1
		self.level = i
		# print len(lvl_element[self.level])


		if len(lvl_element[self.level]) == 0:
			lvl_element[self.level].append(self)
		else:
			for f in lvl_element[self.level]:
				issame = True
				# for m in match_data_addr:
				# 	if f.match_data[m] == None:
				# 		if self.match_data[m] == None:
				# 			pass
				# 	elif self.match_data[m] != None:
				# 		if f.match_data[m].addr == self.match_data[m].addr:
				# 			pass
				# 	else:
				# 		issame = False
				# 		break
				# if issame == False:
				# 	continue
				# else:
				# 	for m in match_data_ord:
				# 		if f.match_data[m] != self.match_data[m]:
				# 			issame = False
				# 			break
				for m in match_data_ord:
					if f.match_data[m] != self.match_data[m]:
						issame = False
						break
				if issame == True:
					# print 'there are same'
					return 0
			lvl_element[self.level].append(self)

		for x in range(0,self.level - 1): # find the related flow above this level
			i = self.level - x -1
			for f in lvl_element[i]:
				contain = True

				for m in match_data_addr:
					if f.match_data[m] == None:
						continue
					elif self.match_data[m] == None:
						contain = False
						break
					elif f.match_data[m].addr != self.match_data[m].addr:
						contain = False
						break
				for m in match_data_ord:
					if f.match_data[m] != self.match_data[m]:
						if f.match_data[m] != None:
							contain = False
							break
						elif f.match_data[m] == None:
							continue
				# for m in match_data:
				# 	if f.match_data[m] != self.match_data[m]:
				# 		if f.match_data[m] != None:
				# 			contain = False
				# 			break
				# 		elif f.match_data[m] == None:
				# 			continue
				if contain == True:
					self.related_flow.add(f)
					nodes_up_sign = True
					for f2 in self.nodes_up:
						if f in self.exception: # meet the except flow
							continue
						elif f in f2.related_flow:
								nodes_up_sign = False
								break
					if nodes_up_sign == True:
						self.nodes_up.append(f)
						f.nodes_down.add(self)
						if f.end_leaf_sign == True:
							f.end_leaf_sign = False

		if len(self.nodes_up) == 0:
			self.nodes_up.append(flow_root)
			flow_root.nodes_down.add(self)

		for x in range(self.level + 1,len(match_data) + 1): # update flow under this level
			for f in lvl_element[x]:
				for f1 in f.nodes_up:
					if f1 in self.nodes_up:
						if self in f.nodes_up:
							f.nodes_up.remove(f1)
							break
						else:
							contain = True
							for m in match_data_addr:
								if f.match_data[m] == None:
									continue
								elif self.match_data[m] == None:
									contain = False
									break
								elif f.match_data[m].addr != self.match_data[m].addr:
									contain = False
									break
							for m in match_data_ord:
								if f.match_data[m] != self.match_data[m]:
									if f.match_data[m] != None:
										contain = False
										break
									elif f.match_data[m] == None:
										continue
								# if f.match_data[m] != self.match_data[m]:
								# 	if f.match_data[m] != None:
								# 		contain = False
								# 		break
								# 	elif f.match_data[m] == None:
								# 		continue
							if contain == True:
								f.nodes_up.remove(f1)
								f.nodes_up.append(self)
								self.nodes_down.add(f)
								self.end_leaf_sign = False

		# if len(self.nodes_down) == 0:
		# 	end_leaf_nodes.add(self)
		# 	self.end_leaf_sign = True
		# 	# print self.end_leaf_sign
		# 	for f in self.nodes_up:
		# 		# print self.nodes_up
		# 		# print f.end_leaf_sign
		# 		if f.end_leaf_sign == True:
		# 			f.end_leaf_sign = False
		# 			end_leaf_nodes.remove(f)
		# 			# print end_leaf_nodes
		# for f in end_leaf_nodes: #calc the related flow that may have overlay
		# 	relevancy = True
		# 	for m in match_data_addr:
		# 		if f.match_data[m] == None:
		# 			continue
		# 		elif self.match_data[m] == None:
		# 			continue
		# 		elif f.match_data[m].addr != self.match_data[m].addr:
		# 			relevancy = False
		# 			break
		# 	for m in match_data_ord:
		# 		if f.match_data[m] != self.match_data[m]:
		# 			if f.match_data[m] != None:
		# 				if self.match_data[m] != None:
		# 					relevancy = False
		# 				else:
		# 					continue
		# 	if relevancy == True:
		# 		self.may_overlap_nodes.add(f)
		# for f in self.may_overlap_nodes:
		# 	if f not in end_leaf_nodes:
		# 		self.may_overlap_nodes.remove(f)

	def calc_flow_graph(self):
		self.flow_graph = self.matrix_assign(matrix = flow_root.flow_graph)
		nodes_up_len = len(self.nodes_up)
		# self.flow_graph = self.nodes_up[nodes_up_len - 1].flow_graph
		for x in range(1,nodes_up_len + 1):
			i = nodes_up_len - x
			for s1 in switchlist:
				for s2 in switchlist:
					if self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] < self.nodes_up[i].flow_graph[switchlist.index(s1)][switchlist.index(s2)]:
						self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = self.nodes_up[i].flow_graph[switchlist.index(s1)][switchlist.index(s2)]
		self.calc_actions_graph()
		# for f in self.nodes_down:
		# 	if :
		# 		pass
		# 	f.calc_flow_graph(switchlist_1 = switchlist_tmp, flow_graph1 = self.flow_graph)
		# # for f in self.nodes_down:
		# 	f.calc_flow_graph()
		# print self.flow_graph

	def calc_down_w_change(self):
		for x in range(self.level + 1,len(match_data) + 1): # update flow under this level
			for f in lvl_element[x]:
				if self in f.related_flow:
					f.calc_flow_graph()

	def calc_actions_graph(self):
		# self.actions_graph = self.matrix_assign(matrix = self.flow_graph)
		coll_action_sign = False
		for ac in self.actions:
			if ac.action_name == 'Attach_to_Path':
				break_sign = False
				for s in ac.path:
					if s not in switchlist:
						print s, "is not in thes witchlist"
						break_sign = True
						break
				if break_sign == True:
					continue
				# self.attach_to_path(path = ac.path)
				coll_action_sign = True
				self.active_action = ac
			elif ac.action_name == 'Flow_forbidden':
				break_sign = False
				for s in ac.allow_set:
					if s not in switchlist:
						print s, "is not in thes witchlist"
						break_sign = True
						break
				if break_sign == True:
					continue
				self.flow_forbidden(allow_set = ac.allow_set)

		if coll_action_sign == False:
			p_tmp = 0
			tmp = False
			for f in self.nodes_up:
				if f.active_action == False:
					continue
				else:
					if f.active_action.priority > p_tmp:
						tmp = f.active_action
						p_tmp = f.active_action.priority
			if tmp == False:
				pass
			else:
				self.active_action = tmp
				# if self.active_action.action_name == 'Attach_to_Path':
					# self.attach_to_path(path = self.active_action.path)





	def flow_delete(self):
		global end_leaf_nodes
		for fl in self.nodes_up:
			fl.nodes_down.remove(self)
		if self.end_leaf_sign == True:
			for f in self.nodes_up:
				if len(f.nodes_down) == 0:
					f.end_leaf_sign = True
					end_leaf_nodes.add(f)
		lvl_element[self.level].remove(self)
		for fl in self.nodes_down:
			for f1 in fl.nodes_up:
				f1.nodes_down.remove(fl)
			fl.nodes_up = []
			fl.related_flow = set()
			for x in range(1,fl.level - 1): # find the related flow above this level
				i = fl.level - x
				for f in lvl_element[i]:
					contain = True
					for m in match_data_addr:
						if f.match_data[m] == None:
							continue
						elif fl.match_data[m] == None:
							contain = False
							break
						elif f.match_data[m].addr != fl.match_data[m].addr:
							contain = False
							break
					for m in match_data_ord:
						if f.match_data[m] != fl.match_data[m]:
							if f.match_data[m] != None:
								contain = False
								break
							elif f.match_data[m] == None:
								continue
						# if f.match_data[m] != fl.match_data[m]:
						# 	if f.match_data[m] != None:
						# 		contain = False
						# 		break
						# 	elif f.match_data[m] == None:
						# 		continue
					if contain == True:
						fl.related_flow.add(f)
						for f2 in fl.nodes_up:
							if f in fl.exception: # meet the except flow
								continue
							else:
								if f in fl.nodes_up.related_flow:
									continue
								else:
									fl.nodes_up.append(f)
									f.nodes_down.add(fl)
			if len(fl.nodes_up) == 0:
				fl.nodes_up.append(flow_root)
				flow_root.nodes_down.add(fl)
			fl.calc_flow_graph()
		for x in range(self.level + 1,len(match_data) + 1): # update flow under this level
			for f in lvl_element[x]:
				if self in f.related_flow:
					f.related_flow.remove[self]
					f.calc_flow_graph()



	def attach_to_path(self, path):
		path_len = len(path)
		for s in switchlist:
			if s in path:
				if path.index(s) != path_len - 1:
					for s2 in switchlist:
						if s2 == path[path.index(s)+1]:
							pass
						else:
							self.actions_graph[switchlist.index(s)][switchlist.index(s2)] = 60000
				else:
					for s2 in switchlist:
						self.actions_graph[switchlist.index(s)][switchlist.index(s2)] = 60000
			else:
				for s2 in switchlist:
					self.actions_graph[switchlist.index(s)][switchlist.index(s2)] = 60000

		pass
	def flow_forbidden(self, allow_set):
		for s1 in switchlist:
			for s2 in switchlist:
				if s2 not in allow_set:
					self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = 60000
				if s1 not in allow_set:
					self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = 60000


	def update_graph_under(self):
		for x in range(self.level + 1,len(match_data) + 1): # update flow under this level
			for f in lvl_element[x]:
				if self in f.related_flow:
					# f.location_find()
					f.calc_flow_graph()




	def D_path_find(self, s1, s2):
		assert s1 is not s2
		if s1 in switchlist:
			if s2 in switchlist:
				GMN = len(switchlist)
				l_record = defaultdict(lambda:[])
				u_record = defaultdict(lambda:[])
				for s in switchlist:
					l_record[s] = 60000
					u_record[s] = s1
				l_record[s1] = 0
				S_record = []
				S_record.append(s1)
				i = 0
				u_tmp = s1
				while (i < GMN - 1):

					for v in switchlist:
						if v not in S_record:
							if (l_record[v] > (l_record[u_tmp] + self.flow_graph[switchlist.index(u_tmp)][switchlist.index(v)])):
								l_record[v] = l_record[u_tmp] + self.flow_graph[switchlist.index(u_tmp)][switchlist.index(v)]
								u_record[v] = u_tmp
					tmp = 60000
					for v in switchlist:
						if v not in S_record:
							if (l_record[v] < tmp):
								tmp = l_record[v]
								u_tmp = v
					if tmp == 60000:
						break
					S_record.append(u_tmp)
					i = i + 1
				if s2 not in u_record:
					path = False
				else:

					path = []
					path.append(s2)
					tmp = s2
					for i in xrange(0,GMN):
						tmp = u_record[tmp]
						if tmp is s1:
							path.append(s1)
							break
						path.append(tmp)
				return path




def D_path_find_test(s1, s2):
	assert s1 is not s2
	if s1 in switchlist:
		if s2 in switchlist:
			GMN = len(switchlist)
			l_record = defaultdict(lambda:[])
			u_record = defaultdict(lambda:[])
			for s in switchlist:
				l_record[s] = 60000
				u_record[s] = s1
			l_record[s1] = 0
			S_record = []
			S_record.append(s1)
			i = 0
			u_tmp = s1
			while (i < GMN - 1):

				for v in switchlist:
					if v not in S_record:
						if (l_record[v] > (l_record[u_tmp] + flow_root.flow_graph[switchlist.index(u_tmp)][switchlist.index(v)])):
							l_record[v] = l_record[u_tmp] + flow_root.flow_graph[switchlist.index(u_tmp)][switchlist.index(v)]
							u_record[v] = u_tmp
				tmp = 60000
				for v in switchlist:
					if v not in S_record:
						if (l_record[v] < tmp):
							tmp = l_record[v]
							u_tmp = v
				if tmp == 60000:
					break
				S_record.append(u_tmp)
				i = i + 1
			if s2 not in u_record:
				path = False
			else:
				path = []
				path.append(s2)
				tmp = s2
				for i in xrange(0,GMN):
					tmp = u_record[tmp]
					if tmp is s1:
						path.append(s1)
						break
					path.append(tmp)
			return path
	pass

flow_name = {}

def flow_generation(NUM = 10):
	global flow_name
	print "runing"
	for x in xrange(1, NUM +1):
		print x
		match_data_tmp = {
		'dl_src' : None,
		'dl_dst' : None,
		'dl_vlan' : None,
		'dl_vlan_pcp' : None,
		'nw_tos' : None,
		'nw_src' : None,
		'nw_dst' : None,
		'tp_src' : None,
		'tp_dst' : None,
		}
		root_sign = True
		for m in match_data:
			p = random.randint(0, 100)
			if p < 30:
				match_data_tmp[m] = None
			else:
				if m == 'nw_src':
					p = random.randint(1, 240)
					p_s = '%d'%p
					str_s = ['10.0.0.', p_s]
					tmp = ''.join(str_s)
					match_data_tmp[m] = IPAddr(tmp)
					root_sign = False

				elif m == 'nw_dst':
					p = random.randint(1, 240)
					p_s = '%d'%p
					str_s = ['10.0.0.', p_s]
					tmp = ''.join(str_s)
					match_data_tmp[m] = IPAddr(tmp)
					root_sign = False
				# elif m == 'dl_src':
				# 	match_data_tmp[m] = None
				# elif m == 'dl_dst':
				# 	match_data_tmp[m] = None
				elif m == 'dl_vlan':
					match_data_tmp[m] = random.randint(1, 500)
					root_sign = False
				# elif m == 'dl_vlan_pcp':
				# 	match_data_tmp[m] = None
				elif m == 'tp_src':
					match_data_tmp[m] = random.randint(1, 2000)
					root_sign = False
				elif m == 'tp_dst':
					match_data_tmp[m] = random.randint(1, 2000)
					root_sign = False
				# elif m == 'nw_tos':
				# 	match_data_tmp[m] = None
		if root_sign == True:
			continue
		startTimeStamp = time.time()
		flow_name[x] = flow(nw_src = match_data_tmp['nw_src'], nw_dst = match_data_tmp['nw_dst'], dl_vlan = match_data_tmp['dl_vlan'],
				 		tp_src = match_data_tmp['tp_src'], tp_dst = match_data_tmp['tp_dst'])
		endTimeStamp=time.time()
		print (endTimeStamp-startTimeStamp)*1000
		p = random.randint(0, 100)
		if p < 70:
			p1 = random.randint(1, 12)
			flow_allow_set = set([1,2,3,4,5,6,7,8,9,10,11,12])
			flow_allow_set.remove(p1)

			# if p1 != 1:
			# 	p2 = random.randint(1, p-1)
			# 	flow_allow_set.remove(p2)
			# else:
			# 	p2 = random.randint(3, 12)
			# 	flow_allow_set.remove(p2)
			flow_name[x].actions.append(entry_action_flow_forbidden(allow_set = flow_allow_set))

		# else:
		# 	flow_path = []
		# 	for x in xrange(1,5):
		# 		p1 = random.randint(1, 12)
		# 		flow_path.append(p1)
		# 	flow_name[x].actions.append(entry_action_attach_to_path(path = flow_path))





		# print x
		# print flow_name[x].match_data

def launch():
	#global _noflood_by_default, _hold_down
	#if no_flood is True:
	#	_noflood_by_default = True
	#if hold_down is True:
	#	_hold_down = True
	# startTimeStamp=time.time()
	# flow1 = flow(nw_src = IPAddr('10.0.0.1'),
	# 			 nw_dst = IPAddr('10.0.0.2'))
	# # flow1_path = [2,5,8,10,11]
	# flow1_path = [11,10,8,5,2]
	# f1 = entry_action_attach_to_path(path = flow1_path)
	# flow1.actions.append(entry_action_attach_to_path(path = flow1_path))
	# flow1.calc_actions_graph()
	# flow2 = flow(nw_src = IPAddr('10.0.0.4'),
	# 			 nw_dst = IPAddr('10.0.0.5'))
	# flow2_allow = set([8,9,10])

	# flow2.actions.append(entry_action_flow_forbidden(allow_set = flow2_allow))
	# flow2.calc_actions_graph()

	# flow3 = flow(dl_vlan = 25)
	# flow4 = flow(dl_vlan = 25, nw_src = IPAddr('10.0.0.4'),
	# 			 nw_dst = IPAddr('10.0.0.5'))


	# flow_generation(NUM = 500)
	# startTimeStamp=time.time()
	# flow2 = flow(nw_src = IPAddr('10.0.0.4'),
	# 			 nw_dst = IPAddr('10.0.0.50'))
	# flow2_allow = set([1])

	# flow2.actions.append(entry_action_flow_forbidden(allow_set = flow2_allow))
	# flow2.calc_actions_graph()

	# print lvl_element, flow_name
	# endTimeStamp=time.time()
	# print (endTimeStamp-startTimeStamp)*1000, 'ms'
	# print flow_name
	# print end_leaf_nodes

	# # print flow1.flow_graph
	# print flow_root.nodes_down



	def start_flowpr ():
		# flow_root = flow_root()
		core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
		core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)
		core.openflow_discovery.addListenerByName("LinkEvent", _handle_LinkEvent)
		core.openflow.addListenerByName("FlowStatsReceived", _handle_flow_stats)
		core.openflow.addListenerByName("QueueStatsReceived", _handle_queue_stats)
		core.openflow.addListenerByName("PortStatsReceived", _handle_port_stats)
		core.openflow.addListenerByName("TableStatsReceived", _handle_table_stats)
		core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
		Timer(5, request_flowstats, recurring = True)
		#Timer(10, request_portstats, recurring = True)
		log.debug("Flowpr component ready")
	core.call_when_ready(start_flowpr, "openflow_discovery")
