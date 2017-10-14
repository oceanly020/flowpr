
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
from test_generation import *

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
		self.intersection = set()
		self.inter_nodes_up = False
		self.nodes_up = False
		self.nodes_down = set()
		self.context_down = set()
		self.inter_nodes_down = set()
		self.level = 0
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
 		)      #前面的IP和MAC地址比对,由于格式的不同
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
	# print "UpdateTime:",(endTimeStamp4 - startTimeStamp1)*1000,"ms" #UpdateTime
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

def flow_mod(match_data = None, in_port = None, outport = None, Spath = None):#下发流函数MODIFY,添加或者修改流表头,并加上动作为ofp_action_output
	msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT,
						idle_timeout=FLOW_IDLE_TIMEOUT
						#hard_timeout=of.OFP_FLOW_PERMANENT
						)

	msg.actions.append(of.ofp_action_output(port = outport))
	# msg.match.in_port = adjacency_port_in[s][path[path.index(s)+1]]
	in_port = in_port
	# msg.match.nw_src = a.protosrc # Wildcard source IP
	# msg.match.nw_dst = a.protodst # Wildcard dst IP
	# msg.match = of.ofp_match.from_packet(packet, in_port)
	msg.match.dl_vlan = match_data['dl_vlan']
	msg.match.dl_vlan_pcp = match_data['dl_vlan_pcp']
	msg.match.dl_src = match_data['dl_src'] # Wildcard dst IP
	msg.match.dl_dst = match_data['dl_dst']
	msg.match.nw_proto = match_data['nw_proto']
	msg.match.dl_type = match_data['dl_type']
	msg.match.nw_tos = match_data['nw_tos']
	msg.match.tp_src = match_data['tp_src']
	msg.match.tp_dst = match_data['tp_dst']
	msg.match.nw_src = match_data['nw_src'] # Wildcard dst IP
	msg.match.nw_dst = match_data['nw_dst']
	switchpath[Spath].send(msg)




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
						flow_mod(match_data = packetflow.match_data, in_port = packetflow.in_port, outport = prt, Spath = path[1])
					else:

						for s in path: # update path

							if s == dpid_dst:
								flow_mod(match_data = packetflow.match_data, in_port = adjacency_port_in[s][path[path.index(s)+1]], outport = prt, Spath = s)
							else:
								if s != dpid:
									flow_mod(match_data = packetflow.match_data, in_port = adjacency_port[s][path[path.index(s)+1]], outport = adjacency_port[s][path[path.index(s)-1]], Spath = s)

								else:
									flow_mod(match_data = packetflow.match_data, in_port = packetflow.in_port, outport = adjacency_port[s][path[path.index(s)-1]], Spath = s)
									

	elif isinstance(packet.next, arp): # upload the packet flow policy
		startTimeStamp=time.time()
		packetflow = packet_flow(packet = packet)
		endTimeStamp1 = time.time()
		# print packetflow.flow_graph
		# print switchlist
		# print "PacketflowEstabelishied:",(endTimeStamp1 - startTimeStamp)*1000,"ms"
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
						# print "PathCalc:",(endTimeStamp2 - startTimeStamp)*1000,"ms"
						startTimeStamp=time.time()
						if path == False:
							pass

						else:
							if (len(path) == 2) and (path[0] == path[1]):
								flow_mod(match_data = packetflow.match_data, in_port = packetflow.in_port, outport = prt, Spath = path[1])								
							else:

								for s in path: # update path
									if s == dpid_dst:
										flow_mod(match_data = packetflow.match_data, in_port = adjacency_port_in[s][path[path.index(s)+1]], outport = prt, Spath = s)
									else:
										if s != dpid:
											flow_mod(match_data = packetflow.match_data, in_port = adjacency_port[s][path[path.index(s)+1]], outport = adjacency_port[s][path[path.index(s)-1]], Spath = s)
										else:
											flow_mod(match_data = packetflow.match_data, in_port = packetflow.in_port, outport = adjacency_port[s][path[path.index(s)-1]], Spath = s)
							
							endTimeStamp3 = time.time()
							# print "RuleInstalled:",(endTimeStamp3 - startTimeStamp)*1000,"ms"





def request_flowstats():
	for con in core.openflow.connections:

		# con.send(of.ofp_stats_request(body = of.ofp_flow_stats_request()))
		# con.send(of.ofp_stats_request(body = of.ofp_queue_stats_request()))
		# con.send(of.ofp_stats_request(body = of.ofp_port_stats_request()))
		# con.send(of.ofp_stats_request(body = of.ofp_table_stats_request()))
		pass


class action_entry(object):
	def __init__(self, action_name, priority = 1,path = None, allow_set = None, match_field = None, mod_name = None):
		self.action_name = action_name
		self.priority = priority
		if self.action_name == "Flow_modify":
			action.mod_name = None
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
 			match_field['dl_vlan'] = match_field['dl_vlan']
			match_field['dl_vlan_pcp'] = match_field['dl_vlan_pcp']
			match_field['dl_src'] = match_field['dl_src'] # Wildcard dst IP
			match_field['dl_dst'] = match_field['dl_dst']
			match_field['nw_proto'] = match_field['nw_proto']
			match_field['dl_type'] = match_field['dl_type']
			match_field['nw_tos'] = match_field['nw_tos']
			match_field['tp_src'] = match_field['tp_src']
			match_field['tp_dst'] = match_field['tp_dst']
			match_field['nw_src']  = match_field['nw_src'] # Wildcard dst IP
			match_field['nw_dst'] = match_field['nw_dst']
		elif self.action_name == "Flow_forbidden":
			self.allow_set = set()
			if allow_set == None:
				self.allow_set = None
			else:
				for s in allow_set:
					self.allow_set.add(s)

		elif self.action_name == "Path_choose": 
			self.path = []
			if path == None:
				self.path = None
			else:
				for s in path:
					self.path.append(s)	

		else:
			pass


# class entry_action_flow_forbidden(object):

# 	def __init__(self, allow_set = None):
# 		self.action_name = 'Flow_forbidden'
# 		self.allow_set = set()
# 		if allow_set == None:
# 			self.allow_set = None
# 		else:
# 			for s in allow_set:
# 				self.allow_set.add(s)


# class entry_action_attach_to_path(object):

# 	def __init__(self, path = None, priority = 1):
# 		self.action_name = "Path_choose"

# 		self.path = []
# 		if path == None:
# 			self.path = None
# 		else:
# 			for s in path:
# 				self.path.append(s)
# 		self.priority = priority		

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
		self.in_port = None
		self.nodes_up = []
		self.flow_graph = self.matrix_assign(matrix = flow_root.flow_graph) #将总体的矩阵复制过来
		self.flow_from_packet(packet = packet)
		self.may_overlap_nodes = set() 
		self.actions_set = [] #总体继承动作排序
		self.phenotype_a = None #显性动作,即下发动作

		self.flow_match_intree()
		self.calc_flow_graph()

		# self.calc_max_granule_flow()
		# if self.phenotype_a != None:
		# 	print self.phenotype_a.action_name
		# else:
		# 	print self.phenotype_a
		# print self.match_data
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
		# self.flow_graph = self.matrix_assign(matrix = flow_root.flow_graph)
		# nodes_up_len = len(self.nodes_up)
		# # self.flow_graph = self.nodes_up[nodes_up_len - 1].flow_graph
		# for x in range(1,nodes_up_len + 1):
		# 	i = nodes_up_len - x
		# 	for s1 in switchlist:
		# 		for s2 in switchlist:
		# 			if self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] < self.nodes_up[i].flow_graph[switchlist.index(s1)][switchlist.index(s2)]:
		# 				self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = self.nodes_up[i].flow_graph[switchlist.index(s1)][switchlist.index(s2)]
		self.calc_actions()
		self.calc_actions_graph()

	def calc_actions(self):#计算下发动作
		#先将所有动作排序
		print self.nodes_up
		print self.actions_set
		allow_set_temp = set()
		for f in self.nodes_up:
			if f.active_action != False:
				print "calc_actions"
			
				for action in f.active_action: #无冲突可以表现出来的动作集
					self.actions_set.append(action)

		self.actions_set.sort(key=lambda priority : action.priority, reverse = False)
		print self.actions_set
		state = 0#0状态为未知,1为仅有禁止,2为选路,3为mod,只找mod
		for action in self.actions_set:
			if state == 0:
				if action.action_name == "Flow_modify":
					if action.mod_name == "add":
						state = 3
						continue
					else:
						break	
				
				elif action.action_name == "Flow_forbidden":
					state = 1
					self.phenotype_a = action
					allow_set_temp = action.allow_set
					continue

				elif action.action_name == "Path_choose":
					# state = 2
					self.phenotype_a = action
					break
			elif state == 1:
				if action.action_name == "Flow_modify":
					if action.mod_name == "add":
						state = 3
						continue
					else:
						break	
				
				elif action.action_name == "Flow_forbidden":
					allow_set_temp = allow_set_temp & action.allow_set
					self.phenotype_a = action_entry(action_name = "Flow_forbidden", priority = action.priority, allow_set = allow_set_temp)
					continue

				elif action.action_name == "Path_choose":
					for s in action.path:

						if s in allow_set_temp:
							self.phenotype_a = action
							
						else:
							self.phenotype_a  = "Deny"
							state = 2
							break
					break
						
			# elif state = 2:
			# 	if action.action_name == "Flow_modify":
			# 		if action.mod_name == "add"
			# 			state = 3
			# 			continue
			# 		else:
			# 			break	
				
			# 	elif action.action_name == "Flow_forbidden":
			# 		state = 1
			# 		continue

			# 	elif action.action_name == "Path_choose":
			# 		state = 2
			# elif state = 3:
			# 	if action.action_name == "Flow_modify":
			# 		pass
			# 	else:
			# 		continue


	def calc_actions_graph(self):

		# print self.active_action
		if self.phenotype_a != 	None:
			if self.phenotype_a  != "Deny":
				if self.phenotype_a.action_name == "Path_choose":
					self.attach_to_path(path = self.phenotype_a.path)
				elif self.phenotype_a.action_name == "Flow_forbidden":
					self.flow_forbidden(allow_set = self.phenotype_a.allow_set)



	def attach_to_path(self, path):
		path_len = len(path)
		for s in switchlist:
			if s in path:
				if path.index(s) != path_len - 1:
					for s2 in switchlist:

						if s2 == path[path.index(s)+1]:
							continue
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

		if self.phenotype_a  == "Deny":
			return False
			pass
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
					print S_record

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









class flow (object):
 	"""docstring for flow_establish"""
 	def __init__(self, dl_src = None, dl_dst = None, dl_vlan = None,
				   dl_vlan_pcp = None, dl_type = None, nw_tos = None, nw_proto = None,
				   nw_src = None, nw_dst = None, tp_src = None, tp_dst = None, actions = None):
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
		# self.flow_graph = []
		# self.actions_graph = []
		# self.may_overlap_nodes = set()
		self.nodes_down_upsign = False
		self.end_leaf_sign = True
		traversed_sign = False
		self.nodes_down = set()
		self.nodes_up = []
		self.inter_nodes_up = set()
		self.inter_nodes_down = set()
		self.actions = []
		self.intersection = set()
		if actions != None:
			for ac in actions:
				self.actions.append(ac)

		self.level = 0
		self.related_flow = set()
		self.active_action = []

		# mark = self.location_find()
		mark = self.location_find_1()

		# self.calc_flow_graph()
		# self.calc_actions()

		# print "start"
		# print self
		# print self.nodes_up
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

	def location_find_1(self):
		
		self.nodes_down = set()
		self.related_flow = set()


		lvl = len(match_data)
		i = 0
		for x in match_data:
			if self.match_data[x] != None:
				i = i + 1
		self.level = i
		self.nodes_up = []
		temp = set()
		i = 1

		if len(lvl_element[self.level]) == 0:
			lvl_element[self.level].append(self)
		else: # if there is same
			# print "This is the debug breakpoint!!!"
			for f in lvl_element[self.level]:
				comp_sign = self.flow_comp(f)


				if comp_sign == 0:
					for ac in self.actions:
						f.actions.append(ac)
					return 0
			lvl_element[self.level].append(self)
		for f in flow_root.nodes_down:
			temp.add(f)

		
		while 1: #find the coverd
			if i >= self.level: 				
				break
			if len(temp) == 0 :
				break
			tempc = set()
			remove_temp = set()
			for f in temp:

				if f.level == i:										
					remove_temp.add(f)									
					comp_sign = self.flow_comp(f,1)
					if comp_sign == 1:
						self.nodes_up.append(f)
						for f1 in f.nodes_down:
							if f1 not in tempc:							
								tempc.add(f1)
						for f1 in f.nodes_up:
							if f1 in self.nodes_up:
								self.nodes_up.remove(f1)		

			i = i + 1
			for f in remove_temp:
				temp.remove(f)
			for f in tempc:
				if f not in temp:
					temp.add(f)
		temp = set()
		i = 100

		if len(self.nodes_up) == 0:
			remove_temp = set()  			
			for f in flow_root.nodes_down:
			# 	temp.add(f)
			# for f in temp:
				comp_sign = self.flow_comp(f, 4)
				if comp_sign == 2:
					remove_temp.add(f)
					f.nodes_up.remove(flow_root)
					self.nodes_down.add(f)
					f.nodes_up.append(self)			
					self.end_leaf_sign = False
		# 			# self.nodes_down_upsign = True
				elif comp_sign == 3:
					for f1 in f.nodes_down:			
						temp.add(f)
						if f.level < i:
							i = f.level					 
			# for f in remove_temp:
			# 	temp.remove(f)
			# for f in tempc:
			# 	temp.append(f)
			# 	if f.level < i:
			# 		i = f.level
			self.nodes_up.append(flow_root)
			flow_root.nodes_down.add(self)
			for f in remove_temp:
				flow_root.nodes_down.remove(f)


		else:
			remove_temp = set()
			for f in self.nodes_up:
				for f1 in f.nodes_down:
					comp_sign = self.flow_comp(f1, 4)
					if comp_sign == 2:
						self.nodes_down.add(f1)
						f1.nodes_up.remove(f)
						f1.nodes_up.append(self)
						remove_temp.add(f1)
						self.end_leaf_sign = False
					elif comp_sign == 3:
						for f1 in f.nodes_down:			
							temp.add(f)
							if f.level < i:
								i = f.level

				for f1 in  remove_temp:
					f.nodes_down.remove(f1)
			for f in self.nodes_up:
				f.nodes_down.add(self)

		while 1:
			if len(temp) == 0 :
				break
			tempc = set()
			remove_temp = set()
			if i <= self.level:
				for f in temp:
					if f.level == i:										
						remove_temp.add(f)
						comp_sign = self.flow_comp(f, 3)
						if comp_sign == 3:
							for f1 in f.nodes_down:						
								tempc.add(f1)			
			elif i > self.level:
				for f in temp:
					if f.level == i:										
						remove_temp.add(f)
						comp_sign = self.flow_comp(f, 4)
						if comp_sign == 2:
							self.nodes_down.add(f)
							f1.nodes_up.append(self)
							self.end_leaf_sign = False
							# self.nodes_down_upsign = True
						elif comp_sign == 3:
							for f1 in f.nodes_down:						
								tempc.add(f1)
			for f in remove_temp:
				temp.remove(f)
			for f in tempc:
				temp.add(f)
			i = i + 1

	def flow_comp(self, f, sign = 0 ):
		"""-----------------------------------------------------------------
		sign = 1 self < f: 1 
		sign = 2 self > f: 2 
		intersection: 3 sign = 3
		sign = 4 intersection & self > f: self > f  2 ;intersection  3 
		sign = 5 intersection & self > f: self < f  1 ;intersection: 3
		other: 9 
		----------------------------------------------------------------"""
		if sign == 0:
			issame = True
			for m in match_data_addr:
				if f.match_data[m] == None:
					if self.match_data[m] == None:
						continue
					else:
						issame = False
						break

				elif self.match_data[m] != None:
					if f.match_data[m].addr == self.match_data[m].addr:
						continue
					else:
						issame = False
						break

				else:
					issame = False
					break
			if issame == True:
				for m in match_data_ord:
					if f.match_data[m] != self.match_data[m]:
						issame = False
						break

			if issame == True:
				return 0
			else:
				return 9
		elif sign == 1:

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
			if contain == True:
				for m in match_data_ord:
					if f.match_data[m] != self.match_data[m]:
						if f.match_data[m] != None:
							contain = False
							break
						elif f.match_data[m] == None:
							continue
			if contain == True:
				return 1
			else:
				return 9

		elif sign == 2:
			contain = True
			for m in match_data_addr:
				if self.match_data[m] == None:
					continue
				elif f.match_data[m] == None:
					contain = False
					break
				elif self.match_data[m].addr != f.match_data[m].addr:
					contain = False
					break
			if contain == True:
				for m in match_data_ord:
					if self.match_data[m] != f.match_data[m]:
						if self.match_data[m] != None:
							contain =  False
							break
						elif self.match_data[m] == None:
							continue
			if contain == True:
				return 2
			else:
				return 9
		elif sign == 3:
			intersection = True
			for m in match_data_addr:
				if self.match_data[m] == None:
					continue
				elif f.match_data[m] == None:
					continue
				elif self.match_data[m].addr != f.match_data[m].addr:
					contain = False
					break
			if intersection == True:				
				for m in match_data_ord:
					if self.match_data[m] != f.match_data[m]:
						if self.match_data[m] != None:
							if f.match_data[m] != None:
								intersection = False
								break
						else:
							continue
			if intersection == True:
				return 3
			else:
				return 9
		elif sign == 4:
			intersection = True
			contain = True
			for m in match_data_addr:
				if self.match_data[m] == None:
					continue
				elif f.match_data[m] == None:
					contain = False
				elif self.match_data[m].addr != f.match_data[m].addr:
					contain = False
					intersection = False
					break
			if contain == True:
				for m in match_data_ord:
					if self.match_data[m] == None:
						continue
					elif f.match_data[m] == None:
						contain = False
					elif self.match_data[m] != f.match_data[m]:
						contain = False
						intersection = False
						break

			if contain == True:
				return 2
			elif intersection == True:
				return 3
			else:
				return 9
		elif sign == 5:
			intersection = True
			contain = True
			for m in match_data_addr:
				if f.match_data[m] == None:
					continue
				elif self.match_data[m] == None:
					contain = False
				elif self.match_data[m].addr != f.match_data[m].addr:
					contain = False
					intersection = False
					break
			if contain == True:
				for m in match_data_ord:
					if f.match_data[m] == None:
						continue
					elif self.match_data[m] == None:
						contain = False
					elif self.match_data[m] != f.match_data[m]:
						contain = False
						intersection = False
						break

			if contain == True:
				return 1
			elif intersection == True:
				return 3
			else:
				return 9

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
				for m in match_data_addr:
					if f.match_data[m] == None:
						if self.match_data[m] == None:
							continue
						else:
							issame = False
							break

					elif self.match_data[m] != None:
						if f.match_data[m].addr == self.match_data[m].addr:
							continue
						else:
							issame = False
							break

					else:
						issame = False
						break
				if issame == False:
					continue
				else:
					for m in match_data_ord:
						if f.match_data[m] != self.match_data[m]:
							issame = False
							break
				# for m in match_data_ord:
				# 	if f.match_data[m] != self.match_data[m]:
				# 		issame = False
				# 		break
				if issame == True:
					print 'there are same'
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
				if contain == True:
					self.related_flow.add(f)
					nodes_up_sign = True
					for f2 in self.nodes_up:
						if f in f2.related_flow:
							nodes_up_sigd = False
							break
					if nodes_up_sign == True:
						self.nodes_up.append(f)
						f.nodes_down.add(self)
						if f.end_leaf_sign == True:
							f.end_leaf_sign = False

		if len(self.nodes_up) == 0:
			self.nodes_up.append(flow_root)
			flow_root.nodes_down.add(self)

		for x in range(self.level + 1 ,len(match_data) + 1): # update flow under this level
			for f in lvl_element[x]:
				for f1 in f.nodes_up:
					if f1 in self.nodes_up:
						if self in f.nodes_up:
							f.nodes_up.remove(f1)
							break
						else:
							contain = True
							for m in match_data_addr:
								if self.match_data[m] == None:
									continue
								elif f.match_data[m] == None:
									contain = False
									break
								elif f.match_data[m].addr != self.match_data[m].addr:
									contain = False
									break
							for m in match_data_ord:
								if f.match_data[m] != self.match_data[m]:
									if self.match_data[m] != None:
										contain = False
										break
									elif self.match_data[m] == None:
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
								f.calc_actions()
								self.nodes_down_upsign = True
		# print self
		# print self.nodes_up

		# if len(self.nodes_down) == 0:
		# 	end_leaf_nodes.add(self)
		# 	self.end_leaf_sign = True
		# 	# print self.end_leaf_sign
		# 	for f in self.nodes_up:
		# 		# print self.nodes_up
		# 		# cprint f.end_leaf_sign
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
		# self.flow_graph = self.matrix_assign(matrix = flow_root.flow_graph)
		# nodes_up_len = len(self.nodes_up)
		# # self.flow_graph = self.nodes_up[nodes_up_len - 1].flow_graph
		# for x in range(1,nodes_up_len + 1):
		# 	i = nodes_up_len - x
		# 	for s1 in switchlist:
		# 		for s2 in switchlist:
		# 			if self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] < self.nodes_up[i].flow_graph[switchlist.index(s1)][switchlist.index(s2)]:
		# 				self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = self.nodes_up[i].flow_graph[switchlist.index(s1)][switchlist.index(s2)]
		# self.calc_actions_graph()
		# for f in self.nodes_down:
		# 	if :
		# 		pass
		# 	f.calc_flow_graph(switchlist_1 = switchlist_tmp, flow_graph1 = self.flow_graph)
		# # for f in self.nodes_down:
		# 	f.calc_flow_graph()
		# print self.flow_graph
		pass

	def calc_actions_flowdown_change(self, alg = "EVERY"):
		
		if self.nodes_down_upsign == True:
			if alg == "EVERY":
				flow_temp = []
				nodes_down_temp = set()
				nodes_down_temp = nodes_down_temp | self.nodes_down
				for x in range(self.level + 1,len(match_data) + 1): # update flow under this level
					for f in lvl_element[x]:
						if f in nodes_down_temp:
							flow_temp.append[f]
							nodes_down_temp = nodes_down_temp | f.nodes_down
				for f in flow_temp:
					f.calc_actions()
				self.nodes_down_upsign == False

	def calc_actions(self):
		action_temp = []
		allow_set_temp = set()
		for action in self.actions:
			action_temp.append(action)


		for f in self.nodes_up:
			if f.active_action != False:
				for action in f.active_action: #nodes_up无冲突可以表现出来的动作集
					action_temp.append(action)
		# print action_temp
		
		action_temp.sort(key = lambda action : action.priority, reverse = True)
		# print action_temp
		if len(action_temp) > 1:
			print action_temp[0].priority, action_temp[1].priority

		
		state = 0#0状态为未知,1为仅有禁止,2为选路,3为mod,只找mod
		for action in action_temp:
			if state == 0:
				if action.action_name == "Flow_modify":
					if action.mod_name == "add":
						state = 3
						continue
					else:
						break	
				
				elif action.action_name == "Flow_forbidden":
					state = 1
					self.active_action.append(action)
					allow_set_temp = action.allow_set
					continue

				elif action.action_name == "Path_choose":
					state = 2
					self.active_action.append(action)
					continue
			elif state == 1:
				if action.action_name == "Flow_modify":
					if action.mod_name == "add":
						state = 3
						continue
					else:
						break	
				
				elif action.action_name == "Flow_forbidden":
					self.active_action.append(action)
					allow_set_temp = action.allow_set & self.phenotype_a.vallow_set
					
					continue

				elif action.action_name == "Path_choose":
					for s in action.path:
						if s in allow_set_temp:
							self.active_action.append(action)
							break							
					state = 2
					self.active_action.append(action)

		# print self.active_action
		self.calc_actions_flowdown_change()

		

			# elif state = 2:
			# 	if action.action_name == "Flow_modify":
			# 		if action.mod_name == "add"
			# 			state = 3
			# 			continue
			# 		else:
			# 			break	
				
			# 	elif action.action_name == "Flow_forbidden":
			# 		self.active_action.append(action)
			# 		continue

			# 	elif action.action_name == "Path_choose":
			# 		continue						

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

	def find_intersection_from_nodeup(self):
		temp = set()
		if flow_root in self.nodes_up:
			intersection = self.find_intersection()
		else:


			for f in self.nodes_up:
				for x in f.intersection:
					temp.add(x)
				pass
			intersection = set()
			for f in temp:
				comp_sign = self.flow_comp(f,3)
				if comp_sign == 3:
					intersection.add(f)
		return intersection


		


	def find_intersection(self):
		temp = set()
		for f in flow_root.nodes_down:
			temp.add(f)
		intersection_set = set()
		# self.nodes_up = []
		# temp = set()
		
		i = 1
		while 1: #find the intersection
			if len(temp) == 0:
				break

			tempc = set()
			remove_temp = set()

			for f in temp:
				if f.level == i:										
					remove_temp.add(f)

					comp_sign = self.flow_comp(f,3)
					if comp_sign == 3:
						intersection_set.add(f)
						for f1 in f.nodes_down:
							if f1 not in tempc:							
								tempc.add(f1)
						# for f1 in f.nodes_up:
						# 	if f1 in self.nodes_up:
						# 		self.nodes_up.remove(f1)		

			i = i + 1
			for f in remove_temp:
				temp.remove(f)
			for f in tempc:
				if f not in temp:
					temp.add(f)
			for x in intersection_set:
				self.intersection.add(x)
				pass
		return intersection_set
	

	def find_intersection_nomal(self):
		intersection_set = set()
		flowset_all = set()
		# for i in xrange(1,len(match_data) + 1):
		# 	for f in lvl_element[i]:
		# 		if :
		# 			pass


		for i in xrange(1, len(match_data) + 1):
			for f in lvl_element[i]:
				flowset_all.add(f)
		for f in flowset_all:
			comp_sign = self.flow_comp(f,3)
			if comp_sign == 3:
				intersection_set.add(f)

		return intersection_set

	def find_intersection_conflict(self):
		save_temp = set()
		save_temp = save_temp | flow_root.nodes_down
		conflict_set = set()
		for i in xrange(1,len(match_data) + 1):
			compare_temp = []
			for f in save_temp:
				if f.level == i:
					compare_temp.append(f)
					save_temp.remove(f)
			for f in compare_temp:
				inter_sign = True
				for m in match_data_addr:
					if f.match_data[m] == None:
						continue
					elif self.match_data[m] == None:
						continue
						
					elif f.match_data[m].addr != self.match_data[m].addr:
						inter_sign = False
						break
				for m in match_data_ord:
					if f.match_data[m] == None:
						continue
					elif self.match_data[m] == None:
						continue
					elif f.match_data[m] != self.match_data[m]:
						inter_sign = False
						break
				if inter_sign == True:


					action_temp = []
					for action in self.actions:
						action_temp.append(action)
					for action in f.active_action: #nodes_up无冲突可以表现出来的动作集
						action_temp.append(action)							
					action_temp.sort(key = lambda priority : action.priority, reverse = True)
					
					state = 0#0状态为未知,1为仅有禁止,2为选路,3为mod,只找mod；需要判断是否冲突,如果冲突,则返回流加入
					for action in action_temp:
						if state == 0:
							if action.action_name == "Flow_modify":
								if action.mod_name == "add":
									state = 3
									continue
								else:
									continue	
							
							elif action.action_name == "Flow_forbidden":
								state = 1
								self.phenotype_a = action
								continue

							elif action.action_name == "Path_choose":
								state = 2
								self.phenotype_a = action
								break
						elif state == 1:
							if action.action_name == "Flow_modify":
								if action.mod_name == "add":
									state = 3
									continue
								else:
									f.conflict_set.add(f)
									break								
							elif action.action_name == "Flow_forbidden":
								allow_set = action.allow_set & self.phenotype_a.allow_set
								self.phenotype_a = action_entry(action_name = "Flow_forbidden", priority = action.priority, allow_set = allow_set)
								continue

							elif action.action_name == "Path_choose":
								conflict_sign = False
								for s in action.path:

									if s in self.phenotype_a.allow_set:
										self.phenotype_a = action
										conflict_sign = False
										state = 2										
										continue									
									else:
										self.phenotype_a  = "Deny"
										conflict_sign = True
										break
								if conflict_sign == True:
									f.conflict_set.add(f)
									break
						elif state == 2:
							if action.action_name == "Flow_modify":
								if action.mod_name == "add":
									state = 3
									continue 
								else:
									f.conflict_set.add(f)
									break	

							elif action.action_name == "Flow_forbidden":
								conflict_sign = False
								for s in action.path:

									if s in self.phenotype_a.allow_set:
										self.phenotype_a = action
										conflict_sign = False										
										continue									
									else:
										self.phenotype_a  = "Deny"
										conflict_sign = True
										break
								if conflict_sign == True:
									f.conflict_set.add(f)
									break

							elif action.action_name == "Path_choose":
								conflict_sign = False
								if len(self.phenotype_a.path) == len(action.path):
									for x in xrange(0,len(phenotype_a.path)):
										if self.phenotype_a.path[x] != action.path[x]:
											conflict_sign = True
								else:
									conflict_sign = True
								if conflict_sign == True:
									f.conflict_set.add(f)
									break
					if f.end_leaf_sign == False:
						save_temp = save_temp | f.nodes_down
					# if f.end_leaf_sign == False:
					# 	inter_set.append(f)
					# 	save_temp = save_temp | f.nodes_down
					# elif end_leaf_sign == True:
					# 	inter_set.append(f)
			if len(save_temp) == 0:
				break
		return conflict_set

	def attach_to_path(self, path):
		pass
	# 	path_len = len(path)
	# 	for s in switchlist:
	# 		if s in path:
	# 			if path.index(s) != path_len - 1:
	# 				for s2 in switchlist:
	# 					if s2 == path[path.index(s)+1]:
	# 						pass
	# 					else:
	# 						self.actions_graph[switchlist.index(s)][switchlist.index(s2)] = 60000
	# 			else:
	# 				for s2 in switchlist:
	# 					self.actions_graph[switchlist.index(s)][switchlist.index(s2)] = 60000
	# 		else:
	# 			for s2 in switchlist:
	# 				self.actions_graph[switchlist.index(s)][switchlist.index(s2)] = 60000

	# 	pass
	# def flow_forbidden(self, allow_set):
	# 	for s1 in switchlist:
	# 		for s2 in switchlist:
	# 			if s2 not in allow_set:
	# 				self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = 60000
	# 			if s1 not in allow_set:
	# 				self.flow_graph[switchlist.index(s1)][switchlist.index(s2)] = 60000


	# def update_graph_under(self):
	# 	for x in range(self.level + 1,len(match_data) + 1): # update flow under this level
	# 		for f in lvl_element[x]:
	# 			if self in f.related_flow:
	# 				# f.location_find()
	# 				f.calc_flow_graph()

	def D_path_find(self, s1, s2):
		pass
		# assert s1 is not s2
		# if s1 in switchlist:
		# 	if s2 in switchlist:
		# 		GMN = len(switchlist)
		# 		l_record = defaultdict(lambda:[])
		# 		u_record = defaultdict(lambda:[])
		# 		for s in switchlist:
		# 			l_record[s] = 60000
		# 			u_record[s] = s1
		# 		l_record[s1] = 0
		# 		S_record = []
		# 		S_record.append(s1)
		# 		i = 0
		# 		u_tmp = s1
		# 		while (i < GMN - 1):

		# 			for v in switchlist:
		# 				if v not in S_record:
		# 					if (l_record[v] > (l_record[u_tmp] + self.flow_graph[switchlist.index(u_tmp)][switchlist.index(v)])):
		# 						l_record[v] = l_record[u_tmp] + self.flow_graph[switchlist.index(u_tmp)][switchlist.index(v)]
		# 						u_record[v] = u_tmp
		# 			tmp = 60000
		# 			for v in switchlist:
		# 				if v not in S_record:
		# 					if (l_record[v] < tmp):
		# 						tmp = l_record[v]
		# 						u_tmp = v
		# 			if tmp == 60000:
		# 				break
		# 			S_record.append(u_tmp)
		# 			i = i + 1
		# 		if s2 not in u_record:
		# 			path = False
		# 		else:

		# 			path = []
		# 			path.append(s2)
		# 			tmp = s2
		# 			for i in xrange(0,GMN):
		# 				tmp = u_record[tmp]
		# 				if tmp is s1:
		# 					path.append(s1)
		# 					break
		# 				path.append(tmp)
		# 		return path




class Conflict_Find(object):
	"""Find the Conflict"""
	def __init__(self, Conflict_name, NUM = None):
		self.Conflict_name = Conflict_name
		if self.Conflict_name == "Intersection":
			self.duplicate_conection()
			self.intersection_dict = self.Intersection_find()
			self.duplicate_conection()
		elif self.Conflict_name == "Intersection_nomal":
			self.duplicate_conection()
			self.intersection_dict = self.Intersection_find_nomal()
			self.duplicate_conection()

	def duplicate_conection(self):
		for f1 in flow_root.nodes_down:
			flow_root.inter_nodes_down.add(f1)

		for i in xrange(1, len(match_data) + 1):
			for f in lvl_element[i]:
				f.inter_nodes_up = set()
				f.inter_nodes_down = set()
				for f1 in f.nodes_up:
					f.inter_nodes_up.add(f1)
				for f1 in f.nodes_down:
					f.inter_nodes_down.add(f1)

			
	def Intersection_find(self):
		if len(flow_root.inter_nodes_down) == 0:
			return False
		# for f in flow_root.inter_nodes_down:
		# 	f.inter_nodes_up = flow_root
		# 	flow_root.inter_nodes_down.remove(f)
		# 	Transient_Flow = f
		# 	break
		Transient_Flow = flow_root
		inter_set = dict()
		inter_set[flow_root] = set()
		for i in xrange(1, len(match_data) + 1):
			for f in lvl_element[i]:
				inter_set[f] = set()

		# while 1:
		# 	if len(temp) == 0 :
		# 		break
		# 	tempc = set()
		# 	remove_temp = set()
		# 	if i <= self.level:
		# 		for f in temp:
		# 			if f.level == i:										
		# 				remove_temp.add(f)
		# 				comp_sign = self.flow_comp(f, 3)
		# 				if comp_sign == 3:
		# 					for f1 in f.nodes_down:						
		# 						tempc.add(f1)			
		# 	elif i > self.level:
		# 		for f in temp:
		# 			if f.level == i:										
		# 				remove_temp.add(f)
		# 				comp_sign = self.flow_comp(f, 4)
		# 				if comp_sign == 2:
		# 					self.nodes_down.add(f)
		# 					f1.nodes_up.append(self)
		# 					self.end_leaf_sign = False
		# 					# self.nodes_down_upsign = True
		# 				elif comp_sign == 3:
		# 					for f1 in f.nodes_down:						
		# 						tempc.add(f1)
		# 	for f in remove_temp:
		# 		temp.remove(f)
		# 	for f in tempc:
		# 		temp.add(f)
		# 	i = i + 1

		
		while 1: # depth
			if len(Transient_Flow.inter_nodes_down) == 0:
				if Transient_Flow.inter_nodes_up == False:
					break
				else:
					Transient_Flow = Transient_Flow.inter_nodes_up
			else:
				for f in Transient_Flow.inter_nodes_down:
					f.inter_nodes_up = Transient_Flow
					Transient_Flow.inter_nodes_down.remove(f)
					Transient_Flow = f
					break

				for f in inter_set[Transient_Flow.inter_nodes_up]:
					comp_sign = Transient_Flow.flow_comp(f, 5)
					if comp_sign == 3:
						inter_set[Transient_Flow].add(f)
						inter_set[f].add(Transient_Flow)
				i = Transient_Flow.inter_nodes_up.level + 1
				temp = set()
				for f in Transient_Flow.inter_nodes_up.inter_nodes_down:
					temp.add(f)


				while 1:
					if len(temp) == 0 :
						break
					tempc = set()
					remove_temp = set()
					for f in temp:
						if f.level == i:										
							remove_temp.add(f)
							comp_sign = Transient_Flow.flow_comp(f, 4)
							if comp_sign == 3:
								inter_set[Transient_Flow].add(f)
								inter_set[f].add(Transient_Flow)
								for f1 in f.inter_nodes_down:						
									tempc.add(f1)	

					for f in remove_temp:
						temp.remove(f)
					for f in tempc:
						temp.add(f)
					i = i + 1


		return inter_set
	def Intersection_find_nomal(self):
		# inter_set = dict()
		# inter_set[flow_root] = set()
		# for i in xrange(1, len(match_data) + 1):
		# 	for f in lvl_element[i]:
		# 		inter_set[f] = set()

		flowset_all = set()
		temp = set()
		for f in flow_root.nodes_down:
			temp.add(f)
		# i = 1
		# while 1:
		# 	if len(temp) == 0 :
		# 		break
		# 	remove_temp = set()
		# 	tempc = set()
		# 	for f in temp:
		# 		if f.level == i:										
		# 			remove_temp.add(f)
		# 			flowset_all.add(f)
		# 			for f1 in f.nodes_down:						
		# 				tempc.add(f1)
		# 	for f in remove_temp:
		# 		temp.remove(f)
		# 	for f in tempc:
		# 		temp.add(f)
		# 	i = i + 1

		for i in xrange(1, len(match_data) + 1):
			# print len(lvl_element[i])
			for f in lvl_element[i]:
				flowset_all.add(f)
		# print len(flowset_all)
		while 1:
			# print flowset_all
			if len(flowset_all) <= 1 :
				break
			for f in flowset_all:
				Transient_Flow = f
				flowset_all.remove(f)
				break
			for f in flowset_all:
				comp_sign1 = Transient_Flow.flow_comp(f, 4)
				comp_sign2 = Transient_Flow.flow_comp(f, 5)
				if (comp_sign1 == 3) and (comp_sign2 == 3):
					inter_set[Transient_Flow].add(f)
					inter_set[f].add(Transient_Flow)
		# return inter_set


class flow_generation(object):
	"""docstring for ClassName"""
	def __init__(self, generation_name, NUM = None):
		self.generation_name = generation_name
		if self.generation_name == "Rand_generation":
			self.flow_name = []
			self.num = NUM
			for x in xrange(1, self.num + 1):
				self.flow_name.append(False)		
			self.flow_rand_generation(NUM = self.num)

		elif self.generation_name == "Fix_1_generation":			
			self.fix_1_generation()

		elif self.generation_name == "Rand_generation_parameter":
			self.num = NUM
			self.lvl_build = self.lvl_element_init() 
			self.flow_rand_generation_parameter(NUM = self.num)
			self.flow_generation_lvlstruct()
		elif self.generation_name == "Rand_generation_1_real":
			pass

	def fix_1_generation(self):
		ac = []
		allow_set = set([1,2,3,11,12])
		ac.append(action_entry(action_name = "Flow_forbidden", allow_set = allow_set))
		flow1 = flow(nw_src = IPAddr('10.0.0.1'),
					 nw_dst = IPAddr('10.0.0.70'), actions = ac)
		ac = []
		allow_set = set([7,8,9,10,11,12])
		# path = [9,12,10,11,6,3,2,1]
		ac.append(action_entry(action_name = "Flow_forbidden", allow_set = allow_set, priority = 55))
		flow4 = flow(nw_dst = IPAddr('10.0.0.52'), actions = ac)

		ac = []
		allow_set = set([2,3,5,8,11,12])
		ac.append(action_entry(action_name = "Flow_forbidden", allow_set = allow_set))
		flow2 = flow(nw_src = IPAddr('10.0.0.5'),
					 nw_dst = IPAddr('10.0.0.70'), actions = ac)

		ac = []
		path = [1,2,3,6,11,10,12,9]
		# path = [9,12,10,11,6,3,2,1]
		ac.append(action_entry(action_name = "Path_choose", path = path, priority = 50))
		flow3 = flow(nw_src = IPAddr('10.0.0.1'),
					 nw_dst = IPAddr('10.0.0.52'), actions = ac)
		

		flow5 = flow(nw_src = IPAddr('10.0.0.1'))

		flow6 = flow(nw_src = IPAddr('10.0.0.1'),
					 nw_dst = IPAddr('10.0.0.52'),
					 tp_src = 8036)
		flow7 = flow(nw_src = IPAddr('10.0.0.1'),
					 tp_src = 8036)
		print "graph"
		print flow5
		print flow5.nodes_up
		print flow4
		print flow4.nodes_up
		print flow2
		print flow2.nodes_up
		print flow7
		print flow7.nodes_up
		print flow1
		print flow1.nodes_up
		print flow3
		print flow3.nodes_up
		print flow6
		print flow6.nodes_up

		

		# print flow_root.nodes_down
		# ac = []
		# allow_set = set([2,3,5,8,11,12])
		# ac.append(action_entry(action_name = "Flow_forbidden", allow_set = allow_set))
		# flow1 = flow(nw_src = IPAddr('10.0.0.1'),
		# 			 actions = ac, priority = 55)
	
	def flow_generation_lvlstruct(self):
		n_sign = 1
		for i in range(1,len(match_data)+1): 
			for f in self.lvl_build[i]:

				flow(dl_src = f.match_data['dl_src'], dl_dst = f.match_data['dl_dst'], dl_vlan = f.match_data['dl_vlan'],
						dl_vlan_pcp = f.match_data['dl_vlan_pcp'], dl_type = None, nw_tos = f.match_data['nw_tos'], nw_proto = None,
						nw_src = f.match_data['nw_src'], nw_dst = f.match_data['nw_dst'], tp_src = f.match_data['tp_src'], 
						tp_dst = f.match_data['tp_dst'], actions = f.actions)
				print n_sign
				n_sign = n_sign + 1
		for i in range(1,len(match_data)+1): 
			print len(lvl_element[i])

	def flow_rand_generation_1(self):
		p1 = random.randint(1, len(self.lvl_build) - 2)
		p2 = random.randint(1, len(self.lvl_build[p1])) - 1
		f_data = self.match_data_gene_1(lvl = p1 + 1, up_node = self.lvl_build[p1][p2])

		startTimeStamp_1=time.time()
		f1 = flow(dl_src = f_data.match_data['dl_src'], dl_dst = f_data.match_data['dl_dst'], dl_vlan = f_data.match_data['dl_vlan'],
						dl_vlan_pcp = f_data.match_data['dl_vlan_pcp'], dl_type = None, nw_tos = f_data.match_data['nw_tos'], nw_proto = None,
						nw_src = f_data.match_data['nw_src'], nw_dst = f_data.match_data['nw_dst'], tp_src = f_data.match_data['tp_src'], 
						tp_dst = f_data.match_data['tp_dst'], actions = f_data.actions)
		endTimeStamp_1=time.time()
		print "build time:"
		print (endTimeStamp_1-startTimeStamp_1)*1000, 'ms'
		return f1
	
	def flow_rand_generation_parameter(self, NUM = None): # times 100, /100 = NUM, virtual for test
		rules_NUM = NUM * 100             
		# p_up = 0.75 # probability of relatation to the level(self.level - 1)
		p_up = 0.75
		lvl_1_NUM = int(rules_NUM * 0.1) #  /10 = int ; means the NUM of entire nodes in this level
		lvl_2_NUM = int(rules_NUM * 0.3)
		lvl_3_NUM = int(rules_NUM * 0.1)
		lvl_4_NUM = int(rules_NUM * 0.1)
		lvl_5_NUM = int(rules_NUM * 0.1)	
		lvl_6_NUM = int(rules_NUM * 0.1)
		lvl_7_NUM = int(rules_NUM * 0.1)
		lvl_8_NUM = int(rules_NUM * 0.1)
		lvl_NUM = [1, lvl_1_NUM, lvl_2_NUM, lvl_3_NUM, lvl_4_NUM, lvl_5_NUM, lvl_6_NUM, lvl_7_NUM, lvl_8_NUM]
		for x in xrange(1, 9):
			lvl_NUM_temp = lvl_NUM[x]
			for i in xrange(1, x + 1):
				
				k = x + 1 - i
				if k == 1:
					for sign in xrange(0, lvl_NUM_temp):
						self.lvl_build[x].append(self.match_data_gene_1(lvl = x))
				else:
					num_temp = int(p_up * lvl_NUM_temp)
					lvl_NUM_temp = lvl_NUM_temp - num_temp
					for sign in xrange(0, num_temp):
						p1 = random.randint(0, lvl_NUM[x - 1] - 1)
						self.lvl_build[x].append(self.match_data_gene_1(lvl = x, up_node = self.lvl_build[x - 1][p1]))

	def match_data_gene_1(self, lvl = 1, up_node = "ROOT"): #generate one flow match data randomly based on the level and related up_node
		f = primary_matchnode()
		f.level = lvl
		if up_node == "ROOT":
			i = f.level
			n = 9
			for m in f.match_data:
				if i >= 1:
					p = random.randint(1, n)
					n = n - 1
					if p == 1:						
						i = i - 1
						f.match_data[m] = self.match_data_rand(m = m)

		else:
			i = f.level - up_node.level
			n = 9 - up_node.level

			for m in up_node.match_data:
				if up_node.match_data[m] != None:
					f.match_data[m] = up_node.match_data[m]
				else:
					if i >= 1:
						p = random.randint(1, n)
						n = n - 1
						if p == 1:							
							i = i - 1
							f.match_data[m] = self.match_data_rand(m = m)
		p = random.randint(1, 3)
		if p == 1:
			f.actions.append(self.action_rand(action_name = "Flow_forbidden"))
		else:
			f.actions.append(self.action_rand(action_name = "Flow_forbidden"))

		return f

	def match_data_rand(self, m = None):
		if m != None:

			if m == 'nw_src':
				p = random.randint(1, 240)
				p_s = '%d'%p
				str_s = ['10.0.0.', p_s]
				tmp = ''.join(str_s)
				match_data = IPAddr(tmp)

			elif m == 'nw_dst':
				p = random.randint(1, 240)
				p_s = '%d'%p
				str_s = ['10.0.0.', p_s]
				tmp = ''.join(str_s)
				match_data = IPAddr(tmp)

			elif m == 'dl_src':
				addr_t = []
				for x in xrange(1,7):
					int_N = random.randint(1, 255)
					if int_N < 16:
						add_0 = []
						add_0.append('0')
						add_0.append(hex(int_N)[2])
						addr_t.append(''.join(add_0))
					else:
						addr_t.append(''.join(hex(int_N)[2: ]))
				addr = '-'.join(addr_t)

				match_data = EthAddr(addr)
			elif m == 'dl_dst':
				addr_t = []
				for x in xrange(1,7):
					int_N = random.randint(1, 255)
					if int_N < 16:
						add_0 = []
						add_0.append('0')
						add_0.append(hex(int_N)[2])
						addr_t.append(''.join(add_0))
					else:
						addr_t.append(''.join(hex(int_N)[2: ]))
				addr = '-'.join(addr_t)
				match_data = EthAddr(addr)

			elif m == 'dl_vlan':
				match_data = random.randint(1, 500)
			# elif m == 'dl_vlan_pcp':
			# 	match_data_tmp[m] = None
			elif m == 'tp_src':
				match_data = random.randint(1, 2000)
			elif m == 'tp_dst':
				match_data = random.randint(1, 2000)
			elif m == 'nw_tos':
				match_data = random.randint(1, 500)
			elif m == 'dl_vlan_pcp':
				match_data = random.randint(1, 500)

			return match_data 
	
	def action_rand(self, action_name = None):
		if action_name == "Flow_forbidden":
			p = random.randint(0, 100)
			flow_allow_set = set()
			for x in xrange(1,12):
				if p < 30:
					p1 = random.randint(1, 12)
					if p1 not in flow_allow_set:
						flow_allow_set.add(p1)
			action = action_entry(action_name = "Flow_forbidden", allow_set = flow_allow_set)
			return action
		
	def hex_d0x(self, int_N):
		 if isinstance(int_N, int):
		 	hex(int_N)[2: ]
		 else:
			pass	

	def lvl_element_init(self):
		lvl_element_temp = []
		for i in range(0,len(match_data)+1):
			tmp = []
			lvl_element_temp .append(tmp)
		lvl_element_temp[0].append('ROOT')
		return lvl_element_temp
	
	def flow_rand_generation(self, NUM = None):
		
		print "runing"
		for x in xrange(0, NUM):
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
			# startTimeStamp = time.time()
			self.flow_name[x] = flow(nw_src = match_data_tmp['nw_src'], nw_dst = match_data_tmp['nw_dst'], dl_vlan = match_data_tmp['dl_vlan'], tp_src = match_data_tmp['tp_src'], 
									tp_dst = match_data_tmp['tp_dst'])

			p = random.randint(0, 100)
			if p < 70:
				p1 = random.randint(1, 12)
				flow_allow_set = set([1,2,3,4,5,6,7,8,9,10,11,12])
				flow_allow_set.remove(p1)
				self.flow_name[x].actions.append(action_entry(action_name = "Flow_forbidden", allow_set = flow_allow_set))
			

class primary_matchnode(object):
	"""docstring for ClassName"""
	def __init__(self, actions = None):
 		self.match_data = {
 		'dl_src' : None,
 		'dl_dst' : None,
 		'dl_vlan' : None,
 		'dl_vlan_pcp' : None,
 		# 'dl_type' : None,
 		'nw_tos' : None,
 		'nw_src' : None,
 		'nw_dst' : None,
 		'tp_src' : None,
 		'tp_dst' : None,
 		}
		self.nodes_down = set()
		self.nodes_up = set()
		self.actions = []
		self.level = 0
	

def launch():
	#global _noflood_by_default, _hold_down
	#if no_flood is True:
	#	_noflood_by_default = True
	#if hold_down is True:
	#	_hold_down = True
	# startTimeStamp=time.time()
	# flow_generation(generation_name = "Fix_1_generation")

	ge = flow_generation(generation_name = "Rand_generation_parameter", NUM = 10)
	# flow_generation(generation_name = "Rand_generation", NUM = 2500)
	
	# startTimeStamp1=time.time()
	# intersection = Conflict_Find(Conflict_name = "Intersection")
	# endTimeStamp1=time.time()
	# startTimeStamp2=time.time()
	# intersection_nomal = Conflict_Find(Conflict_name = "Intersection_nomal")
	# endTimeStamp2=time.time()
	# print "Intersection is shown:"
	# print (endTimeStamp1-startTimeStamp1)*1000, 'ms'
	# # print intersection.intersection_dict
	# print " The Nomal Intersection is shown:" 
	# print (endTimeStamp2-startTimeStamp2)*1000, 'ms'
	# # print intersection_nomal.intersection_dictp

	# print lvl_element
	# p1 = random.randint(1, len(ge.lvl_build) - 1)
	# p2 = random.randint(0, len(ge.lvl_build[p1]) - 2)

	# startTimeStamp1=time.time()
	# intersection = lvl_element[p1][p2].find_intersection()
	# endTimeStamp1=time.time()
	# startTimeStamp2=time.time()
	# intersection = lvl_element[p1][p2].find_intersection_nomal()
	# endTimeStamp2=time.time()
	
	f1 = ge.flow_rand_generation_1()

	for f in f1.nodes_up:
		f.find_intersection()
		temp = set()
		for x in f.intersection:
			sign1 = f1.flow_comp(x, sign = 4 )
			sign2 = f1.flow_comp(x, sign = 5 )
			if sign1 == 2 or sign2 == 1:
				temp.add(x)
		print len(f.intersection)
		for x in temp:

			f.intersection.remove(x)		


	startTimeStamp3=time.time()
	intersection = f1.find_intersection_from_nodeup()
	print len(intersection)
	endTimeStamp3=time.time()
	startTimeStamp1=time.time()

	intersection = f1.find_intersection()
	print len(intersection)
	endTimeStamp1=time.time()
	startTimeStamp2=time.time()
	intersection = f1.find_intersection_nomal()
	print len(intersection)
	endTimeStamp2=time.time()
	

	print "Intersection is shown:"
	print (endTimeStamp1-startTimeStamp1)*1000, 'ms'
	# print intersection.intersection_dict
	print " The Nomal Intersection is shown:"
	print (endTimeStamp2-startTimeStamp2)*1000, 'ms'
	# print intersection_nomal.intersection_dict
	print " from_nodeup:"
	print (endTimeStamp3-startTimeStamp3)*1000, 'ms'
	# print flow1.actions
	# print flow1.active_action

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
