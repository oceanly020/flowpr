
import sys
sys.path.append("..")
from clchecker.cover_graph import *
from helper import *
from time import time, clock

class action(object):
	"""
		action in rules
		1:forward
		2:modify
		3:ACL

	"""
	def __init__(self, atype):
		self.atype = atype
		self.priority = 0
		rule_id = None
		if self.atype == 1:
			# outport = 0 is drop, list for multi-ports forwarding
			# outport = 1 is switch
			# outport = 2 is inport
			self.outport = []		
		elif self.atype == 2:
			# 0: without modified; 1: modified
			self.modify_MF_sign =  {
			'dl_src' : 0,
			'dl_dst' : 0,
			'dl_vlan' : 0,
			'dl_vlan_pcp' : 0,
			'dl_type' : 0,
			'nw_tos' : 0,
			'nw_proto' : 0,
			'nw_src' : [0, 0, 0, 0],
			'nw_dst' : [0, 0, 0, 0],
			'tp_src' : 0,
			'tp_dst' : 0,
			}
			#modify fields
			self.modify_MF =  {
			'dl_src' : None,
			'dl_dst' : None,
			'dl_vlan' : None,
			'dl_vlan_pcp' : None,
			'dl_type' : None,
			'nw_tos' : None,
			'nw_proto' : None,
			'nw_src' : [None, None, None, None],
			'nw_dst' : [None, None, None, None],
			'tp_src' : None,
			'tp_dst' : None,
			}
		elif self.atype == 3:
			# 1: permit
			# 0: deny
			self.ACL_state = 1
		else:
			print "Fail to create action! Type wrong!"

class rule(object):
	"""one rule, has match fields, switch, actions """
	def __init__(self):
		#1: wildcard
		self.mf_wc = {
		
		'dl_src' : 1,
		'dl_dst' : 1,
		'dl_vlan' : 1,
		'dl_vlan_pcp' : 1,
		'dl_type' : 1,
		'nw_tos' : 1,
		'nw_proto' : 1,
		'nw_src' : [1, 1, 1, 1],
		'nw_dst' : [1, 1, 1, 1],
		'tp_src' : 1,
		'tp_dst' : 1,
		'inport' : 1,
		}
		self.mf = {
		
		'dl_src' : None,
		'dl_dst' : None,
		'dl_vlan' : None,
		'dl_vlan_pcp' : None,
		'dl_type' : None,
		'nw_tos' : None,
		'nw_proto' : None,
		'nw_src' : [None, None, None, None],
		'nw_dst' : [None, None, None, None],
		'tp_src' : None,
		'tp_dst' : None,
		'inport' : None,
		}
		# self.mf_up_bound = {
		# 'nw_src' : None,
		# 'nw_dst' : None,
		# 'tp_src' : None,
		# 'tp_dst' : None,
		# }
		# self.mf_lo_bound = {
		# 'nw_src' : None,
		# 'nw_dst' : None,
		# 'tp_src' : None,
		# 'tp_dst' : None,
		# }

		# self.inport =
		self.location = 0
		self.actions = []
		self.rule_id = 0
		self.level = 0

	def rule_to_string(self):
		output = "Matchfield:"
		mf = ('inport', 'dl_src', 'dl_dst', 'dl_vlan', 'dl_vlan_pcp', 'dl_type', 'nw_tos', \
				  'nw_proto', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst')

		for m_field in mf:
			if self.mf_wc[m_field] == 1:
				output = output + m_field + " (wildcard),"
			else:
				if m_field == 'nw_src' or m_field == 'nw_dst':
					output = output + " " + m_field + "(%s),"%(array_to_dotted_ip(self.mf[m_field]))
				elif m_field == 'dl_src' or m_field == 'dl_dst':
					output = output + " " + m_field + "(%s),"%(int_to_mac(self.mf[m_field]))
				else:
					output = output + " " + m_field + "(%d),"%(self.mf[m_field])

		output.rstrip(",")
		output = output + " Switchlocation: %d Action: "%self.location

		for ac in self.actions:
			if ac.atype == 1:
				output = output + " forwarding("
				for port in ac.outport:
					output = output + " %d"%port + ","
				output.rstrip(",")
				output = output + ")"
			elif ac.atype == 2:
				output = output + " modify("
				for m_field in mf:
					if m_field in ac.modify_MF_sign:
						if ac.modify_MF_sign[m_field] == 1:
							if m_field == 'nw_src' or m_field == 'nw_dst':
								output = output + " " + m_field + ": %s"%(array_to_dotted_ip(ac.modify_MF[m_field])) + ","
							else:
								output = output + " " + m_field + ": %d"%(ac.modify_MF[m_field]) + ","
				output.rstrip(",")
				output = output + ")"
			elif ac.atype == 3:
				output = output + " ACL("   
				if ac.ACL_state == 1:
					output = output + "permit)"
				else:
					output = output + "deny)"
		
		return output	

	def get_mf_level(self):
		self.level = 0
		for x in match_data_ord:
			if self.mf_wc[x] == 0:
				self.level = self.level + 1
		for x in match_data_addr :
			for token in [0,1,2,3] :
				if self.mf_wc[x][token] == 0:
					self.level = self.level + 1

	def node_generate(self, cover_graph):
		node_ge = node()
		for mf_token in match_data_ord:
			node_ge.mf_wc[mf_token] = self.mf_wc[mf_token]
			node_ge.mf[mf_token] = self.mf[mf_token]
		for mf_token in match_data_addr:
			for token in [0,1,2,3]:
				node_ge.mf_wc[mf_token][token] = self.mf_wc[mf_token][token]
				node_ge.mf[mf_token][token] = self.mf[mf_token][token]
		for ac in self.actions:
			node_ge.actions.append(ac)
		node_ge.location = self.location	
		node_ge.get_mf_level()
		if node_ge.level == 0:
			return cover_graph.lvl_element[0][node_ge.location - 1]
		
		time1 = time()
		node_ge_final = node_ge.location_find(cover_graph)
		time2 = time()

		print "Using cover_graph: ", (time2 - time1)*1000
		print "NUM of intersection: ", len(node_ge_final.intersection),len(node_ge_final.coverd),len(node_ge_final.covering)

		time1 = time()
		intersection = node_ge_final.find_intersection_nomal(cover_graph)
		intersection.discard(node_ge_final)
		time2 = time()
		print "Normal method: ", (time2 - time1)*1000
		print "NUM of intersection: ", len(intersection)
		# time1 = time()
		# intersection = node_ge.find_intersection_cover_graph(cover_graph)
		# time2 = time()
		# print "intersection_cover_graph: ", (time2 - time1)*1000
		# print "NUM of intersection: ", len(intersection)
		return node_ge_final
		
	def node_generate_backup(self, cover_graph):
		node_ge = node()
		for mf_token in match_data_ord:
			node_ge.mf_wc[mf_token] = self.mf_wc[mf_token]
			node_ge.mf[mf_token] = self.mf[mf_token]
		for mf_token in match_data_addr:
			for token in [0,1,2,3]:
				node_ge.mf_wc[mf_token][token] = self.mf_wc[mf_token][token]
				node_ge.mf[mf_token][token] = self.mf[mf_token][token]
		for ac in self.actions:
			node_ge.actions.append(ac)
		node_ge.location = self.location	
		node_ge.get_mf_level()
		if node_ge.level == 0:
			return cover_graph.lvl_element[0][node_ge.location - 1]
		time1 = time()
		node_ge_final = node_ge.location_find_backup(cover_graph)
		time2 = time()

		# print len({x for x in node_ge_final.intersection if x.level == node_ge_final.level})
		# i = 0
		# for f in node_ge_final.intersection:
		# 	if node_ge_final.matchfield_comp(f, 4) == 3:
		# 		i = i+1
		# print "the difference", i
		print "Using cover_graph_backup: ", (time2 - time1)*1000
		print "NUM of intersection: ", len(node_ge_final.intersection),len(node_ge_final.coverd),len(node_ge_final.covering)
		return node_ge_final

	def node_generate_backup2(self, cover_graph):
		node_ge = node()
		for mf_token in match_data_ord:
			node_ge.mf_wc[mf_token] = self.mf_wc[mf_token]
			node_ge.mf[mf_token] = self.mf[mf_token]
		for mf_token in match_data_addr:
			for token in [0,1,2,3]:
				node_ge.mf_wc[mf_token][token] = self.mf_wc[mf_token][token]
				node_ge.mf[mf_token][token] = self.mf[mf_token][token]
		for ac in self.actions:
			node_ge.actions.append(ac)
		node_ge.location = self.location	
		node_ge.get_mf_level()
		if node_ge.level == 0:
			return cover_graph.lvl_element[0][node_ge.location - 1]
		time1 = time()
		node_ge_final = node_ge.location_find_backup2(cover_graph)
		time2 = time()

		print "Using cover_graph_backup2: ", (time2 - time1)*1000
		print "NUM of intersection: ", len(node_ge_final.intersection),len(node_ge_final.coverd),len(node_ge_final.covering)
		return node_ge_final
	
	def trie_leaf_node_generate(self, trie_root):
		node_ge = node()
		for mf_token in match_data_ord:
			node_ge.mf_wc[mf_token] = self.mf_wc[mf_token]
			node_ge.mf[mf_token] = self.mf[mf_token]
		for mf_token in match_data_addr:
			for token in [0,1,2,3]:
				node_ge.mf_wc[mf_token][token] = self.mf_wc[mf_token][token]
				node_ge.mf[mf_token][token] = self.mf[mf_token][token]
		for ac in self.actions:
			node_ge.actions.append(ac)
		node_ge.location = self.location

		time1 = time()
		node_ge_final = node_ge.location_find_in_trie_tree(trie_root)
		time2 = time()
		print "Trie tree find location: ", (time2 - time1)*1000

	def trie_find_intersection(self, trie_root):
		node_ge = node()
		for mf_token in match_data_ord:
			node_ge.mf_wc[mf_token] = self.mf_wc[mf_token]
			node_ge.mf[mf_token] = self.mf[mf_token]
		for mf_token in match_data_addr:
			for token in [0,1,2,3]:
				node_ge.mf_wc[mf_token][token] = self.mf_wc[mf_token][token]
				node_ge.mf[mf_token][token] = self.mf[mf_token][token]
		for ac in self.actions:
			node_ge.actions.append(ac)
		node_ge.location = self.location

		time1 = time()
		node_ge_final = node_ge.location_find_in_trie_tree(trie_root)
		intersection = node_ge.find_intersection_in_trie_tree(trie_root)
		intersection.remove(node_ge_final)
		

		time2 = time()
		print "Trie tree find intersection: ", (time2 - time1)*1000
		print "NUM of intersection: ", len(intersection)


class rule_range(object):
	"""one rule, has match fields, switch, actions """
	def __init__(self):
		self.n_range = ('inport', 'dl_src', 'dl_dst', 'dl_vlan_pcp', 'dl_type', \
						'nw_tos', 'nw_proto', 'dl_vlan')
		self.range = ( 'nw_src', 'nw_dst', 'tp_src', 'tp_dst')
		#1: wildcard
		self.mf_wc = {
		'inport' : 1,
		'dl_src' : 1,
		'dl_dst' : 1,
		'dl_vlan' : 1,
		'dl_vlan_pcp' : 1,
		'dl_type' : 1,
		'nw_tos' : 1,
		'nw_proto' : 1,
		'nw_src' : [1, 1, 1, 1],
		'nw_dst' : [1, 1, 1, 1],
		'tp_src' : 1,
		'tp_dst' : 1,
		}
		self.mf_up_bound = {
		'inport' : None,
		'dl_src' : None,
		'dl_dst' : None,
		'dl_vlan_pcp' : None,
		'dl_type' : None,
		'nw_tos' : None,
		'nw_proto' : None,
		'dl_vlan' : None,
		'nw_src' : [None, None, None, None],
		'nw_dst' : [None, None, None, None],
		'tp_src' : None,
		'tp_dst' : None,
		}
		self.mf_lo_bound = {
		'inport' : None,
		'dl_src' : None,
		'dl_dst' : None,
		'dl_vlan_pcp' : None,
		'dl_type' : None,
		'nw_tos' : None,
		'nw_proto' : None,
		'dl_vlan' : None,
		'nw_src' : [None, None, None, None],
		'nw_dst' : [None, None, None, None],
		'tp_src' : None,
		'tp_dst' : None,
		}

		# self.inport =
		self.location = 0
		self.actions = []
		self.rule_id = 0
		self.level = 0

	def rule_to_string(self):
		output = "Matchfield:"
		for m_field in self.n_range:
			if self.mf_wc[m_field] == 1:
				output = output + m_field + " (wildcard),"
			else:
				if m_field == 'dl_src' or m_field == 'dl_dst':
					output = output + " " + m_field + "(%s),"%(int_to_mac(self.mf_lo_bound[m_field]))
				else:
					output = output + " " + m_field + "(%d),"%(self.mf_lo_bound[m_field])

		for m_field in self.range:
			if self.mf_wc[m_field] == 1:
				output = output + m_field + " (wildcard),"
			else:
				if m_field == 'nw_src' or m_field == 'nw_dst':
					output = output + " " + m_field + "(%s - %s)," \
					%(array_to_dotted_ip(self.mf_lo_bound[m_field]), array_to_dotted_ip(self.mf_up_bound[m_field]))
				else:
					output = output + " " + m_field + "(%d - %d)," \
					%(self.mf_lo_bound[m_field], self.mf_up_bound[m_field])

		output.rstrip(",")
		output = output + " Switchlocation: %d Action: "%self.location

		for ac in self.actions:
			if ac.atype == 1:
				output = output + " forwarding("
				for port in ac.outport:
					output = output + " %d"%port + ","
				output.rstrip(",")
				output = output + ")"
			elif ac.atype == 2:
				output = output + " modify("
				for m_field in ac.modify_MF_sign:
					# if m_field in ac.modify_MF_sign:
					if ac.modify_MF_sign[m_field] == 1:
						if m_field == 'nw_src' or m_field == 'nw_dst':
							output = output + " " + m_field + ": %s"%(array_to_dotted_ip(ac.modify_MF[m_field])) + ","
						else:
							output = output + " " + m_field + ": %d"%(ac.modify_MF[m_field]) + ","
				output.rstrip(",")
				output = output + ")"
			elif ac.atype == 3:
				output = output + " ACL("   
				if ac.ACL_state == 1:
					output = output + "permit)"
				else:
					output = output + "deny)"
		
		return output	

	def get_mf_level(self):
		self.level = 0
		for x in match_data_ord:
			if self.mf_wc[x] == 0:
				self.level = self.level + 1
		for x in match_data_addr :
			for token in [0,1,2,3] :
				if self.mf_wc[x][token] == 0:
					self.level = self.level + 1

	def node_generate(self, cover_graph):
		node_ge = node_range()
		for mf_token in match_data_ord:
			node_ge.mf_wc[mf_token] = self.mf_wc[mf_token]
			node_ge.mf_up_bound[mf_token] = self.mf_up_bound[mf_token]
			node_ge.mf_lo_bound[mf_token] = self.mf_lo_bound[mf_token]
		for mf_token in match_data_addr:
			for token in [0,1,2,3]:
				node_ge.mf_wc[mf_token][token] = self.mf_wc[mf_token][token]
				node_ge.mf_up_bound[mf_token][token] = self.mf_up_bound[mf_token][token]
				node_ge.mf_lo_bound[mf_token][token] = self.mf_lo_bound[mf_token][token]
		for ac in self.actions:
			node_ge.actions.append(ac)
		node_ge.location = self.location	
		node_ge.get_mf_level()
		if node_ge.level == 0:
			return cover_graph.lvl_element[0][node_ge.location - 1]
		print 'start'
		time1 = time()
		node_ge_final = node_ge.location_find(cover_graph)
		time2 = time()
		
		# print self.rule_to_string()
		print node_ge_final.node_to_string(), node_ge_final.level
		# print 'coverd'
		# for node in node_ge_final.coverd:
		# 	print node.node_to_string(), node.level
		# print 'covering'
		# if node_ge_final in node_ge_final.covering:
		# 	print 'node_ge_final in node_ge_final.covering'
		# for node in node_ge_final.covering:
		# 	print node.node_to_string()

		print "Using cover_graph: ", time2 - time1
		print "NUM of intersection: ", len(node_ge_final.intersection), len(node_ge_final.coverd), len(node_ge_final.covering)
		time1 = time()
		intersection = node_ge.find_intersection_nomal(cover_graph)
		
		time2 = time()
		intersection.discard(node_ge_final)
		print "Normal method: ", time2 - time1
		print "NUM of intersection: ", len(intersection)
		
		# for node in node_ge_final.covering:
		# 	if node not in intersection:
		# 		print node.node_to_string(), node.level, node.location, node.nodes_up


		# for node in intersection:
		# 	print node.node_to_string(), node.level

		return node_ge_final
		