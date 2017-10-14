

import sys
sys.path.append("..")
from config_parser.rules_range import *
from config_parser.helper import *


match_data_ord = (
		'inport',
		'dl_src',
		'dl_dst',
		'dl_vlan',
		'dl_vlan_pcp',
		'dl_type',
		'nw_tos',
		'nw_proto',
		'tp_src',
		'tp_dst',
		)
match_data_addr = (
		'nw_src',
 		'nw_dst',
 		)



class node_root(object):
	def __init__(self, cs_id = 0):
		self.intersection = set()
		self.coverd = set()
		
		self.nodes_up = False
		self.nodes_down = set()
		self.level = 0
		self.active_action = False
		self.location = cs_id
		# self.end_leaf_sign = False



class node(object):
	"""match fields, switch, actions, and nodes relationships """
	def __init__(self):
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
		self.mf = {
		'inport' : None,
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

		self.loaction = 0
		self.level = 0
		self.nodes_id = 0

		self.nodes_down = set()
		self.nodes_up = set()
		self.intersection = set()
		self.coverd = set()
		self.covering = set()

		self.actions = []
		self.active_action = []

	def node_to_string(self):
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
		output = output + " Switchlocation: %d Action: "%self.loaction

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

	def location_find_backup(self, cover_graph):		
		self.nodes_down = set()
		self.coverd = set()
		self.nodes_up = set()
		self.covering = set()
		self.intersection = set()	
		temp = set()
		i = 1	
		compare_num = 0

		for root in cover_graph.lvl_element[0]:
			if self.location == root.location:
				flow_root = root
				break

		# flow_root = cover_graph.lvl_element[0][self.loaction - 1]
		temp = temp | flow_root.nodes_down

		# for f in flow_root.nodes_down:
		# 	temp.add(f)		
		while 1: #find the coverd
			# print "temp:",i,self.level,len(temp)
			if i == self.level: 
				for f in temp:
					if f.level == i:
						compare_num = compare_num + 1
						comp_sign = self.matchfield_comp(f)
						if comp_sign == 0:
							print "This is the debug breakpoint!!!"
							for ac in self.actions:
								f.actions.append(ac)

							return f
				cover_graph.lvl_element[self.level].append(self)									
				break
			elif i > self.level: 				
				break

			if len(temp) == 0 :
				break

			tempc = set()
			remove_temp = set()
			for f in temp:
				if f.level == i:										
					remove_temp.add(f)		
					compare_num = compare_num + 1							
					comp_sign = self.matchfield_comp(f,1)
					if comp_sign == 1:
						self.nodes_up.add(f)
						self.coverd.add(f)
						tempc = tempc | f.nodes_down
						self.nodes_up = self.nodes_up - f.nodes_up
			i = i + 1
			temp = temp - remove_temp
			temp = temp | tempc


		temp = set()
		i = 100
		if len(self.nodes_up) == 0:
			remove_temp = set()  
			for f in flow_root.nodes_down:
				compare_num = compare_num + 1
				comp_sign = self.matchfield_comp(f, 4)
				if comp_sign == 2:
					remove_temp.add(f)
					f.nodes_up.remove(flow_root)
					self.nodes_down.add(f)
					f.nodes_up.add(self)			
					self.end_leaf_sign = False
					self.covering.add(f)
					f.coverd.add(self)
					# self.nodes_down_upsign = True
				elif comp_sign == 3:
					self.intersection.add(f)
					f.intersection.add(self)	
					for f1 in f.nodes_down:				
						temp.add(f1)
						if f1.level < i:
							i = f1.level					 
			self.nodes_up.add(flow_root)
			flow_root.nodes_down.add(self)
			flow_root.nodes_down = flow_root.nodes_down - remove_temp
		else:
			remove_temp = set()
			for f in self.nodes_up:
				for f1 in f.nodes_down:
					compare_num = compare_num + 1
					comp_sign = self.matchfield_comp(f1, 4)
					if comp_sign == 2:
						self.nodes_down.add(f1)
						f1.nodes_up.remove(f)
						f1.nodes_up.add(self)
						remove_temp.add(f1)
						self.end_leaf_sign = False
					elif comp_sign == 3:
						self.intersection.add(f1)
						f1.intersection.add(self)
						for f2 in f1.nodes_down:			
							temp.add(f2)							
							if f2.level < i:
								i = f2.level
				f.nodes_down = f.nodes_down - remove_temp		
			for f in self.nodes_up:
				f.nodes_down.add(self)
		while 1:#find the covering
			if len(temp) == 0 :
				break
			tempc = set()
			remove_temp = set()
			if i <= self.level:
				for f in temp:
					if f.level == i:										
						remove_temp.add(f)
						compare_num = compare_num + 1
						comp_sign = self.matchfield_comp(f, 3)
						if comp_sign == 3:
							self.intersection.add(f)
							f.intersection.add(self)
							tempc = tempc | f.nodes_down
			elif i > self.level:
				for f in temp:
					if f.level == i:										
						remove_temp.add(f)
						compare_num = compare_num + 1
						comp_sign = self.matchfield_comp(f, 4)
						if comp_sign == 2:
							self.nodes_down.add(f)
							f.nodes_up.add(self)
							self.end_leaf_sign = False
							self.covering.add(f)
							# self.nodes_down_upsign = True
						elif comp_sign == 3:
							self.intersection.add(f)
							f.intersection.add(self)
							tempc = tempc | f.nodes_down			
			temp = temp - remove_temp
			temp = temp | tempc
			i = i + 1

		parentsin_cup = set()
		for f in self.nodes_up:
			parentsin_cup = parentsin_cup | f.intersection
		parentsin_cup = parentsin_cup - self.intersection
		parentsin_cup = parentsin_cup - self.coverd
		parentsin_cup.discard(self)
		for f in parentsin_cup:
			compare_num = compare_num + 1
			sign = self.matchfield_comp(f, sign = 3 )
			if sign == 3:
				self.intersection.add(f)
				f.intersection.add(self)
		print "the num of compare",compare_num
		return self

	def location_find_backup2(self, cover_graph):		
		self.nodes_down = set()
		self.coverd = set()
		self.nodes_up = set()
		self.covering = set()
		self.intersection = set()	
		temp = set()
		i = 1	

		for root in cover_graph.lvl_element[0]:
			if self.location == root.location:
				flow_root = root
				break
		temp = temp | flow_root.nodes_down	
		while 1: #find the coverd
			if len(temp) == 0 :
				break			
			if i == self.level: 
				temp = {x for x in temp if x.level == i}
				for f in temp:
					if self.matchfield_comp(f) == 0:
						print "This is the debug breakpoint!!!"
						for ac in self.actions:
							f.actions.append(ac)
						return f
				cover_graph.lvl_element[self.level].append(self)									
				break
			elif i > self.level: 				
				break

			tempc = set()
			remove_temp = {x for x in temp if x.level == i}
			for f in remove_temp:								
				if self.matchfield_comp(f,1) == 1:
					self.nodes_up.add(f)
					self.coverd.add(f)
					tempc = tempc | f.nodes_down
					self.nodes_up = self.nodes_up - f.nodes_up
			i = i + 1
			temp = temp - remove_temp
			temp = temp | tempc

		temp = set()
		i = 100
		if len(self.nodes_up) == 0:
			remove_temp = set()  
			for f in flow_root.nodes_down:
				comp_sign = self.matchfield_comp(f, 4)
				if comp_sign == 2:
					remove_temp.add(f)
					f.nodes_up.remove(flow_root)
					self.nodes_down.add(f)
					f.nodes_up.add(self)			
					self.covering.add(f)
					self.covering = self.covering | f.covering
					f.coverd.add(self)
					for node in f.covering:
						node.coverd.add(self) 
					# self.nodes_down_upsign = True
				elif comp_sign == 3:
					self.intersection.add(f)
					f.intersection.add(self)	
					for f1 in f.nodes_down:				
						temp.add(f1)
						if f1.level < i:
							i = f1.level					 
			self.nodes_up.add(flow_root)
			flow_root.nodes_down.add(self)
			flow_root.nodes_down = flow_root.nodes_down - remove_temp
		else:
			remove_temp = set()
			for f in self.nodes_up:
				for f1 in f.nodes_down:
					comp_sign = self.matchfield_comp(f1, 4)
					if comp_sign == 2:
						self.nodes_down.add(f1)
						f1.nodes_up.remove(f)
						f1.nodes_up.add(self)
						remove_temp.add(f1)
						self.covering.add(f1)
						self.covering = self.covering | f1.covering
						f1.coverd.add(self)
						for node in f1.covering:
							node.coverd.add(self)
					elif comp_sign == 3:
						self.intersection.add(f1)
						f1.intersection.add(self)
						for f2 in f1.nodes_down:			
							temp.add(f2)							
							if f2.level < i:
								i = f2.level
				f.nodes_down = f.nodes_down - remove_temp		
			for f in self.nodes_up:
				f.nodes_down.add(self)
		while 1:#find the covering
			if len(temp) == 0 :
				break
			tempc = set()
			remove_temp = {x for x in temp if x.level == i}
			if i <= self.level:
				for f in remove_temp:
					if self.matchfield_comp(f, 3) == 3:
						self.intersection.add(f)
						f.intersection.add(self)
						tempc = tempc | f.nodes_down
			elif i > self.level:
				for f in remove_temp:
					comp_sign = self.matchfield_comp(f, 4)
					if comp_sign == 2:
						self.nodes_down.add(f)
						f.nodes_up.add(self)
						self.covering.add(f)
						self.covering =  self.covering | f.covering
						f.coverd.add(self)
						for node in f.covering:
							node.coverd.add(self)
						# self.nodes_down_upsign = True
					elif comp_sign == 3:
						self.intersection.add(f)
						f.intersection.add(self)
						tempc = tempc | f.nodes_down			
			temp = temp - remove_temp
			temp = temp | tempc
			i = i + 1

		parentsin_cup = set()
		for f in self.nodes_up:
			parentsin_cup = parentsin_cup | f.intersection
		parentsin_cup = parentsin_cup - (self.intersection | self.coverd | self.covering)
		parentsin_cup.discard(self)
		for f in parentsin_cup:
			sign = self.matchfield_comp(f, 3)
			if sign == 3:
				self.intersection.add(f)
				f.intersection.add(self)
		return self

	def location_find_backup3(self, cover_graph):	
		self.nodes_down = set()
		self.coverd = set()
		self.nodes_up = set()
		self.covering = set()
		self.intersection = set()	
		temp = set()
		i = 1	
		intr_temp = set()
		for root in cover_graph.lvl_element[0]:
			if self.location == root.location:
				flow_root = root
				break

		temp = temp | flow_root.nodes_down		
		while 1: 
			if len(temp) == 0 :
				break			
			if i == self.level: 
				tempc = set()
				remove_temp = {x for x in temp if x.level == i}
				for f in remove_temp:
					comp_sign = self.matchfield_comp(f)
					if comp_sign == 0:
						print "This is the debug breakpoint!!!"
						for ac in self.actions:
							f.actions.append(ac)
						return f
					elif comp_sign == 3:
						tempc = tempc | f.nodes_down
						self.intersection.add(f)

				temp = temp - remove_temp
				temp = temp | tempc
				cover_graph.lvl_element[self.level].append(self)

				tempc = set()	
				remove_temp = {x for x in intr_temp if x.level == i}
				for f in remove_temp:
					if self.matchfield_comp(f,3) == 3:
						tempc = tempc | f.nodes_down
						self.intersection.add(f)
						# f.intersection.add(self)
				intr_temp = intr_temp - remove_temp
				intr_temp = intr_temp | tempc
				intr_temp = intr_temp | temp
				i = i + 1	
				for f in self.intersection:
					f.intersection.add(self)				
				break
			elif i > self.level:							
				break

			tempc = set()
			inter_tempc = set()
			remove_temp = {x for x in temp if x.level == i}
			for f in remove_temp:	
				comp_sign = self.matchfield_comp(f,5)					
				if comp_sign == 1:
					self.nodes_up.add(f)
					self.coverd.add(f)
					tempc = tempc | f.nodes_down
					self.nodes_up = self.nodes_up - f.nodes_up
				elif comp_sign == 3:
					inter_tempc = inter_tempc | f.nodes_down
					self.intersection.add(f)
					# f.intersection.add(self)

			temp = temp - remove_temp
			temp = temp | tempc	
			tempc = set()	
			remove_temp = {x for x in intr_temp if x.level == i}
			intr_temp = intr_temp | inter_tempc
			for f in remove_temp:
				if self.matchfield_comp(f,3) == 3:
					tempc = tempc | f.nodes_down
					self.intersection.add(f)
					# f.intersection.add(self)
			intr_temp = intr_temp - remove_temp
			intr_temp = intr_temp | tempc	
			i = i + 1
			
		temp = set()
		temp = temp | intr_temp
		if len(self.nodes_up) == 0:
			self.nodes_up.add(flow_root)
			flow_root.nodes_down.add(self)
		else:
			for f in self.nodes_up:
				f.nodes_down.add(self)
		while 1:#find the covering
			if len(temp) == 0 :
				break
			tempc = set()
			remove_temp = {x for x in temp if x.level == i}
			for f in remove_temp:
				comp_sign = self.matchfield_comp(f, 4)
				if comp_sign == 2:
					self.nodes_down.add(f)						
					f.nodes_up = f.nodes_up - self.nodes_up
					f.nodes_up.add(self)
					self.covering.add(f)
					self.covering =  self.covering | f.covering
					f.coverd.add(self)
					for node in f.covering:
						node.coverd.add(self)
					# self.nodes_down_upsign = True
				elif comp_sign == 3:
					self.intersection.add(f)
					f.intersection.add(self)
					tempc = tempc | f.nodes_down	
				
			temp = temp - remove_temp
			temp = temp | tempc
			i = i + 1
		for f in self.nodes_up:
			f.nodes_down = f.nodes_down - self.nodes_down
		return self

	def location_find(self, cover_graph):	
		self.nodes_down = set()
		self.coverd = set()
		self.nodes_up = set()
		self.covering = set()
		self.intersection = set()	
		temp = set()
		i = 1	
		intr_temp = set()

		for root in cover_graph.lvl_element[0]:
			if self.location == root.location:
				flow_root = root
				break
		temp = temp | flow_root.nodes_down	
		compare_num = 0
		while 1: 
			if len(temp) == 0 :
				break			
			if i == self.level: 
				tempc = set()
				remove_temp = {x for x in temp if x.level == i}
				for f in remove_temp:
					comp_sign = self.matchfield_comp(f)
					compare_num = compare_num + 1
					if comp_sign == 0:
						print "This is the debug breakpoint!!!"
						for ac in self.actions:
							f.actions.append(ac)
						return f
					elif comp_sign == 3:
						tempc = tempc | f.nodes_down
						self.intersection.add(f)

				temp = temp - remove_temp
				temp = temp | tempc
				cover_graph.lvl_element[self.level].append(self)

				tempc = set()	
				remove_temp = {x for x in intr_temp if x.level == i}
				for f in remove_temp:
					compare_num = compare_num + 1
					if self.matchfield_comp(f,3) == 3:
						tempc = tempc | f.nodes_down
						self.intersection.add(f)
						# f.intersection.add(self)
				intr_temp = intr_temp - remove_temp
				intr_temp = intr_temp | tempc
				temp = intr_temp | temp
				i = i + 1	
				for f in self.intersection:
					f.intersection.add(self)				
				break
			elif i > self.level:							
				break

			tempc = set()
			inter_tempc = set()
			remove_temp = {x for x in temp if x.level == i}
			for f in remove_temp:	
				comp_sign = self.matchfield_comp(f,5)	
				compare_num = compare_num + 1				
				if comp_sign == 1:
					self.nodes_up.add(f)
					self.coverd.add(f)
					tempc = tempc | f.nodes_down
					self.nodes_up = self.nodes_up - f.nodes_up
				elif comp_sign == 3:
					inter_tempc = inter_tempc | f.nodes_down
					self.intersection.add(f)
					# f.intersection.add(self)

			temp = temp - remove_temp
			temp = temp | tempc	
			tempc = set()	
			remove_temp = {x for x in intr_temp if x.level == i}
			intr_temp = intr_temp | inter_tempc
			for f in remove_temp:
				compare_num = compare_num + 1
				if self.matchfield_comp(f,3) == 3:
					tempc = tempc | f.nodes_down
					self.intersection.add(f)
					# f.intersection.add(self)
			intr_temp = intr_temp - remove_temp
			intr_temp = intr_temp | tempc	
			i = i + 1
			
		# temp = set()
		# temp = temp | intr_temp
		if len(self.nodes_up) == 0:
			self.nodes_up.add(flow_root)
			flow_root.nodes_down.add(self)
		else:
			for f in self.nodes_up:
				f.nodes_down.add(self)
		while 1:#find the covering
			if len(temp) == 0 :
				break
			tempc = set()
			remove_temp = {x for x in temp if x.level == i}
			for f in remove_temp:
				compare_num = compare_num + 1
				comp_sign = self.matchfield_comp(f, 4)
				if comp_sign == 2:
					self.nodes_down.add(f)						
					f.nodes_up = f.nodes_up - self.nodes_up
					f.nodes_up.add(self)
					self.covering.add(f)
					self.covering =  self.covering | f.covering
					f.coverd.add(self)
					for node in f.covering:
						node.coverd.add(self)
					# self.nodes_down_upsign = True
				elif comp_sign == 3:
					self.intersection.add(f)
					f.intersection.add(self)
					tempc = tempc | f.nodes_down	
				
			temp = temp - remove_temp
			temp = temp | tempc
			i = i + 1
		for f in self.nodes_up:
			f.nodes_down = f.nodes_down - self.nodes_down
		print "the num of compare",compare_num
		return self



	def find_intersection_cover_graph(self, cover_graph):
		for root in cover_graph.lvl_element[0]:
			if self.location == root.location:
				flow_root = root
				break
		intersection_set = set()
		temp = set()
		temp = temp | flow_root.nodes_down
		i = 1
		while 1: 
			if len(temp) == 0 :
				break			

			tempc = set()
			remove_temp = {x for x in temp if x.level == i}
			for f in remove_temp:								
				if self.matchfield_comp(f,3) == 3:
					intersection_set.add(f)
					tempc = tempc | f.nodes_down
			i = i + 1
			temp = temp - remove_temp
			temp = temp | tempc
		intersection_set.discard(self)
		return intersection_set		

	def location_find_in_trie_tree(self, trie_root):
		token = trie_root
		for lvl in match_data_addr:
			for num in xrange(0,4):
				if self.mf_wc[lvl][num] == 1:
					if token.has_key('wc') != True:
						token['wc'] = {}
					token = token['wc']
				else:
					if token.has_key(self.mf[lvl][num]) != True:
						token[self.mf[lvl][num]] = {}
					token = token[self.mf[lvl][num]]

		for num in xrange(0, len(match_data_ord)-1):
			lvl_mf = match_data_ord[num]
			if self.mf_wc[lvl_mf] == 1:
				if token.has_key('wc') != True:
					token['wc'] = {}
				token = token['wc']
			else:
				if token.has_key(self.mf[lvl_mf]) != True:
					token[self.mf[lvl_mf]] = {}
				token = token[self.mf[lvl_mf]]
		lvl_mf = match_data_ord[len(match_data_ord)-1]
		if self.mf_wc[lvl_mf] == 1:
			if token.has_key('wc'):
				for ac in self.actions:
					token['wc'].actions.append(ac)
			else:	
				token['wc'] = self
			token = token['wc']
		else:
			if token.has_key(self.mf[lvl_mf]):
				for ac in self.actions:
					token[self.mf[lvl_mf]].actions.append(ac)
			else:
				token[self.mf[lvl_mf]] = self
			token = token[self.mf[lvl_mf]] 
		return token

	def find_intersection_in_trie_tree(self, trie_root):# breadth-first
		compare_num = 0
		append_num = 0
		temp = []
		temp.append(trie_root)
		for lvl in match_data_addr:			
			for num in xrange(0,4):
				tempc = []
				if self.mf_wc[lvl][num] == 1:
					for token in temp:
						for tab in token:
							append_num = append_num + 1
							tempc.append(token[tab])
				else:
					for token in temp:
						compare_num = compare_num + 1
						if token.has_key('wc'):
							append_num = append_num + 1
							tempc.append(token['wc'])
						compare_num = compare_num + 1
						if token.has_key(self.mf[lvl][num]):
							append_num = append_num + 1
							tempc.append(token[self.mf[lvl][num]])
				temp = []
				for element in tempc:
					temp.append(element)
				print len(temp)

		for lvl in match_data_ord:
			tempc = []
			if self.mf_wc[lvl] == 1:
				for token in temp:
					for tab in token:
						append_num = append_num + 1
						tempc.append(token[tab])
			else:
				for token in temp:
					compare_num = compare_num + 1
					if token.has_key('wc'):		
						append_num = append_num + 1	
						tempc.append(token['wc'])
					compare_num = compare_num + 1
					if token.has_key(self.mf[lvl]):	
						append_num = append_num + 1
						tempc.append(token[self.mf[lvl]])
			temp = []
			for element in tempc:
				append_num = append_num + 1
				temp.append(element)
			print len(temp)
		print "the num of compare",compare_num
		print "the num of append",append_num
		return temp

	def find_intersection_nomal(self, cover_graph):
		compare_num = 0
		intersection_set = set()
		flowset_all = set()			
		compare_num = 0

		for lvl in cover_graph.lvl_element:

			for f in lvl:
				flowset_all.add(f)


		for f in flowset_all:
			if f.nodes_up != False:
				if f.location == self.location:
					compare_num = compare_num + 1

					comp_sign = self.matchfield_comp(f, 4)
					comp_sign = self.matchfield_comp(f, 5)
					if comp_sign == 3:
						intersection_set.add(f)
					elif comp_sign == 1:
						intersection_set.add(f)

		print "the num of compare",compare_num

		return intersection_set

	def matchfield_comp_backup(self, f, sign = 0 ):
		"""-----------------------------------------------------------------
		sign = 0 self = f: 0
		sign = 1 self < f: 1 
		sign = 2 self > f: 2 
		intersection: 3 sign = 3
		sign = 4 intersection & self > f: self > f  2 ;intersection  3 
		sign = 5 intersection & self > f: self < f  1 ;intersection: 3
		other: 9 
		----------------------------------------------------------------"""
		if sign == 0:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if f.mf_wc[ipaddr][m] == self.mf_wc[ipaddr][m]:
						if f.mf_wc[ipaddr][m] == 1:
							continue

						elif f.mf[ipaddr][m] != self.mf[ipaddr][m]:
							return 9

					else:
						return 9

			for m in match_data_ord:
				if f.mf_wc[m] == self.mf_wc[m]:
					if f.mf_wc[m] == 1:
						continue
					elif f.mf[m] != self.mf[m]:
						return 9
				else:
					return 9
			return 0
						
		elif sign == 1:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if f.mf_wc[ipaddr][m] == 1:
						continue
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9

			for m in match_data_ord:
				if f.mf_wc[m] == 1:
					continue
				elif f.mf[m] != self.mf[m]:
					return 9
			return 1


		elif sign == 2:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1:
						continue
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9

			for m in match_data_ord:
				if self.mf_wc[m] == 1:
					continue
				elif f.mf[m] != self.mf[m]:
					return 9
			return 2

		elif sign == 3:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1 or f.mf_wc[ipaddr][m] == 1:
						continue
					elif  f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9
			for m in match_data_ord:
				if self.mf_wc[m] == 1 or f.mf_wc[m] == 1:
					continue
				elif f.mf[m] != self.mf[m]:
					return 9
			return 3

		elif sign == 4:

			contain = True
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1:
						continue
					if f.mf_wc[ipaddr][m] == 1:
						contain = False
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]: 
						return 9
			for m in match_data_ord:
				if self.mf_wc[m] == 1:
					continue
				if f.mf_wc[m] == 1:
					contain = False
				elif f.mf[m] != self.mf[m]:
					return 9
			if contain == True:
				return 2
			else:
				return 3

			
		elif sign == 5:
			contain = True
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if f.mf_wc[ipaddr][m] == 1:
						continue
					elif self.mf_wc[ipaddr][m] == 1:
						contain = False
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9
			for m in match_data_ord:
				if f.mf_wc[m] == 1:
					continue
				elif self.mf_wc[m] == 1:
					contain = False
				elif f.mf[m] != self.mf[m]:
					return 9

			if contain == True:
				return 1
			else:
				return 3

	def matchfield_comp(self, f, sign = 0 ):
		"""-----------------------------------------------------------------
		sign = 0 self = f: 0  ;intersection: 3
		sign = 1 self < f: 1 
		sign = 2 self > f: 2 
		intersection: 3 sign = 3
		sign = 4 intersection & self > f: self > f  2 ;intersection  3 
		sign = 5 intersection & self > f: self < f  1 ;intersection: 3
		other: 9 
		----------------------------------------------------------------"""
		if sign == 0:
			issame = 1
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1: 
						if f.mf_wc[ipaddr][m] == 1:
							continue
						else:
							issame = 0
							continue
					elif f.mf_wc[ipaddr][m] == 1 :
						issame = 0
						continue
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9
			for m in match_data_ord:
				if self.mf_wc[m] == 1: 
					if f.mf_wc[m] == 1:
						continue
					else:
						issame = 0
						continue
				elif f.mf_wc[m] == 1:
					issame = 0
					continue
				elif f.mf[m] != self.mf[m]:
					return 9
			if issame == 1:
				return 0
			else:
				return 3
						
		elif sign == 1:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if f.mf_wc[ipaddr][m] == 1:
						continue
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9

			for m in match_data_ord:
				if f.mf_wc[m] == 1:
					continue
				elif f.mf[m] != self.mf[m]:
					return 9
			return 1


		elif sign == 2:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1:
						continue
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9

			for m in match_data_ord:
				if self.mf_wc[m] == 1:
					continue
				elif f.mf[m] != self.mf[m]:
					return 9
			return 2

		elif sign == 3:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1 or f.mf_wc[ipaddr][m] == 1:
						continue
					elif  f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9
			for m in match_data_ord:
				if self.mf_wc[m] == 1 or f.mf_wc[m] == 1:
					continue
				elif f.mf[m] != self.mf[m]:
					return 9
			return 3

		elif sign == 4:

			contain = True
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1:
						continue
					if f.mf_wc[ipaddr][m] == 1:
						contain = False
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]: 
						return 9
			for m in match_data_ord:
				if self.mf_wc[m] == 1:
					continue
				if f.mf_wc[m] == 1:
					contain = False
				elif f.mf[m] != self.mf[m]:
					return 9
			if contain == True:
				return 2
			else:
				return 3

			
		elif sign == 5:
			contain = True
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if f.mf_wc[ipaddr][m] == 1:
						continue
					elif self.mf_wc[ipaddr][m] == 1:
						contain = False
					elif f.mf[ipaddr][m] != self.mf[ipaddr][m]:
						return 9
			for m in match_data_ord:
				if f.mf_wc[m] == 1:
					continue
				elif self.mf_wc[m] == 1:
					contain = False
				elif f.mf[m] != self.mf[m]:
					return 9

			if contain == True:
				return 1
			else:
				return 3



class node_range(object):
	"""match fields, switch, actions, and nodes relationships """
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

		self.loaction = 0
		self.level = 0
		self.nodes_id = 0

		self.nodes_down = set()
		self.nodes_up = set()
		self.intersection = set()
		self.coverd = set()
		self.covering = set()

		self.actions = []
		self.active_action = []

	def node_to_string(self):
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
					output = output + " " + m_field + "(%s - %s; %d%d%d%d)," \
					%(array_to_dotted_ip(self.mf_lo_bound[m_field]), array_to_dotted_ip(self.mf_up_bound[m_field]), \
					self.mf_wc[m_field][0], self.mf_wc[m_field][1], self.mf_wc[m_field][2], self.mf_wc[m_field][3])
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

	def location_find(self, cover_graph):		
		self.nodes_down = set()
		self.coverd = set()
		self.nodes_up = set()
		self.covering = set()
		self.intersection = set()	
		temp = set()		
		i = 1	

		for root in cover_graph.lvl_element[0]:
			if self.location == root.location:
				flow_root = root
				break

		# flow_root = cover_graph.lvl_element[0][self.loaction - 1]
		# for f in flow_root.nodes_down:
		# 	temp.add(f)		
		temp = temp | flow_root.nodes_down
		while 1: #find the coverd
			if len(temp) == 0 :
				for node in self.coverd:
					node.covering.add(self)
				cover_graph.lvl_element[self.level].append(self)
				break
			temp_i_lvl = {node for node in temp if node.level == i}
			temp = temp - temp_i_lvl

			if i == self.level: 
				while 1:
					if len(temp_i_lvl) == 0 :

						break
					tempc_i = set()
					for f in temp_i_lvl:
						if f in self.coverd:
							continue
						comp_sign = self.matchfield_comp(f)
						if comp_sign == 1:
							self.nodes_up.add(f)
							self.coverd.add(f)
							self.coverd = self.coverd | f.coverd
							tempc_i = tempc_i | {node for node in f.nodes_down if node.level == i}
							self.nodes_up = self.nodes_up - f.coverd
						elif comp_sign == 0:
							for ac in self.actions:
								f.actions.append(ac)
							print "this is the same"
							return f 
					temp_i_lvl = set()
					tempc_i = tempc_i - self.coverd
					temp_i_lvl = temp_i_lvl | tempc_i

				cover_graph.lvl_element[self.level].append(self)
				for node in self.coverd:
					node.covering.add(self)									
				break
			elif i > self.level: 				
				break

		
			while 1:
				if len(temp_i_lvl) == 0 :
					break
				tempc_i = set()
				for f in temp_i_lvl:
					if f in self.coverd:
						continue
					comp_sign = self.matchfield_comp(f,1)
					if comp_sign == 1:
						self.nodes_up.add(f)
						self.coverd.add(f)
						self.coverd = self.coverd | f.coverd
						tempc_i = tempc_i | {node for node in f.nodes_down if node.level == i}
						self.nodes_up = self.nodes_up - f.coverd
				temp_i_lvl = set()
				tempc_i = tempc_i - self.coverd
				temp_i_lvl = temp_i_lvl | tempc_i
			
			nodes_up_i = {node for node in self.nodes_up if node.level == i}
			for f in nodes_up_i:
				temp = temp | {node for node in f.nodes_down if node.level > i}
			# for f in self.nodes_up:
			# 	if f.level == i:
			# 		temp = temp | f.nodes_down
			i = i + 1


		temp = set()
		i = 100
		if len(self.nodes_up) == 0:
			remove_temp = set()  
			for f in flow_root.nodes_down:
				comp_sign = self.matchfield_comp(f, 4)
				if comp_sign == 2:
					remove_temp.add(f)
					f.nodes_up.remove(flow_root)
					self.nodes_down.add(f)
					f.nodes_up.add(self)			
					# self.end_leaf_sign = False
					self.covering.add(f)
					f.coverd.add(self)
					for node in f.covering:
						node.coverd.add(self)

					self.covering = self.covering | f.covering
					
					# self.nodes_down_upsign = True
				elif comp_sign == 3:
					self.intersection.add(f)
					f.intersection.add(self)	
					for f1 in f.nodes_down:				
						temp.add(f1)
						if f1.level < i:
							i = f1.level					 
			self.nodes_up.add(flow_root)
			flow_root.nodes_down.add(self)
			flow_root.nodes_down = flow_root.nodes_down - remove_temp
		else:
			remove_temp = set()
			for f in self.nodes_up:
				for f1 in f.nodes_down:
					comp_sign = self.matchfield_comp(f1, 4)
					if comp_sign == 2:
						self.nodes_down.add(f1)
						f1.nodes_up.remove(f)
						f1.nodes_up.add(self)
						remove_temp.add(f1)
						self.covering.add(f1)
						self.covering = self.covering | f1.covering
						f1.coverd.add(self)
						for node in f1.covering:
							node.coverd.add(self)
						# self.end_leaf_sign = False
					elif comp_sign == 3:
						self.intersection.add(f1)
						f1.intersection.add(self)
						for f2 in f1.nodes_down:			
							temp.add(f2)							
							if f2.level < i:
								i = f2.level
				f.nodes_down = f.nodes_down - remove_temp		
			for f in self.nodes_up:
				f.nodes_down.add(self)


		while 1:#find the covering
			if len(temp) == 0 :
				break
			temp_i_lvl = {node for node in temp if node.level == i}
			temp = temp - temp_i_lvl

			tempc = set()
			remove_temp = set()
			if i < self.level:
				while 1:
					if len(temp_i_lvl) == 0 :
						break
					tempc_i = set()
					for f in temp_i_lvl:
						if f in self.intersection:
							continue
						comp_sign = self.matchfield_comp(f, 3)
						if comp_sign == 3:
							self.intersection.add(f)
							f.intersection.add(self)
							tempc_i = tempc_i | {node for node in f.nodes_down if node.level == i}
							temp = temp | {node for node in f.nodes_down if node.level > i}

					temp_i_lvl = set()
					temp_i_lvl = temp_i_lvl | tempc_i

			else:
				while 1:
					if len(temp_i_lvl) == 0 :
						break
					tempc_i = set()
					for f in temp_i_lvl:

						if f in self.intersection:
							continue
						if f in self.covering:
							continue
						comp_sign = self.matchfield_comp(f, 4)
						if comp_sign == 2:
							self.nodes_down.add(f)
							self.covering.add(f)
							self.nodes_down = self.nodes_down - f.covering
							self.covering =  self.covering | f.covering
							f.coverd.add(self)
							for node in f.covering:
								node.coverd.add(self)
						if comp_sign == 3:
							self.intersection.add(f)
							f.intersection.add(self)
							tempc_i = tempc_i | {node for node in f.nodes_down if node.level == i}
							temp = temp | {node for node in f.nodes_down if node.level > i}
					temp_i_lvl = set()
					temp_i_lvl = temp_i_lvl | tempc_i
			i = i + 1
		for f in self.nodes_down:
			f.nodes_up.add(self)
		parentsin_cup = set()
		for f in self.nodes_up:
			parentsin_cup = parentsin_cup | f.intersection
		parentsin_cup = parentsin_cup - self.intersection
		parentsin_cup = parentsin_cup - self.coverd
		parentsin_cup = parentsin_cup - self.covering
		parentsin_cup.discard(self)
		for f in parentsin_cup:
			sign = self.matchfield_comp(f, 3)
			if sign == 3:
				self.intersection.add(f)
				f.intersection.add(self)
		return self

	def find_intersection_nomal(self, cover_graph):
		intersection_set = set()
		flowset_all = set()			
		for lvl in cover_graph.lvl_element:
			for f in lvl:
				flowset_all.add(f)
		for f in flowset_all:
			if f.nodes_up != False:
				if f.location == self.location:
					comp_sign = self.matchfield_comp(f, 3)
					# comp_sign = self.matchfield_comp(f, 2)
					# comp_sign2 = self.matchfield_comp(f, 5)
					if comp_sign == 3 :
						intersection_set.add(f)


		return intersection_set

	@staticmethod
	def range_value_comp(a, b):	
		"""-----------------------------------------------------------------
		a = b: 0
		a < b: 1 
		a > b: 2 
		intersection: 3
		other: 9 
		----------------------------------------------------------------"""
		if a[0] <= b[1] and a[1] >= b[0]:
			if a[0] == b[0] and a[1] == b[1]:
				return 0
			elif a[0] >= b[0] and a[1] <= b[1]:
				return 1
			elif a[0] <= b[0] and a[1] >= b[1]:
				return 2
		return 3

	def matchfield_comp(self, f, sign = 0 ):
		"""-----------------------------------------------------------------
		sign = 0 self = f: 0, self < f: 1
		sign = 1 self < f: 1 
		sign = 2 self > f: 2 
		intersection: 3 sign = 3
		sign = 4 intersection & self > f: self > f  2 ;intersection  3 
		sign = 5 intersection & self > f: self < f  1 ;intersection: 3
		other: 9 
		----------------------------------------------------------------"""
		if sign == 0:
			issame = True
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if f.mf_wc[ipaddr][m] == 1:
						if self.mf_wc[ipaddr][m] == 1:
							continue
						else:
							issame = False
							continue
					elif self.mf_wc[ipaddr][m] == 1 or \
						 f.mf_lo_bound[ipaddr][m] > self.mf_lo_bound[ipaddr][m] or \
						 f.mf_up_bound[ipaddr][m] < self.mf_up_bound[ipaddr][m]:
						return 9
					elif f.mf_lo_bound[ipaddr][m] != self.mf_lo_bound[ipaddr][m] or \
						 f.mf_up_bound[ipaddr][m] != self.mf_up_bound[ipaddr][m]:
						issame = False

			for m in match_data_ord:
				if f.mf_wc[m] == 1:
					if self.mf_wc[m] == 1:
						continue
					else:
						issame = False
						continue
				elif self.mf_wc[m] == 1 or \
					 f.mf_lo_bound[m] > self.mf_lo_bound[m] or \
					 f.mf_up_bound[m] < self.mf_up_bound[m]:
					return 9
				elif f.mf_lo_bound[m] != self.mf_lo_bound[m] or \
					 f.mf_up_bound[m] != self.mf_up_bound[m]: 
					issame = False

			if issame == True:
				return 0
			else:
				return 1
						
		elif sign == 1:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if f.mf_wc[ipaddr][m] == 1:
						continue
					elif self.mf_wc[ipaddr][m] == 1 or \
						 f.mf_lo_bound[ipaddr][m] > self.mf_lo_bound[ipaddr][m] or \
						 f.mf_up_bound[ipaddr][m] < self.mf_up_bound[ipaddr][m]:
						return 9

			for m in match_data_ord:
				if f.mf_wc[m] == 1:
					continue
				elif self.mf_wc[m] == 1 or \
					 f.mf_lo_bound[m] > self.mf_lo_bound[m] or \
					 f.mf_up_bound[m] < self.mf_up_bound[m]:
					return 9
			return 1

		elif sign == 2:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1:
						continue
					elif f.mf_wc[ipaddr][m] == 1 or \
						 self.mf_lo_bound[ipaddr][m] > f.mf_lo_bound[ipaddr][m] or \
						 self.mf_up_bound[ipaddr][m] < f.mf_up_bound[ipaddr][m]:
						return 9

			for m in match_data_ord:
				if self.mf_wc[m] == 1:
					continue
				elif f.mf_wc[m] == 1 or \
					 self.mf_lo_bound[m] > f.mf_lo_bound[m] or \
					 self.mf_up_bound[m] < f.mf_up_bound[m]:
					return 9
			return 2

		elif sign == 3:
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1 or f.mf_wc[ipaddr][m] == 1:
						continue
					elif self.mf_lo_bound[ipaddr][m] > f.mf_up_bound[ipaddr][m] or \
						 self.mf_up_bound[ipaddr][m] < f.mf_lo_bound[ipaddr][m]:
						return 9
			for m in match_data_ord:
				if self.mf_wc[m] == 1 or f.mf_wc[m] == 1:
					continue
				elif self.mf_lo_bound[m] > f.mf_up_bound[m] or \
					 self.mf_up_bound[m] < f.mf_lo_bound[m]:
					return 9
			return 3

		elif sign == 4:

			contain = True
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if self.mf_wc[ipaddr][m] == 1:
						continue
					elif f.mf_wc[ipaddr][m] == 1:
						contain = False
						continue
					elif self.mf_lo_bound[ipaddr][m] > f.mf_lo_bound[ipaddr][m] or \
						 self.mf_up_bound[ipaddr][m] < f.mf_up_bound[ipaddr][m]:
						contain = False
						if self.mf_lo_bound[ipaddr][m] > f.mf_up_bound[ipaddr][m] or \
						   self.mf_up_bound[ipaddr][m] < f.mf_lo_bound[ipaddr][m]:
							return 9											
			for m in match_data_ord:
				if self.mf_wc[m] == 1:
					continue
				elif f.mf_wc[m] == 1: 
					contain = False
					continue
				elif self.mf_lo_bound[m] > f.mf_lo_bound[m] or \
					 self.mf_up_bound[m] < f.mf_up_bound[m]:
					contain = False
					if self.mf_lo_bound[m] > f.mf_up_bound[m] or \
					   self.mf_up_bound[m] < f.mf_lo_bound[m]:
						return 9				
			if contain == True:
				return 2
			else:
				return 3
			
		elif sign == 5:
			contain = True
			for ipaddr in match_data_addr:
				for m in [0,1,2,3]:
					if f.mf_wc[ipaddr][m] == 1:
						continue
					elif self.mf_wc[ipaddr][m] == 1:
						contain = False
						continue
					elif f.mf_lo_bound[ipaddr][m] > self.mf_lo_bound[ipaddr][m] or \
						 f.mf_up_bound[ipaddr][m] < self.mf_up_bound[ipaddr][m]:
						contain = False
						if f.mf_lo_bound[ipaddr][m] > self.mf_up_bound[ipaddr][m] or \
						   f.mf_up_bound[ipaddr][m] < self.mf_lo_bound[ipaddr][m]:
							return 9
			for m in match_data_ord:
				if f.mf_wc[m] == 1:
					continue
				elif self.mf_wc[m] == 1:
					contain = False
					continue
				elif f.mf_lo_bound[m] > self.mf_lo_bound[m] or \
					 f.mf_up_bound[m] < self.mf_up_bound[m]:
					contain = False
					if f.mf_lo_bound[m] > self.mf_up_bound[m] or \
					   f.mf_up_bound[m] < self.mf_lo_bound[m]:
						return 9
			if contain == True:
				return 1
			else:
				return 3


class cover_graph(object):
	"""cover_graph structure"""
	def __init__(self, cs_id_list):
		self.lvl_element = []
 		self.lvl_element_init(cs_id_list)

	def lvl_element_init(self, NUM_of_cs):
		len_match_data = len(match_data_ord) + 4 * len(match_data_addr)
		for i in range(0, len_match_data + 1):
			tmp = []
			self.lvl_element.append(tmp)
		for cs_id in range(1, NUM_of_cs + 1):
			self.lvl_element[0].append(node_root(cs_id))
		# print lvl_element
		

class trie_tree(object):
	"""trie_tree structure"""
	def __init__(self):

		self.trie_root = { }
		