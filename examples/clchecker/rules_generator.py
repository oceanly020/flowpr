
import sys
sys.path.append("..")
import random
from cover_graph import *
from config_parser.rules_range import *
from config_parser.helper import *



class generate_rules(object):
	"""docstring for generate_rules"""
	def __init__(self, mode, NUM = 0):
		if mode ==  'Fix':
			self.rules = self.fix_generation()

		elif mode == 'Rand_by_Parameter':
			self.mf = ('dl_src', 'dl_dst', 'dl_vlan', 'dl_vlan_pcp', 'nw_tos', \
				  		'nw_src', 'nw_dst', 'tp_src', 'tp_dst')
			self.switchNUM = 1
			self.num = NUM
			self.lvl_build = self.lvl_element_init() 
			self.rules = self.flow_rand_generation_parameter(NUM = self.num)



	def fix_generation_range(self):
		rules = []
		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.70'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.52'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.5'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.70'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.52'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.52'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rule_ge.mf_wc['tp_src'] = 0
		rule_ge.mf['tp_src'] = 8036
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		rule_ge.mf_wc['tp_src'] = 0
		rule_ge.mf['tp_src'] = 8036
		rules.append(rule_ge)
		return rules

		

	def fix_generation(self):
		rules = []
		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.70'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.52'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.5'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.70'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.52'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.52'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
		rule_ge.mf_wc['tp_src'] = 0
		rule_ge.mf['tp_src'] = 8036
		rules.append(rule_ge)

		rule_ge = rule()
		rule_ge.location = 1
		ip = int_to_arraywc_ip(dotted_ip_to_int('10.0.0.1'))
		for exp in [3,2,1,0]:
			rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
			rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
		rule_ge.mf_wc['tp_src'] = 0
		rule_ge.mf['tp_src'] = 8036
		rules.append(rule_ge)
		return rules

	def lvl_element_init(self):
		lvl_element_temp = []
		len_match_data = len(match_data_ord) + 4 * len(match_data_addr)
		for i in range(0,len_match_data+1):
			tmp = []
			lvl_element_temp .append(tmp)
		lvl_element_temp[0].append('ROOT')
		return lvl_element_temp

	def rule_rand_generation(self, lvl = 1, up_node = "ROOT"): #generate one rule match data randomly based on the level and related up_node
		rule_ge = rule()
		rule_ge.location = 1
		rule_ge.level = lvl
		m = ()
		n = 9
		if up_node == "ROOT":
			sample = random.sample(self.mf,lvl) 
			for m in sample:
				if m == 'nw_src' or m == 'nw_dst':
					for exp in [3,2,1,0]:
						ip = self.match_data_rand(m = m)
			 			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
						rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
				else:
					rule_ge.mf_wc[m] = 0
					rule_ge.mf[m] = self.match_data_rand(m = m)
		else:
			mf_slice = []
			for m in self.mf:
				if m == 'nw_src' or m == 'nw_dst':
					wc_sign = 1
					for exp in [3,2,1,0]:
						if up_node.mf_wc[m][exp] == 0:
							wc_sign = 0
					if wc_sign == 0:
						for exp in [3,2,1,0]:
							rule_ge.mf_wc['nw_dst'][exp] = up_node.mf_wc['nw_dst'][exp]
							rule_ge.mf['nw_dst'][exp] = up_node.mf['nw_dst'][exp]
					else:
						mf_slice.append(m)

				else:
					if up_node.mf_wc[m] == 0:
						rule_ge.mf_wc[m] = up_node.mf_wc[m]
						rule_ge.mf[m] = up_node.mf[m]
					else:
						mf_slice.append(m)
			sample = random.sample(mf_slice, lvl - up_node.level)
			for m in sample:
				if m == 'nw_src' or m == 'nw_dst':
					for exp in [3,2,1,0]:
						ip = self.match_data_rand(m = m)
			 			rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
						rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
				else:
					rule_ge.mf_wc[m] = 0
					rule_ge.mf[m] = self.match_data_rand(m = m)

		rule_ge.actions.append(self.action_rand())
		return rule_ge

	def match_data_rand(self, m = None):
		if m != None:

			if m == 'nw_src' or m == 'nw_dst':
				wc_ip = {
						'wc': [1, 1, 1, 1],
						'ip': [0, 0, 0, 0]
						}
				p = random.randint(1, 4)
				for num in range(0, p):
					wc_ip['wc'][num] = 0
					wc_ip['ip'][num] = random.randint(1, 240)
				match_data = wc_ip

			elif m == 'dl_src' or m == 'dl_dst':
				match_data = random.randint(1, 1000)

			elif m == 'dl_vlan':
				match_data = random.randint(1, 1000)

			elif m == 'tp_src':
				match_data = random.randint(1, 1000)

			elif m == 'tp_dst':
				match_data = random.randint(1, 1000)

			elif m == 'nw_tos':
				match_data = random.randint(1, 1000)

			elif m == 'dl_vlan_pcp':
				match_data = random.randint(1, 1000)

			return match_data

	@staticmethod
	def action_rand(action_name = "ACL"):
		if action_name == "ACL":
			action_ge = action(3)
			p = random.randint(0, 1)
			action_ge.ACL_state = p
			return action_ge

	def flow_rand_generation_parameter(self, NUM = None): # times 100, /100 = NUM, virtual for test
		rules = set()
		rules_NUM = NUM * 100             
		# p_up = 0.75 # probability of relatation to the level(self.level - 1)
		p_up = 0.9
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
						rule = self.rule_rand_generation(lvl = x)
						self.lvl_build[x].append(rule)
						rules.add(rule)
				else:
					num_temp = int(p_up * lvl_NUM_temp)
					lvl_NUM_temp = lvl_NUM_temp - num_temp
					for sign in xrange(0, num_temp):
						p1 = random.randint(0, lvl_NUM[x - 1] - 1)
						rule = self.rule_rand_generation(lvl = x, up_node = self.lvl_build[x - 1][p1])
						self.lvl_build[x].append(rule)
						rules.add(rule)
		return rules