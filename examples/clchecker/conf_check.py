

import sys
sys.path.append("..")
from cover_graph import * 
from rules_generator import *
from config_parser.rules_range import *
from config_parser.helper import *
from config_parser.sf_bacebone_rule_genetator import *
from time import time, clock


print "test_compare"
rules = set()
# sf_backbone_ge = sf_backbone('Range_rules')
# sf_backbone_ge = sf_backbone()
# cover_graph_ge = cover_graph(len(sf_backbone_ge.cs_list))  
# for cs in sf_backbone_ge.cs_list:
# 	for rule in sf_backbone_ge.cs_list[cs].rules:  
# 		rules.add(rule)
cover_graph_ge = cover_graph(1)
cover_graph_ge1 = cover_graph(1)
cover_graph_ge2 = cover_graph(1)
trie_tree_ge = trie_tree()
cs = generate_rules('Rand_by_Parameter', 20)
# cs = generate_rules('Fix')
rules = rules | cs.rules
            
rule_len = 0

for rule in rules:
	rule_len = rule_len + 1
	print "---------------------------------------------------"
	print "rule NUM = ", rule_len

	node = rule.node_generate(cover_graph_ge)
	node = rule.node_generate_backup(cover_graph_ge1)
	# node = rule.node_generate_backup2(cover_graph_ge2)
	node = rule.trie_find_intersection(trie_tree_ge.trie_root)
	# if rule_len > 720:
	# 	break
print rule_len
i = 0
for list_cg in cover_graph_ge.lvl_element:
	print "level" + str(i), len(list_cg)
	i = i + 1
print len(cover_graph_ge.lvl_element[0][0].nodes_down)

# rule_len = 0
# for cs in sf_backbone_ge.cs_list:
# 	# rule_len = rule_len + len(sf_backbone_ge.cs_list[cs].rules)

# 	for rule in sf_backbone_ge.cs_list[cs].rules:                      
# 		rule_len = rule_len + 1
# 		print "---------------------------------------------------"
# 		print "rule NUM = ", rule_len



# 		node = rule.node_generate(cover_graph_ge)
# 		node = rule.node_generate_backup(cover_graph_ge1)

# 		node = rule.trie_find_intersection(trie_tree_ge.trie_root)
# print rule_len
# print len(cover_graph_ge.lvl_element[0][0].nodes_down)


		
# en = time()
# print (en - st)	
# for lvl in cover_graph_ge.lvl_element:
# 	print len(lvl)


# for lvl in cover_graph_ge.lvl_element:
# 	for node in lvl:
# 		print node,node.level, node.nodes_down
	



# class conflict_checker(object):
# 	"""docstring for conflict_checker"""
# 	def __init__(self):
# 		super(conflict_checker, self).__init__()
# 		self.arg = arg

# node_ge1 = node_range()
# node_ge1.location = 1
# # node_ge1.mf_wc['tp_dst'] = 0
# # node_ge1.mf_up_bound['tp_dst'] = 65535
# # node_ge1.mf_lo_bound['tp_dst'] = 135
# node_ge1.mf_wc['nw_proto'] = 0
# node_ge1.mf_up_bound['nw_proto'] = 0
# node_ge1.mf_lo_bound['nw_proto'] = 0

# # node_ge1.mf_wc['nw_src'][0] = 0
# node_ge1.mf_lo_bound['nw_src'][0] = 0
# node_ge1.mf_up_bound['nw_src'][0] = 0
# # node_ge1.mf_wc['nw_src'][1] = 0
# node_ge1.mf_lo_bound['nw_src'][1] = 0
# node_ge1.mf_up_bound['nw_src'][1] = 0
# # node_ge1.mf_wc['nw_src'][2] = 0
# node_ge1.mf_lo_bound['nw_src'][2] = 0
# node_ge1.mf_up_bound['nw_src'][2] = 0
# # node_ge1.mf_wc['nw_src'][3] = 0
# node_ge1.mf_lo_bound['nw_src'][3] = 0
# node_ge1.mf_up_bound['nw_src'][3] = 0
# # node_ge1.mf_wc['nw_dst'][0] = 0
# node_ge1.mf_lo_bound['nw_dst'][0] = 0
# node_ge1.mf_up_bound['nw_dst'][0] = 0
# # node_ge1.mf_wc['nw_dst'][1] = 0
# node_ge1.mf_lo_bound['nw_dst'][1] = 0
# node_ge1.mf_up_bound['nw_dst'][1] = 0
# # node_ge1.mf_wc['nw_dst'][2] = 0
# node_ge1.mf_lo_bound['nw_dst'][2] = 0
# node_ge1.mf_up_bound['nw_dst'][2] = 0
# # node_ge1.mf_wc['nw_dst'][3] = 0
# node_ge1.mf_lo_bound['nw_dst'][3] = 0
# node_ge1.mf_up_bound['nw_dst'][3] = 0

# node_ge2 = node_range()
# node_ge2.location = 1
# # node_ge2.mf_wc['tp_dst'] = 0
# # node_ge2.mf_up_bound['tp_dst'] = 65535
# # node_ge2.mf_lo_bound['tp_dst'] = 135
# node_ge2.mf_wc['nw_proto'] = 0
# node_ge2.mf_up_bound['nw_proto'] = 0
# node_ge2.mf_lo_bound['nw_proto'] = 0

# node_ge2.mf_wc['nw_src'][0] = 0
# node_ge2.mf_lo_bound['nw_src'][0] = 171
# node_ge2.mf_up_bound['nw_src'][0] = 171
# node_ge2.mf_wc['nw_src'][1] = 0
# node_ge2.mf_lo_bound['nw_src'][1] = 66
# node_ge2.mf_up_bound['nw_src'][1] = 66
# node_ge2.mf_wc['nw_src'][2] = 0
# node_ge2.mf_lo_bound['nw_src'][2] = 96
# node_ge2.mf_up_bound['nw_src'][2] = 96
# node_ge2.mf_wc['nw_src'][3] = 1
# node_ge2.mf_lo_bound['nw_src'][3] = 0
# node_ge2.mf_up_bound['nw_src'][3] = 0
# # node_ge2.mf_wc['nw_dst'][0] = 0
# node_ge2.mf_lo_bound['nw_dst'][0] = 0
# node_ge2.mf_up_bound['nw_dst'][0] = 0
# # node_ge2.mf_wc['nw_dst'][1] = 0
# node_ge2.mf_lo_bound['nw_dst'][1] = 0
# node_ge2.mf_up_bound['nw_dst'][1] = 0
# # node_ge2.mf_wc['nw_dst'][2] = 0
# node_ge2.mf_lo_bound['nw_dst'][2] = 0
# node_ge2.mf_up_bound['nw_dst'][2] = 0
# # node_ge2.mf_wc['nw_dst'][3] = 0
# node_ge2.mf_lo_bound['nw_dst'][3] = 0
# node_ge2.mf_up_bound['nw_dst'][3] = 0
# print node_ge1.matchfield_comp(node_ge2,2)