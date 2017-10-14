


import sys
sys.path.append("..")
from config_parser.cisco_router_parser import *
# from headerspace.tf import *
from time import time, clock

replication_factor = 16
output_dir = "tf_stanford_backbone"
# root_tf_id = 16*replication_factor + 1
# start_ip_subnet = dotted_ip_to_int("171.64.0.0")
# start_ip_mask = 14

st = time()
output_path = "tf_stanford_backbone"
rtr_names = [("bbra_rtr",0),
			# ("bbrb_rtr",0),
			# ("boza_rtr",0),
			# ("bozb_rtr",0),
			# ("coza_rtr",580),
			# ("cozb_rtr",580),
			# ("goza_rtr",0),
			# ("gozb_rtr",0),
			# ("poza_rtr",0),
			# ("pozb_rtr",0),
			# ("roza_rtr",0),
			# ("rozb_rtr",0),
			# ("soza_rtr",580),
			# ("sozb_rtr",580),
			# ("yoza_rtr",0),
			# ("yozb_rtr",0),
			]
topology = [("bbra_rtr","te7/3","goza_rtr","te2/1"),
			("bbra_rtr","te7/3","pozb_rtr","te3/1"),
			("bbra_rtr","te1/3","bozb_rtr","te3/1"),
			("bbra_rtr","te1/3","yozb_rtr","te2/1"),
			("bbra_rtr","te1/3","roza_rtr","te2/1"),
			("bbra_rtr","te1/4","boza_rtr","te2/1"),
			("bbra_rtr","te1/4","rozb_rtr","te3/1"),
			("bbra_rtr","te6/1","gozb_rtr","te3/1"),
			("bbra_rtr","te6/1","cozb_rtr","te3/1"),
			("bbra_rtr","te6/1","poza_rtr","te2/1"),
			("bbra_rtr","te6/1","soza_rtr","te2/1"),
			("bbra_rtr","te7/2","coza_rtr","te2/1"),
			("bbra_rtr","te7/2","sozb_rtr","te3/1"),
			("bbra_rtr","te6/3","yoza_rtr","te1/3"),
			("bbra_rtr","te7/1","bbrb_rtr","te7/1"),
			("bbrb_rtr","te7/4","yoza_rtr","te7/1"),
			("bbrb_rtr","te1/1","goza_rtr","te3/1"),
			("bbrb_rtr","te1/1","pozb_rtr","te2/1"),
			("bbrb_rtr","te6/3","bozb_rtr","te2/1"),
			("bbrb_rtr","te6/3","roza_rtr","te3/1"),
			("bbrb_rtr","te6/3","yozb_rtr","te1/1"),
			("bbrb_rtr","te1/3","boza_rtr","te3/1"),
			("bbrb_rtr","te1/3","rozb_rtr","te2/1"),
			("bbrb_rtr","te7/2","gozb_rtr","te2/1"),
			("bbrb_rtr","te7/2","cozb_rtr","te2/1"),
			("bbrb_rtr","te7/2","poza_rtr","te3/1"),
			("bbrb_rtr","te7/2","soza_rtr","te3/1"),
			("bbrb_rtr","te6/1","coza_rtr","te3/1"),
			("bbrb_rtr","te6/1","sozb_rtr","te2/1"),
			("boza_rtr","te2/3","bozb_rtr","te2/3"),
			("coza_rtr","te2/3","cozb_rtr","te2/3"),
			("goza_rtr","te2/3","gozb_rtr","te2/3"),
			("poza_rtr","te2/3","pozb_rtr","te2/3"),
			("roza_rtr","te2/3","rozb_rtr","te2/3"),
			("soza_rtr","te2/3","sozb_rtr","te2/3"),
			("yoza_rtr","te1/1","yozb_rtr","te1/3"),
			("yoza_rtr","te1/2","yozb_rtr","te1/2"),
			]
id = 1
f = open("%s/port_map_new.txt"%output_dir,'w')
# dummy_cs = cisco_router(1)
cs_list = {}
for (rtr_name,vlan) in rtr_names:

	cs = cisco_router(id)
	# cs.set_replaced_vlan(vlan)
	# tf = TF(cs.HS_FORMAT()["length"]*2)
	# tf.set_prefix_id(rtr_name)
	cs.read_arp_table_file("Stanford_backbone/%s_arp_table.txt"%rtr_name)
	cs.read_mac_table_file("Stanford_backbone/%s_mac_table.txt"%rtr_name)
	cs.read_config_file("Stanford_backbone/%s_config.txt"%rtr_name)
	cs.read_spanning_tree_file("Stanford_backbone/%s_spanning_tree.txt"%rtr_name)
	cs.read_route_file("Stanford_backbone/%s_route.txt"%rtr_name)
	cs.generate_port_ids([])
	# cs.optimize_forwarding_table()
	# cs.generate_transfer_function(tf)
	# tf.save_object_to_file("%s/%s%d.tf"%(output_dir,rtr_name,replicate+1))
	id += 1
	cs_list["%s"%rtr_name] = cs

	# # list of vlans configured on this switch, and for each vlan, 
	# # the set of access and trunk ports
	# print cs.configed_vlans

	# # for each vlan holds the list of ports in its spanning tree
	# print cs.vlan_span_ports

	# # arp table: ip-->(mac,vlan)
	# print cs.arp_table

	# forwarding table
	# print cs.fwd_table
	
	# print cs.port_to_id
	
	# mac table: mac-->ports
	# print cs.mac_table
	# mapping of ACLs to interfaces/vlans access-list# --> (interface, in/out, vlan, file, line)
	# print cs.acl_iface
	# for key in cs.acl_iface
	# 	for aclnum in cs.acl:	


	# for aclnum in cs.acl:
	# 	for entry in cs.acl[aclnum]:

	# 		acl_rule = cs.acl_dictionary_entry_to_rule_simple(entry, cs.switch_id)
	# 		print acl_rule.rule_to_string()
			
	# 		print cs.acl_dictionary_entry_to_string(entry)

	# cs.configed_vlans_to_rule()
	# cs.mac_table_to_rule()
	# cs.fwd_table_to_rule()
	# cs.arp_table_to_rule()
	cs.acl_table_to_rule()
	for entry in cs.rules:
		print entry.rule_to_string()

# ttf = TF(dummy_cs.HS_FORMAT()["length"]*2)
# ttf.set_prefix_id("topology")
# root_tf = TF(dummy_cs.HS_FORMAT()["length"]*2)
# root_tf.set_prefix_id("root_rtr")
# root_tf_ports = []
# for rtr in cs_list.keys():
# 	cs = cs_list[rtr]
# 	f.write("$%s\n"%rtr)
# 	for p in cs.port_to_id.keys():
# 		f.write("%s:%s\n"%(p,cs.port_to_id[p]))
f.close()