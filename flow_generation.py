




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

def flow_generation(NUM = 10):


	for x in xrange(1, NUM +1):
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
		for m in match_data:

			p = random() % 100
			if p < 50::
				match_data[m] = None
			else:
				if m == 'nw_src':
					p = random() % 240
					p_s = '%d'%p
					tmp = ''.join('10.0.0.', p_s)
					match_data_tmp[m] = tmp

				if m == 'nw_dst':
					p = random() % 240
					p_s = '%d'%p
					tmp = ''.join('10.0.0.', p_s)
					match_data_tmp[m] = tmp
				if m == 'dl_src':
					match_data[m] = None
				if m == 'dl_dst':
					match_data[m] = None
				if m == 'dl_vlan':
					match_data_tmp[m] = random() % 500
				if m == 'dl_vlan_pcp':
					match_data[m] = None
				if m == 'tp_src':
					match_data_tmp[m] = random() % 2000
				if m == 'tp_dst':
					match_data_tmp[m] = random() % 2000
				if m == 'nw_tos':
					match_data[m] = None
