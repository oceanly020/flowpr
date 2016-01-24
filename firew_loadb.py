


def firewalls():
	flow_preserve = []
	flow_preserve.append(flow(nw_src = IPAddr('10.0.0.1')))
	flow_preserve.append(flow(nw_src = IPAddr('10.0.0.2')))
	flow_preserve.append(flow(nw_src = IPAddr('10.0.0.3')))
	flow_preserve.append(flow(nw_src = IPAddr('10.0.0.4')))
	flow_preserve.append(flow(nw_src = IPAddr('10.0.0.5')))
	firewalls_allow1 = set([1,2,3,4,5])
	flow_preserve[0].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve[1].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve[2].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve[3].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve[4].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve.append(flow(nw_dst = IPAddr('10.0.0.1')))
	flow_preserve.append(flow(nw_dst = IPAddr('10.0.0.2')))
	flow_preserve.append(flow(nw_dst = IPAddr('10.0.0.3')))
	flow_preserve.append(flow(nw_dst = IPAddr('10.0.0.4')))
	flow_preserve.append(flow(nw_dst = IPAddr('10.0.0.5')))
	flow_preserve[5].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve[6].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve[7].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve[8].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))
	flow_preserve[9].actions.append(entry_action_flow_forbidden(allow_set = firewalls_allow1))







def load_balance():
	for x in xrange(1,10):
		pass
	pass