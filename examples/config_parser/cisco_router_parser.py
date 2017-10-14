'''
  <Cisco IOS parser>
  

'''



from helper import *
from rules_range import *


class cisco_router(object):
  '''
  Cisco router parser.
  The generated transfer function will have three sub-layers: 
  1) from input port to fwd port: the packet will go through input acl, and vlan untag process
  2) from fwd port to pre-output port: the forwarding table will find output port. but the output
  filter has not been applied yet.
  3) from pre-output port to output port: this is where output acl filter is being done.
  So in order to see the ultimate faith of packet, we need to apply the tf.T() 3 consequative times.
  '''     
  PORT_ID_MULTIPLIER = 1
  INTERMEDIATE_PORT_TYPE_CONST = 1
  OUTPUT_PORT_TYPE_CONST = 2
  PORT_TYPE_MULTIPLIER = 10000
  SWITCH_ID_MULTIPLIER = 100000
  def __init__(self, switch_id):
    '''
    Constructor
    '''
    # for each acl number has a list of acl dictionary entries
    self.acl = {}
    # for each vlan holds the list of ports in its spanning tree
    self.vlan_span_ports = {}
    # forwarding table
    self.fwd_table = []
    # arp table: ip-->(mac,vlan)
    self.arp_table = {}
    #mac table: mac-->ports
    self.mac_table = {}
    # mapping of ACLs to interfaces/vlans access-list# --> (interface, in/out, vlan, file, line)
    self.acl_iface = {}
    # list of vlans configured on this switch, and for each vlan, 
    # the set of access and trunk ports
    self.configed_vlans = {}
    # list of ports configured on this switch
    self.config_ports = set()
    self.rules = []
    
    self.switch_id = switch_id
    self.port_to_id = {}
    self.hs_format = self.HS_FORMAT()
    self.replaced_vlan = None  #(from_vlan,to_vlan)
    self.def_vlan = 1
  def set_default_vlan(self,vlan):
    self.def_vlan = vlan
    
  def set_replaced_vlan(self,rw_vlan):
    self.replaced_vlan = rw_vlan
    
  @staticmethod
  def HS_FORMAT():
    format = {}
    format["vlan_pos"] = 0
    format["ip_src_pos"] = 2
    format["ip_dst_pos"] = 6
    format["ip_proto_pos"] = 10
    format["transport_src_pos"] = 11
    format["transport_dst_pos"] = 13
    format["transport_ctrl_pos"] = 15
    format["vlan_len"] = 2
    format["ip_src_len"] = 4
    format["ip_dst_len"] = 4
    format["ip_proto_len"] = 1
    format["transport_src_len"] = 2
    format["transport_dst_len"] = 2
    format["transport_ctrl_len"] = 1
    format["length"] = 16
    return format
  def set_witch_id(self, switch_id):
    self.switch_id = switch_id
    
  def get_switch_id(self):
    return self.switch_id
  @staticmethod
  def make_acl_dictionary_entry():
    entry = {}
    entry["action"] = True
    entry["src_ip"] = 0
    entry["src_ip_mask"] = 0xffffffff
    entry["dst_ip"] = 0
    entry["dst_ip_mask"] = 0xffffffff
    entry["ip_protocol"] = 0 # Note: this is used instead of any ip protocol
    entry["transport_src_begin"] = 0
    entry["transport_src_end"] = 0xffff
    entry["transport_dst_begin"] = 0
    entry["transport_dst_end"] = 0xffff
    entry["transport_ctrl_begin"] = 0
    entry["transport_ctrl_end"] = 0xff
    return entry

  
  @staticmethod
  def get_protocol_number(proto_name):
    dict = {"ah":51, "eigrp":88, "esp":50, "gre":47, "icmp":1, "igmp":2, \
        "igrp":9, "ip": 0, "ipinip":94, "nos":4, "ospf":89, "tcp":6, \
        "udp":17}
    if proto_name in dict.keys():
      return dict[proto_name]
    else:
      try:
        num = int(proto_name)
        return num
      except Exception as e:
        return None
    
  @staticmethod
  def get_udp_port_number(port_name):
    dict = {"biff": 512, "bootpc":68, "bootps":69, "discard":9, \
        "domain":53, "dnsix":90, "echo":7, "mobile-ip":434, \
        "nameserver":42, "netbios-dgm":137, "netbios-ns":138,\
        "ntp":123, "rip":520, "snmp":161, "snmptrap":162, "sunrpc":111,\
        "syslog":514, "tacacs-ds":49, "talk":517, "tftp":69, "time":37,\
        "who":513, "xdmcp":177}
    if port_name in dict.keys():
      return dict[port_name]
    else:
      try:
        num = int(port_name)
        return num
      except Exception as e:
        return None
    
  @staticmethod
  def get_transport_port_number(port_name):
    dict = {"bgp":179, "chargen":19, "daytime":13, "discard":9, \
        "domain":53, "echo":7, "finger":79, "ftp":21, "ftp-data":20, \
        "gopher":70, "hostname":101, "irc":194, "klogin":543, \
        "kshell":544, "lpd":515, "nntp":119, "pop2":109, "pop3":110, \
        "smtp":25, "sunrpc":111, "syslog":514, "tacacs-ds":65, \
        "talk":517,"telnet":23, "time": 37, "uucp":540, "whois":43, \
        "www":80}
    if port_name in dict.keys():
      return dict[port_name]
    else:
      try:
        num = int(port_name)
        return num
      except Exception as e:
        return None
    
  @staticmethod
  def get_ethernet_port_name(port):
    result = ""
    reminder = ""
    if port.lower().startswith("tengigabitethernet"):
      result = "te"
      reminder = port[len("tengigabitethernet"):]
    elif port.lower().startswith("gigabitethernet"):
      result = "gi"
      reminder = port[len("gigabitethernet"):]
    elif port.lower().startswith("fastethernet"):
      result = "fa"
      reminder = port[len("fastethernet"):]
    else:
      result = port
    return "%s%s"%(result, reminder)

  @staticmethod
  def acl_dictionary_entry_to_rule_range(entry, switch_id):
    rule_ge = rule_range() 
    rule_ge.location = switch_id
    if entry["action"]:
      output = "permit "
      action_ge = action(3) # "permit "    
      rule_ge.actions.append(action_ge)
    else:
      action_ge = action(3)
      action_ge.ACL_state = 0 # "deny " 
    action_ge.priority = 6 #the highest
    rule_ge.mf_wc['nw_proto'] = 0
    rule_ge.mf_lo_bound['nw_proto'] = entry["ip_protocol"]
    rule_ge.mf_up_bound['nw_proto'] = entry["ip_protocol"]
    ip = int_to_arraywc_ip(entry["src_ip"])
    for exp in [3,2,1,0]:
      rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
      rule_ge.mf_lo_bound['nw_src'][exp] = ip['ip'][exp]
      rule_ge.mf_up_bound['nw_src'][exp] = ip['ip'][exp]
    ip = int_to_arraywc_ip(entry["dst_ip"])
    for exp in [3,2,1,0]:
      rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
      rule_ge.mf_lo_bound['nw_dst'][exp] = ip['ip'][exp]
      rule_ge.mf_up_bound['nw_dst'][exp] = ip['ip'][exp]

    # ip = int_to_wc_ip(entry["src_ip"])
    # rule_ge.mf_wc['nw_src'] = ip[0]
    # rule_ge.mf_lo_bound['nw_src'] = ip[1]
    # rule_ge.mf_up_bound['nw_src'] = ip[2]
    # ip = int_to_wc_ip(entry["dst_ip"])
    # rule_ge.mf_wc['nw_dst'] = ip[0]
    # rule_ge.mf_lo_bound['nw_dst'] = ip[1]
    # rule_ge.mf_up_bound['nw_dst'] = ip[2]
    if entry["transport_src_begin"] != 0 or entry["transport_src_end"] != 65535:
      rule_ge.mf_wc['tp_src'] = 0
      rule_ge.mf_lo_bound['tp_src'] = entry["transport_src_begin"]
      rule_ge.mf_up_bound['tp_src'] = entry["transport_src_end"]
    if entry["transport_dst_begin"] != 0 or entry["transport_src_end"] != 65535:
      rule_ge.mf_wc['tp_dst'] = 0
      rule_ge.mf_lo_bound['tp_dst'] = entry["transport_dst_begin"]
      rule_ge.mf_up_bound['tp_dst'] = entry["transport_dst_end"]
    return rule_ge

  @staticmethod
  def mac_in_table_to_int(mac):
    return int(mac.replace('.', ''),16)

  @staticmethod
  def acl_dictionary_entry_to_rule_simple(entry, switch_id):
    rule_ge = rule() 
    rule_ge.location = switch_id
    if entry["action"]:
      output = "permit "
      action_ge = action(3) # "permit "    
      rule_ge.actions.append(action_ge)
    else:
      action_ge = action(3)
      action_ge.ACL_state = 0 # "deny " 
    action_ge.priority = 6 #the highest
    rule_ge.mf_wc['nw_proto'] = 0
    rule_ge.mf['nw_proto'] = entry["ip_protocol"]
    ip = int_to_arraywc_ip(entry["src_ip"])
    for exp in [3,2,1,0]:
      rule_ge.mf_wc['nw_src'][exp] = ip['wc'][exp]
      rule_ge.mf['nw_src'][exp] = ip['ip'][exp]
    ip = int_to_arraywc_ip(entry["dst_ip"])
    for exp in [3,2,1,0]:
      rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
      rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
    if entry["transport_src_begin"] != 0 or entry["transport_src_end"] != 65535:
      rule_ge.mf_wc['tp_src'] = 0
      rule_ge.mf['tp_src'] = entry["transport_src_begin"]
    if entry["transport_dst_begin"] != 0 or entry["transport_src_end"] != 65535:
      rule_ge.mf_wc['tp_dst'] = 0
      rule_ge.mf['tp_dst'] = entry["transport_dst_begin"]
    return rule_ge




  @staticmethod
  def fwd_table_entry_to_rule(entry, switch_id):
    rule_ge = rule() 
    rule_ge.location = switch_id

    rule_ge.mf_wc['nw_proto'] = 0
    rule_ge.mf_only['nw_proto'] = 0
    ip = int_to_wc_ip(entry[0])
    rule_ge.mf_wc['nw_dst'] = ip[0]
    rule_ge.mf_lo_bound['nw_dst'] = ip[1]
    rule_ge.mf_up_bound['nw_dst'] = ip[2]
    return rule_ge


  @staticmethod
  def acl_dictionary_entry_to_string(entry):
    output = ""
    if entry["action"]:
      output = "permit "
    else:
      output = "deny "
    output = output + "ip protocol: %d -- src ip: %s -- src ip mask: \
    %s -- src transport port: %d-%d -- dst ip: %s -- dst ip mask: %s \
    -- dst transport port: %d-%d"%(entry["ip_protocol"],\
    int_to_dotted_ip(entry["src_ip"]),\
    int_to_dotted_ip(entry["src_ip_mask"]),\
    entry["transport_src_begin"],\
    entry["transport_src_end"],
    int_to_dotted_ip(entry["dst_ip"]),\
    int_to_dotted_ip(entry["dst_ip_mask"]),\
    entry["transport_dst_begin"],entry["transport_dst_end"],\
    )
    return output

  def acl_table_to_rule(self):
    for aclnum in self.acl:
      for entry in self.acl[aclnum]:
        acl_rule = self.acl_dictionary_entry_to_rule_simple(entry, self.switch_id)
        self.rules.append(acl_rule)

  def acl_table_to_rule_range(self):
    for aclnum in self.acl:
      for entry in self.acl[aclnum]:
        acl_rule = self.acl_dictionary_entry_to_rule_range(entry, self.switch_id)
        self.rules.append(acl_rule)

  def mac_table_to_rule(self):
    # '''
    # Reads in CISCO mac address table - sh mac-address-table
    # '''
    # print "=== Reading Cisco Mac Address Table File ==="
    for vl_mac in self.mac_table:
      rule_ge = rule()
      rule_ge.location = self.switch_id
      rule_ge.mf_wc['dl_dst'] = 0
      tokens = vl_mac.split(',')
      rule_ge.mf['dl_dst'] = self.mac_in_table_to_int(tokens[1])
      mac = self.mac_in_table_to_int(tokens[1])
      if tokens[0] != 'vlan---':
        rule_ge.mf_wc['dl_vlan'] = 0
        rule_ge.mf['dl_vlan'] = char_to_only_intnum(tokens[0])

      ports_num = []
      for port in self.mac_table[vl_mac]:
        if port == 'Switch':
          ports_num.append(0)
        elif port == 'Router':
          pass
        else:
          port = port.lower()
          ports_num.append(self.port_to_id[port])
      if len(ports_num) > 0:
        action_fw = action(1)
        action_fw.priority = 3
        for port in ports_num:
          action_fw.outport.append(port)
        rule_ge.actions.append(action_fw)
        self.rules.append(rule_ge)

  def mac_table_to_rule_range(self):
    # '''
    # Reads in CISCO mac address table - sh mac-address-table
    # '''
    # print "=== Reading Cisco Mac Address Table File ==="
    for vl_mac in self.mac_table:
      rule_ge = rule_range()
      rule_ge.location = self.switch_id
      rule_ge.mf_wc['dl_dst'] = 0
      tokens = vl_mac.split(',')
      rule_ge.mf_up_bound['dl_dst'] = self.mac_in_table_to_int(tokens[1])
      rule_ge.mf_lo_bound['dl_dst'] = self.mac_in_table_to_int(tokens[1])
      mac = self.mac_in_table_to_int(tokens[1])
      if tokens[0] != 'vlan---':
        rule_ge.mf_wc['dl_vlan'] = 0
        rule_ge.mf_up_bound['dl_vlan'] = char_to_only_intnum(tokens[0])
        rule_ge.mf_lo_bound['dl_vlan'] = char_to_only_intnum(tokens[0])

      ports_num = []
      for port in self.mac_table[vl_mac]:
        if port == 'Switch':
          ports_num.append(0)
        elif port == 'Router':
          pass
        else:
          port = port.lower()
          ports_num.append(self.port_to_id[port])
      if len(ports_num) > 0:
        action_fw = action(1)
        action_fw.priority = 3
        for port in ports_num:
          action_fw.outport.append(port)
        rule_ge.actions.append(action_fw)
        self.rules.append(rule_ge)

  def fwd_table_to_rule(self):
    for entry in self.fwd_table:
      rule_ge = rule() 
      rule_ge.location = self.switch_id
      
      ip = int_to_arraywc_ip(entry[0])
      for exp in [3,2,1,0]:
        rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
        rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
      action_fw = action(1)
      action_fw.priority = 2
      if  entry[2] == 'self':
        action_fw.outport.append(2)
      elif entry[2].startswith('vlan'):
        vlan = char_to_only_charnum(entry[2])
        for token in self.configed_vlans[vlan]:
          for port in self.configed_vlans[vlan][token]:
            port = port.lower()
            port = self.port_to_id[port]
            if port not in action_fw.outport:
              action_fw.outport.append(port)
      else:
        port = entry[2].lower()
        port = port.split('.')
        action_fw.outport.append(self.port_to_id[port[0]])
      rule_ge.actions.append(action_fw)
      self.rules.append(rule_ge)

  def fwd_table_to_rule_range(self):
    for entry in self.fwd_table:
      rule_ge = rule_range() 
      rule_ge.location = self.switch_id
      
      ip = int_to_arraywc_ip(entry[0])
      for exp in [3,2,1,0]:
        rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
        rule_ge.mf_up_bound['nw_dst'][exp] = ip['ip'][exp]
        rule_ge.mf_lo_bound['nw_dst'][exp] = ip['ip'][exp]
      action_fw = action(1)
      action_fw.priority = 2
      if  entry[2] == 'self':
        action_fw.outport.append(2)
      elif entry[2].startswith('vlan'):
        vlan = char_to_only_charnum(entry[2])
        for token in self.configed_vlans[vlan]:
          for port in self.configed_vlans[vlan][token]:
            port = port.lower()
            port = self.port_to_id[port]
            if port not in action_fw.outport:
              action_fw.outport.append(port)
      else:
        port = entry[2].lower()
        port = port.split('.')
        action_fw.outport.append(self.port_to_id[port[0]])
      rule_ge.actions.append(action_fw)
      self.rules.append(rule_ge)

     
  def configed_vlans_to_rule(self):
    for vlan in self.configed_vlans:
      if len(self.configed_vlans[vlan]['access']) > 0:
        for port in self.configed_vlans[vlan]['access']:
          port = port.lower()
          port = self.port_to_id[port]
          rule_ge = rule()
          rule_ge.location = self.switch_id
          rule_ge.mf_wc['inport'] = 0
          rule_ge.mf['inport'] = port
          action_md = action(2)
          action_md.priority = 5
          action_md.modify_MF_sign['dl_vlan'] = 1
          action_md.modify_MF['dl_vlan'] = int(vlan)
          rule_ge.actions.append(action_md)
          self.rules.append(rule_ge)

  def configed_vlans_to_rule_range(self):
    for vlan in self.configed_vlans:
      if len(self.configed_vlans[vlan]['access']) > 0:
        for port in self.configed_vlans[vlan]['access']:
          port = port.lower()
          port = self.port_to_id[port]
          rule_ge = rule_range()
          rule_ge.location = self.switch_id
          rule_ge.mf_wc['inport'] = 0
          rule_ge.mf_up_bound['inport'] = port
          rule_ge.mf_lo_bound['inport'] = port
          action_md = action(2)
          action_md.priority = 5
          action_md.modify_MF_sign['dl_vlan'] = 1
          action_md.modify_MF['dl_vlan'] = int(vlan)
          rule_ge.actions.append(action_md)
          self.rules.append(rule_ge)

  def arp_table_to_rule(self):
    for token in self.arp_table:
      rule_ge = rule() 
      rule_ge.location = self.switch_id
      ip = int_to_arraywc_ip(dotted_ip_to_int(token))
      for exp in [3,2,1,0]:
        rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
        rule_ge.mf['nw_dst'][exp] = ip['ip'][exp]
      action_md = action(2)
      action_md.priority = 4
      action_md.modify_MF_sign['dl_dst'] = 1
      action_md.modify_MF['dl_dst'] = self.mac_in_table_to_int(self.arp_table[token][0])
      rule_ge.actions.append(action_md) 
      if self.arp_table[token][1].startswith('vlan'):
        action_fw = action(1)
        action_fw.priority = 2
        vlan = char_to_only_charnum(self.arp_table[token][1])
        if vlan not in self.configed_vlans:
          continue
        for entry in self.configed_vlans[vlan]:
          for port in self.configed_vlans[vlan][entry]:
            port = port.lower()
            port = self.port_to_id[port]
            if port not in action_fw.outport:
              action_fw.outport.append(port)
        rule_ge.actions.append(action_fw)
      
      self.rules.append(rule_ge)

  def arp_table_to_rule_range(self):
    for token in self.arp_table:
      rule_ge = rule_range() 
      rule_ge.location = self.switch_id
      ip = int_to_arraywc_ip(dotted_ip_to_int(token))
      for exp in [3,2,1,0]:
        rule_ge.mf_wc['nw_dst'][exp] = ip['wc'][exp]
        rule_ge.mf_up_bound['nw_dst'][exp] = ip['ip'][exp]
        rule_ge.mf_lo_bound['nw_dst'][exp] = ip['ip'][exp]
      action_md = action(2)
      action_md.priority = 4
      action_md.modify_MF_sign['dl_dst'] = 1
      action_md.modify_MF['dl_dst'] = self.mac_in_table_to_int(self.arp_table[token][0])
      rule_ge.actions.append(action_md) 
      if self.arp_table[token][1].startswith('vlan'):
        action_fw = action(1)
        action_fw.priority = 2
        vlan = char_to_only_charnum(self.arp_table[token][1])
        if vlan not in self.configed_vlans:
          continue
        for entry in self.configed_vlans[vlan]:
          for port in self.configed_vlans[vlan][entry]:
            port = port.lower()
            port = self.port_to_id[port]
            if port not in action_fw.outport:
              action_fw.outport.append(port)
        rule_ge.actions.append(action_fw)
      
      self.rules.append(rule_ge)

    
  def parse_access_list_entry(self, entry, line_counter):
    
    def parse_ip(lst):
      result = {}
      if lst[0].lower() == "any":
        result["ip"] = 0
        result["ip_mask"] = 0xffffffff
        lst.pop(0)
      elif lst[0].lower() == "host":
        result["ip"] = dotted_ip_to_int(lst[1])
        result["ip_mask"] = 0
        lst.pop(0)
        lst.pop(0)
      elif is_ip_address(lst[0]):
        result["ip"] = dotted_ip_to_int(lst[0])
        if len(lst) > 1 and is_ip_address(lst[1]):
          result["ip_mask"] = dotted_ip_to_int(lst[1])
          lst.pop(0)
          lst.pop(0)
        else:
          result["ip_mask"] = 0
          lst.pop(0)
      return result
    
    def parse_port(lst, proto):
      result = {}
      proto_reader = None
      
      if proto == 6:
        proto_reader = cisco_router.get_transport_port_number
      elif proto == 17:
        proto_reader = cisco_router.get_udp_port_number
      else:
        proto_reader = cisco_router.get_transport_port_number
        
      if lst[0] == "eq":
        lst.pop(0)
        p = proto_reader(lst.pop(0))
        if p != None:
          result["port_begin"] = p
          result["port_end"] = p
      elif lst[0] == "gt":
        lst.pop(0)
        p = proto_reader(lst.pop(0))
        if p != None:
          result["port_begin"] = p + 1
          result["port_end"] = 0xffff
      elif lst[0] == "range":
        lst.pop(0)
        p1 = proto_reader(lst.pop(0))
        p2 = proto_reader(lst.pop(0))
        if p1 != None and p2 != None:
          result["port_begin"] = p1
          result["port_end"] = p2
          
      return result
    
    tokens = entry.split()
    tokens.pop(0)
    acl_number = tokens.pop(0)
    acl_number_int = int(acl_number)
    
    action = tokens.pop(0)
    if action.lower() == "permit" or action.lower() == "deny":
      if not acl_number in self.acl.keys():
        self.acl[acl_number] = []
      
      new_entry = self.make_acl_dictionary_entry()
      new_entry["action"] = (action.lower() == "permit")
      
      # standard access-list entry
      if acl_number_int < 100:
        new_entry["ip_protocol"] = 0
        new_ip = parse_ip(tokens)
        if (len(new_ip.keys()) > 0):
          new_entry["src_ip"] = new_ip["ip"]
          new_entry["src_ip_mask"] = new_ip["ip_mask"]
          self.acl[acl_number].append(new_entry)
          #print self.acl_dictionary_entry_to_string(new_entry)
          return True
        else:
          return False
      
      # extended access-list entry
      else:
        if self.get_protocol_number(tokens[0]) != None:
          new_entry["ip_protocol"] = self.get_protocol_number(\
                    self.get_protocol_number(tokens.pop(0)))
        elif is_ip_address(tokens[0]):
          new_entry["ip_protocol"] = 0
        else:
          return False

        # src ip address and ip mask
        new_ip = parse_ip(tokens)
        if (len(new_ip.keys()) > 0):
          new_entry["src_ip"] = new_ip["ip"]
          new_entry["src_ip_mask"] = new_ip["ip_mask"]

        # src transport port number
        if len(tokens) > 0:
          new_ports = parse_port(tokens, new_entry["ip_protocol"])
          if len(new_ports.keys()) > 0:
            new_entry["transport_src_begin"] = \
                        new_ports["port_begin"]
            new_entry["transport_src_end"] = new_ports["port_end"]
          
        # dst ip address and ip mask  
        if len(tokens) > 0:
          new_ip = parse_ip(tokens)
          if (len(new_ip.keys()) > 0):
            new_entry["dst_ip"] = new_ip["ip"]
            new_entry["dst_ip_mask"] = new_ip["ip_mask"]
            
        # dst transport port number
        if len(tokens) > 0:
          new_ports = parse_port(tokens, new_entry["ip_protocol"])
          if len(new_ports.keys()) > 0:
            new_entry["transport_dst_begin"] = \
                      new_ports["port_begin"]
            new_entry["transport_dst_end"] = new_ports["port_end"]
            
        # transport control bits
        if len(tokens) > 0:
          t = tokens.pop(0)
          if t == "established":
            new_entry["transport_ctrl_begin"] = 0x80
            new_entry["transport_ctrl_end"] = 0xff
            
        new_entry["line"] = [line_counter];
        self.acl[acl_number].append(new_entry)

        # print self.acl_dictionary_entry_to_string(new_entry)
        return True
        
  def parse_interface_config(self,iface_info,file_path):
    def is_in_range(range,val):
      st = range.split("-")
      if len(st) > 1 and int(val) >= int(st[0]) and int(val) <= int(st[1]):
        return True
      elif len(st) == 1 and int(val) == int(st[0]):
        return True
      else:
        return False 
        
    tokens = iface_info[0][0].split()
    iface = cisco_router.get_ethernet_port_name(tokens[1].lower())
    if iface.startswith("vlan"):
      #vlan port 
      vlan = int(iface[4:])
    else:
      parts = re.split('\.',iface)
      if len(parts) > 1:
        #virtual port
        vlan = int(parts[1])
        iface = parts[0]
        if str(vlan) not in self.configed_vlans.keys():
          self.configed_vlans[str(vlan)] = {"access":[],"trunk":[iface]}
        else:
          self.configed_vlans[str(vlan)]["trunk"].append(iface)
        if "vlan%d"%vlan not in self.vlan_span_ports:
          self.vlan_span_ports["vlan%d"%vlan] = [iface]
        elif iface not in self.vlan_span_ports["vlan%d"%vlan]:
          self.vlan_span_ports["vlan%d"%vlan].append(iface)
      else:
        #physical port
        vlan = None
      self.config_ports.add(iface)
        
    shutdown = False
    vlan_ranges = []
    access_vlan = None
    port_mode = None
    for (line,line_counter) in iface_info:
      if line.startswith("shutdown"):
        shutdown = True
      elif line.startswith("switchport mode"):
        tokens = line.split()
        port_mode = tokens[2]
      elif line.startswith("ip access-group"):
        tokens = line.split()
        if not tokens[2] in self.acl_iface.keys():
          self.acl_iface[tokens[2]] = []
        self.acl_iface[tokens[2]].append(\
          (iface,tokens[3],vlan,file_path,[line_counter]))
      elif line.startswith("switchport trunk allowed vlan"):
        tokens = line.split()
        allowed = tokens[-1]
        if allowed.lower() != "none":
          vlan_ranges.extend(allowed.split(","))
      elif line.startswith("switchport access vlan"):
        tokens = line.split()   
        access_vlan = tokens[-1]
        
    if shutdown:
      if vlan != None:
        if str(vlan) in self.configed_vlans:
          self.configed_vlans.pop(str(vlan))
      else:
        self.config_ports.remove(iface)
    elif port_mode == "access" and access_vlan != None:
      self.configed_vlans[access_vlan]["access"].append(iface)
    elif port_mode == "trunk":
      for v in self.configed_vlans.keys():
        for range in vlan_ranges:
          if is_in_range(range,v):
            self.configed_vlans[v]["trunk"].append(iface)
            break
          
  def read_config_file(self, file_path):
    '''
    Reads in the CISCO router config file and extracts access list entries 
    and the ports/vlans they apply to. 
    '''
    print "=== Reading Cisco Router Config File ==="
    f = open(file_path,'r')
    reading_iface = False
    iface_info = []
    line_counter = 0
    for line in f:
      line = line.strip()
      # read an access-list line 
      if line.startswith("access-list"):
        self.parse_access_list_entry(line,line_counter)
      # define a VLAN
      elif line.startswith("vlan"):
        tokens = line.split()
        try:
          vlan = int(tokens[1])
          self.configed_vlans[str(vlan)] = {"access":[],"trunk":[]}
        except Exception as e:
          st = tokens[1].split("-")
          if len(st) > 1:
            try:
              s = int(st[0])
              t = int(st[1])
              for i in range(s,t+1):
                self.configed_vlans[str(i)] = {"access":[],"trunk":[]} 
            except Exception:
              pass
      # read interface config
      elif line.startswith("interface"):
        reading_iface = True
        iface_info = [(line,line_counter)]
      elif reading_iface:
        iface_info.append((line,line_counter))
        if line.startswith("!"):
          reading_iface = False
          self.parse_interface_config(iface_info,file_path)
      line_counter = line_counter + 1
    f.close()
    print "=== DONE Reading Cisco Router Config File ==="
        
  def read_spanning_tree_file(self, file_path):
    '''
    Reads in, the CISCO router "sh spanning-tree" output and extracts the 
    list of ports that are in FWD mode for each vlan.
    '''
    print "=== Reading Cisco Router Spanning Tree File ==="
    current_vlan = 0
    f = open(file_path,'r')
    for line in f:
      tokens = line.split()
      if len(tokens) == 0:
        continue
      if line.startswith("VLAN"):
        if len(tokens) == 1:
          current_vlan = "vlan%d"%int(tokens[0][4:])
          if current_vlan not in self.vlan_span_ports:
            self.vlan_span_ports[current_vlan] = []
      elif (("FWD" in tokens) or ("fwd" in tokens)):
        port = tokens[0].lower()
        if port not in self.vlan_span_ports[current_vlan]:
          self.vlan_span_ports[current_vlan].append(port)
    f.close()
    #print self.vlan_span_ports
    print "=== DONE Reading Cisco Router Spanning Tree File ==="
    
  def read_arp_table_file(self, file_path):
    '''
    Reads in CISCO router arp table - sh arp
    '''
    print "=== Reading Cisco Router ARP Table File ==="
    f = open(file_path,'r')
    for line in f:
      tokens = line.split()
      if (len(tokens) >= 6 and tokens[4].lower() == "arpa"):
        self.arp_table[tokens[1]] = \
        (tokens[3].lower(),tokens[5].lower())
    f.close()
    print "=== DONE Reading Cisco Router ARP Table File ==="
          
  def read_mac_table_file(self, file_path):
    '''
    Reads in CISCO mac address table - sh mac-address-table
    '''
    print "=== Reading Cisco Mac Address Table File ==="
    f = open(file_path,'r')
    seen_star = False
    ports = []
    mac = ""
    for line in f:
      tokens = line.split()
      if (line.startswith("*")):
        if (seen_star):
          self.mac_table[mac] = ports
          ports = []
        mac = "vlan%s,%s"%(tokens[1],tokens[2])
        seen_star = True
        if (len(tokens) >= 7):
          ports.extend(tokens[6].split(","))
      elif (seen_star):
        ports.extend(tokens[0].split(","))
    self.mac_table[mac] = ports
    print "=== DONE Reading Cisco Mac Address Table File ==="
          
  def read_route_file(self, file_path):
    '''
    Reads in the CISCO router "sh ip cef" output and extracts the 
    forwarding table entries.
    '''      
    print "=== Reading Cisco Router IP CEF File ==="
    f = open(file_path,'r')
    port = ""
    line_counter = 0;
    for line in f:
      tokens = line.split()
      if len(tokens) == 0:
        continue
      if is_ip_subnet(tokens[0]):
        ip_subnet = dotted_subnet_to_int(tokens[0])
        if len(tokens) > 2:
          port = cisco_router.get_ethernet_port_name(tokens[2])
          # next hop is a vlan, but also we know the ip adress. 
          # in this case we should find out which vlan port has 
          # that ip address
          if port.lower().startswith("vlan") and \
            is_ip_address(tokens[1]):
            # look up next hop IP address in arp table to find the
            # mac address and output port
            if (tokens[1] in self.arp_table.keys()):
              (mac,vln) = self.arp_table[tokens[1]]
              # if next hop output port is a vlan, look it up in
              # mac table
              if vln.startswith("vlan"):
                vm_key = "%s,%s"%(vln,mac)
                # if mac-address-table for that vlan has the mac
                # address, find out the port
                if vm_key in self.mac_table.keys():
                  resolved_port = self.mac_table[vm_key][0]
                  vlan_num = int(vln[4:])
                  port = "%s.%d"%(\
                              cisco_router.get_ethernet_port_name(resolved_port)\
                              ,vlan_num)
              # if next hop output port is not vlan, use it     
              else:
                port = cisco_router.get_ethernet_port_name(vln)
          # next hop is an attached vlan  
          elif port.lower().startswith("vlan"):
            vlan = int(port[4:])
          else:
            parts = re.split('\.',port)            
            if len(parts) > 1 and self.replaced_vlan != None and int(parts[1]) == self.replaced_vlan[0]:
                port = "%s.%d"%(parts[0],self.replaced_vlan[1])
                vlan = self.replaced_vlan[1]
            elif len(parts) > 1:
              vlan = int(parts[1])
        else:
          port = "self"
          
        if port.lower().startswith("loopback") or \
          port.lower().startswith("null") or \
          tokens[1].lower().startswith("drop"):
          port = "self"

          
        self.fwd_table.append([ip_subnet[0],ip_subnet[1],port.lower(),\
                     file_path,[line_counter]])
      line_counter = line_counter + 1
    f.close()
    #print self.fwd_table
    print "=== DONE Reading Cisco Router IP CEF File ==="

  def generate_port_ids(self, additional_ports):
    '''
    looks at all the ports that has FWD mode for any vlan
    or appear as forwarding port of a forwarding rule, and assign a unique 
    ID to them based on switch_id and a random port id.
    addition_ports will also be considered and assigned a unqie ID. This is 
    for ports that exist on the switch but are not part of any vlan or 
    output of forwarding rules.
    '''
    print "=== Generating port IDs ==="
    s = set(additional_ports)
    for elem in self.config_ports:
      s.add(elem)
    for vlan in self.vlan_span_ports.keys():
      for elem in self.vlan_span_ports[vlan]:
        s.add(elem)
    suffix = 1
    for p in s:
      id = self.switch_id * self.SWITCH_ID_MULTIPLIER + \
        suffix * self.PORT_ID_MULTIPLIER
      self.port_to_id[p] = id
      suffix += 1
    print "=== DONE generating port IDs ==="
    
  def generate_port_ids_only_for_output_ports(self):
    print "=== Generating port IDs ==="
    s = set()
    for fwd_rule in self.fwd_table:
      m = re.split('\.',fwd_rule[2])
      if len(m) > 1:
        s.add(m[0])
      elif fwd_rule[2].startswith('vlan'):
        if fwd_rule[2] in self.vlan_span_ports.keys():
          port_list = self.vlan_span_ports[fwd_rule[2]]
          for p in port_list:
            s.add(p)
      elif fwd_rule[2] != "self":
        s.add(fwd_rule[2])
      suffix = 1
    for p in s:
      id = self.switch_id * self.SWITCH_ID_MULTIPLIER + \
      suffix * self.PORT_ID_MULTIPLIER
      self.port_to_id[p] = id
      suffix += 1
    print "=== DONE generating port IDs ==="
    
  def get_port_id(self,port_name):
    if port_name in self.port_to_id.keys():
      return self.port_to_id[port_name]
    else:
      return None
    
  # def optimize_forwarding_table(self):
  #   print "=== Compressing forwarding table ==="
  #   print " * Originally has %d ip fwd entries * "%len(self.fwd_table)
  #   n = compress_ip_list(self.fwd_table)
  #   print " * After compression has %d ip fwd entries * "%len(n)
  #   self.fwd_table = n
  #   print "=== DONE forwarding table compression ==="