'''
    <Helper functions used in Cisco IOS parser>

@author: Peyman Kazemian
'''



import re
from math import pow

def is_ip_address(str):
    ips = re.match('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', str)
    if ips == None:
        return False
    else:
        return True

def is_ip_subnet(str):
    ips = re.match('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})/(?:[\d]{1,2})', str)
    if ips == None:
        return False
    else:
        return True

def int_to_dotted_ip( intip ):
    octet = ''
    for exp in [3,2,1,0]:
        octet = octet + str(intip / ( 256 ** exp )) + "."
        intip = intip % ( 256 ** exp )
    return(octet.rstrip('.'))

def int_to_array_ip( intip ):
    array_ip = [0,0,0,0]
    for exp in [3,2,1,0]: # the last part is in array_ip[0]
        array_ip[exp] = intip / ( 256 ** exp )
        intip = intip % ( 256 ** exp )
    return array_ip

def array_to_dotted_ip( array_ip ):
    octet = ''
    for exp in [0,1,2,3]: # the last part is in array_ip[3]
        octet = octet + str(array_ip[exp]) + "."
    return(octet.rstrip('.'))

def int_to_arraywc_ip( intip ):
	# wc_ip['ip'][0]: first part.  .  .

	wc_ip = {
	'wc': [1, 1, 1, 1],
	'ip': [0, 0, 0, 0]
	}
	array_ip = int_to_array_ip(intip)
	for exp in [3,2,1,0]:
		wc_ip['ip'][exp] = array_ip[3 - exp]
	if array_ip[0] != 0:
		for exp in [3,2,1,0]:
			wc_ip['wc'][exp] = 0
		return wc_ip
	if array_ip[1] != 0:
		for exp in [2,1,0]:
			wc_ip['wc'][exp] = 0
		return wc_ip
	if array_ip[2] != 0:
		for exp in [1,0]:
			wc_ip['wc'][exp] = 0
		return wc_ip
	if array_ip[3] != 0:
		wc_ip['wc'][0] = 0
		return wc_ip
	return wc_ip

def int_to_wc_ip( intip ):
	# wc_ip[0]: wildcard
	# wc_ip[1]: IP lower bound 
	# wc_ip[2]: IP upper bound 
	wc_ip = [0,0,0]
	array_ip = int_to_array_ip(intip)
	if array_ip[0] != 0:
		wc_ip[1] = intip
		wc_ip[2] = intip	
		return wc_ip
	if array_ip[1] != 0:
		wc_ip[1] = intip
		wc_ip[2] = intip + 255
		return wc_ip
	if array_ip[2] != 0:
		wc_ip[1] = intip
		wc_ip[2] = intip + 256 ** 2 - 1
		return wc_ip
	if array_ip[3] != 0:
		wc_ip[1] = intip
		wc_ip[2] = intip + 256 ** 3 - 1
		return wc_ip
	wc_ip[0] = 1
	return wc_ip
 
def dotted_ip_to_int( dotted_ip ):
    exp = 3
    intip = 0
    for quad in dotted_ip.split('.'):
        intip = intip + (int(quad) * (256 ** exp))
        exp = exp - 1
    return(intip)

def dotted_subnet_to_int( dotted_subnet ):
    exp = 3
    intip = 0
    subnet = 32
    parts = dotted_subnet.split('/')
    if len(parts) > 1:
        try:
            subnet = int(parts[1])
        except Exception:
            pass
    dotted_ip = parts[0]
    for quad in dotted_ip.split('.'):
        intip = intip + (int(quad) * (256 ** exp))
        exp = exp - 1
    return([intip,subnet])

def mac_to_int(mac):
  return int(mac.replace(':', ''),16)

def int_to_mac(intmac):
	hexmac = hex(intmac)
	hexmac = hexmac[2:]
	num = len(hexmac)
	mac = ""
	sign = 0
	# print hexmac
	for token in xrange(0, 12 - len(hexmac)):	
		mac = mac + '0'
		sign = sign + 1
		if sign % 2 == 0:
			mac = mac + ":"
	for token in xrange(0, len(hexmac)):
		mac = mac + hexmac[token]
		sign = sign + 1
		if sign % 2 == 0:
			mac = mac + ":"
	return (mac.rstrip(':'))


def char_to_only_intnum (s):
    fomart = '0123456789'
    for c in s:
        if not c in fomart:
            s = s.replace(c,'');     
    return int(s);

def char_to_only_charnum (s):
    fomart = '0123456789'
    for c in s:
        if not c in fomart:
            s = s.replace(c,'');     
    return s;

    
def l2_proto_to_int(proto):
  if proto == "ip":
    return 0x0800
  elif proto == "arp":
    return 0x0806
  elif proto == "mpls":
    return 0x8847

def find_num_mask_bits_right_mak(mask):
    count = 0
    while (True):
        if (mask & 1 == 1):
            mask = mask >> 1
            count += 1
        else:
            break
    return count

def find_num_mask_bits_left_mak(mask):
    count = 0
    while (True):
        if (mask & 1 == 0):
            mask = mask >> 1
            count += 1
        else:
            break
    return 32-count

