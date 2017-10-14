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
 		'nw_tos'
 		)
match_data_addr = (
		'nw_src',
 		'nw_dst',
 		'dl_src',
 		'dl_dst'
 		)      #前面的IP和MAC地址比对,由于格式的不同
match_data_ord = (
 		'dl_vlan',
 		'dl_vlan_pcp',
 		'tp_src',
 		'tp_dst',
 		# 'dl_type',
 		'nw_tos'
 		) #直接比对内容
link_data = (
 		's_src',
 		'p_src',
 		's_dst',
 		'p_dst'
 		)

class function_r(object):
	"""rule & domain"""
	def __init__(self, ruleblock):
		
		self.domainX_M = [] #main part of domainX, every element is Element entery
		self.domainX_C = [] #complement set & minus part, which is the subset of main part, every element is a set()
		self.domainY_M = [] #main part of domainY, each in set has no intersection part
		self.domainY_C = [] #complement set & minus part, which is the subset of main part, every element is a set()

		self.domainY_1to1 = [] #domainY for every domainX, used to inverse function
		self.M_change = [] #the action part, which loction change when marching domainX
		for x in xrange(1,10):
			#assignment part
			pass

class Element(object):
	"""Element of a block, contain the  match_data & the link, which represent the point in the space"""
	def __init__(self, dl_src = None, dl_dst = None, dl_vlan = None,
				   dl_vlan_pcp = None, dl_type = None, nw_tos = None, nw_proto = None,
				   nw_src = None, nw_dst = None, tp_src = None, tp_dst = None, 
				   s_src = None, p_src = None, s_dst = None,p_dst = None):
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
 		
 		self.Link = {
 		's_src' : s_src,
 		'p_src' : p_src,
 		's_dst' : s_dst,
 		'p_dst' : p_dst,
 		}


class matrix_clc(object):
	"""calculation of spacial connection matrix"""
	def __init__(self, arg):

		super(matrix_clc, self).__init__()
		self.arg = arg

	def Intersection(self, f1, f2): #find the intersection of two Element, result = intersection
		result = Element()
		for l in link_data:
			if f1.link[l] == f2.link[l]:
				result.link[l] = f1.link[l]
			elif f1.link[l] == None:
				result.link[l] = f2.link[l]
			else:
				result.link[l] = f1.link[l]

		for m in match_data_addr:
			if f1.match_data[m].addr == f2.match_data[m].addr:
				result.match_data[m] = f1.match_data[m]
			elif f1.match_data[m] == None:
				result.match_data[m] = f2.match_data[m]
			else:
				result.match_data[m] = f1.match_data[m]

		for m in match_data_ord:
			if f1.match_data[m]== f2.match_data[m]
				result.match_data[m] = f1.match_data[m]
			elif f1.match_data[m] == None:
				result.match_data[m] = f2.match_data[m]
			else:
				result.match_data[m] = f1.match_data[m]

		return result

	def Element_comp(self, f1, f2):
	"""-----------------------------------------------------------------
	find the realation of two elements:
	result = 0: f1 = f2
	result = 1: f1 < f2
	result = 2: f1 > f2
	result = 3: f1 only intersection f2
	result = 9: other: 9 
	----------------------------------------------------------------"""
	

		result = 0
		for l in link_data:
			if f1.link[l] == f2.link[l]:
				continue
			elif f1.link[l] == None:
				if result == 0:
					result = 2
					continue
				elif result == 1:
					result = 3
					continue
				else:
					continue
			elif f2.link[l] == None:
				if result == 0:
					result = 1
					continue
				elif result == 2:
					result = 3
					continue
				else:
					continue
			else:
				result = 9
				return result

		for m in match_data_addr:
			if f1.match_data[m].addr == f2.match_data[m].addr:
				continue
			elif f1.link[m] == None:
				if result == 0:
					result = 2
					continue
				elif result == 1:
					result = 3
					continue
				else:
					continue
			elif f2.link[m] == None:
				if result == 0:
					result = 1
					continue
				elif result == 2:
					result = 3
					continue
				else:
					continue
			else:
				result = 9
				return result
		for m in match_data_ord:
			if f1.match_data[m] == f2.match_data[m]:
				continue
			elif f1.link[m] == None:
				if result == 0:
					result = 2
					continue
				elif result == 1:
					result = 3
					continue
				else:
					continue
			elif f2.link[m] == None:
				if result == 0:
					result = 1
					continue
				elif result == 2:
					result = 3
					continue
				else:
					continue
			else:
				result = 9
				return result
		return result
		
	def dot_multiply(self, r2, r1): 
	"""-----------------------------------------------------------------
	result = r2*r1, r2 operation on r1:

	result = 0: not has connection
	----------------------------------------------------------------"""
		result = function_r()

		for xm2 in r2.domainX_M:
			for ym1 in r21.domainY_M:
				comp_sign = self.Element_comp(xm2, ym1)
				if comp_sign == 9:
					continue
				temp = self.Intersection(xm2, ym1)

				Num_xm2 = r2.domainX_M.index(xm2)

				if r2.domainX_C[Num_xm2] != None:
					for xm2c in r2.domainX_C[Num_xm2]:
						


		


