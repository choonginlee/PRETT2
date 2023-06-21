import json
import sys
import os
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
from networkx.algorithms import isomorphism
import matplotlib.pyplot as plt
import glob
import pprint
# import transitions.MarkupMachine as mm


def read_json_file(filename):
	with open(filename) as f:
		js_graph = json.load(f)
		states = js_graph["states"]
		transitions = js_graph["transitions"]
		dg = nx.DiGraph()
		for state in states:
			dg.add_node(state["name"])

		for transition in transitions:
			source = transition["source"]
			dest = transition["dest"]
			trigger = transition["trigger"]
			dg.add_edge(source, dest)
		return dg


if __name__ == "__main__":
	dirpath = sys.argv[1]

	typeno = 1
	isodict = {}

	for jf1 in glob.glob(dirpath+"*/diagram/*(fin*).json"):
		if jf1.find("NG_O_CR_L") > 0 or jf1.find("NG_O_FF_L") > 0: # avoid state explosion
			continue
		print(">>>>>>>>>>>>>"+jf1)
		dg1 = read_json_file(jf1)

		for jf2 in glob.glob(dirpath+"*/diagram/*(fin*).json"):
			if jf2.find("NG_O_CR_L") > 0 or jf2.find("NG_O_FF_L") > 0: # avoid state explosion
				continue
			if jf1 == jf2:
				continue
			else:
				dg2 = read_json_file(jf2)

				index = jf1.find("result")
				l = len("result")+1
				sm_name1 = jf1[index+l:index+l+9]+"_"+str(len(dg1.nodes))
				sm_name2 = jf2[index+l:index+l+9]+"_"+str(len(dg2.nodes))
				# print(sm_name1, sm_name2)
				gm = isomorphism.DiGraphMatcher(dg1, dg2)
				if gm.is_isomorphic():
					is_unique = True
					for key in isodict.keys():
						if sm_name1 in isodict[key] or sm_name2 in isodict[key]:
							is_unique = False
							# print(sm_name1, sm_name2)
							isodict[key].update([sm_name1, sm_name2])
							break
					if is_unique:
						isodict["T-"+str(typeno)] = set([sm_name1])
						typeno += 1
				elif gm.subgraph_is_isomorphic():
					# print(sm_name1, sm_name2)
					has_supergraph = False
					group_supergraph = ""
					for key in isodict.keys():
						if sm_name1 in isodict[key]:
							has_supergraph = True
							group_supergraph = key

					if has_supergraph:
						if group_supergraph+"-sub" in isodict.keys():
							isodict[group_supergraph+"-sub"].update([sm_name2])
						else:
							isodict[group_supergraph+"-sub"] = set([sm_name2])
					else:
						isodict["T-"+str(typeno)] = set([sm_name1])
						isodict["T-"+str(typeno)+"-sub"] = set([sm_name2])
						typeno += 1
				else:
					is_unique = True
					for key in isodict.keys():
						if sm_name1 in isodict[key]:
							is_unique = False
					if is_unique:
						isodict["T-"+str(typeno)] = set([sm_name1])
						typeno += 1

	allset = set([])
	for key in isodict.keys():
		allset.update(isodict[key])

	print(len(allset))

	pprint.pprint(isodict)
				# if gm.subgraph_is_isomorphic():
				# 	# continue
				# 	print("-----ISOMORPHIC------")
				# 	print(jf1, len(dg1.nodes))
				# 	print(jf2, len(dg2.nodes))
				# 	print(gm.mapping)
				# else:
				# 	continue
				# 	print("-----Non-isomorphic------")
				# 	print(jf1, len(dg1.nodes))
				# 	print(jf2, len(dg2.nodes))
				# 	print(gm.mapping)

	# dg1 = read_json_file(file1)
	# dg2 = read_json_file(file2)
	# # pos1=graphviz_layout(dg1, prog='dot')
	# # pos2=graphviz_layout(dg2, prog='dot')

	# # plt.figure(1)
	# # nx.draw(dg1, pos1)
	# # plt.figure(2)
	# # nx.draw(dg2, pos2)
	# # plt.show()

	# gm = isomorphism.DiGraphMatcher(dg1, dg2)
	# print(gm.is_isomorphic())
	# print(gm.mapping)