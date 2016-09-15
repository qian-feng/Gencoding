import itertools
import sys
sys.path.insert(0, '/usr/local/lib/python2.7/dist-packages/')
import networkx as nx
#import numpy as np
from subprocess import Popen, PIPE
import pdb
import os
import re,mmap
#from graph_edit_new import *

class raw_graph:
	def __init__(self, funcname, g, func_f):
		self.funcname = funcname
		self.old_g = g[0]
		self.g = nx.DiGraph()
		self.entry = g[1]
		self.fun_features = func_f
		self.attributing()

	def __len__(self):
		return len(self.g)

	def attributing(self):
		self.obtainOffsprings(self.old_g)
		for node in self.old_g:
			fvector = self.retrieveVec(node, self.old_g)
			self.g.add_node(node)
			self.g.node[node]['v'] = fvector

		for edge in self.old_g.edges():
			node1 = edge[0]
			node2 = edge[1]
			self.g.add_edge(node1, node2)

	def obtainOffsprings(self,g):
		nodes = g.nodes()
		for node in nodes:
			offsprings = {}
			self.getOffsprings(g, node, offsprings)
			g.node[node]['offs'] = len(offsprings)
		return g

	def getOffsprings(self, g, node, offsprings):
		node_offs = 0
		sucs = g.successors(node)
		for suc in sucs:
			if suc not in offsprings:
				offsprings[suc] = 1
				self.getOffsprings(g, suc, offsprings)

	def retrieveVec(self, id_, g):
		feature_vec = []
		#numC0
		numc = g.node[id_]['consts']
		feature_vec.append(numc)
		#nums1
		nums = g.node[id_]['strings']
		feature_vec.append(nums)
		#offsprings2
		offs = g.node[id_]['offs']
		feature_vec.append(offs)
		#numAs3
		numAs = g.node[id_]['numAs']
		feature_vec.append(numAs)
		# of calls4
		calls = g.node[id_]['numCalls']
		feature_vec.append(calls)
		# of insts5
		insts = g.node[id_]['numIns']
		feature_vec.append(insts)
		# of LIs6
		insts = g.node[id_]['numLIs']
		feature_vec.append(insts)
		# of TIs7
		insts = g.node[id_]['numTIs']
		feature_vec.append(insts)	
		return feature_vec


	def enumerating(self, n):
		subgs = []
		#pdb.set_trace()
		for sub_nodes in itertools.combinations(self.g.nodes(), n):
		    subg = self.g.subgraph(sub_nodes)
		    u_subg = subg.to_undirected()
		    if nx.is_connected(u_subg):
		        subgs.append(subg)
		return subgs


	def genMotifs(self, n):
		motifs = {}
		subgs = enumerating(n)
		for subg in subgs:
			if len(motifs) == 0:
				motifs[subg] = [subg]
			else:
				nomatch = True
				for mt in motifs:
					if nx.is_isomorphic(mt, subg):
						motifs[mt].append(subg)
						nomatch = False
				if nomatch:
					motifs[subg] = [subg]
		return motifs

	def enumerating_efficient(self, n):
		#pdb.set_trace()
		if len(self.g) >= 200:
			return []
		with open('/home/qian/workspace/gEnding/gencoding/encoding/labeled/data/preprocessing/OUTPUT.txt','wb') as f:
			nx.write_edgelist(self.g,f,data=False)
		#pdb.set_trace()
		process = Popen(["/home/qian/workspace/FANMOD-command_line-source/executables/./fanmod_command_line_linux", str(n), "100000", "1", "/home/qian/workspace/gEnding/gencoding/encoding/labeled/data/preprocessing/OUTPUT.txt", "1", "0", "0", "2", "0", "0", "0", "1000", "3", "3", "/home/qian/workspace/gEnding/gencoding/encoding/labeled/data/preprocessing/MotifCount.txt", "0", "1"], stdout=PIPE, stderr=PIPE)
		stdout, stderr = process.communicate()
		if process.returncode >= 0:
		#os.system("/home/qian/software/FANMOD-command_line-source/executables/./fanmod_command_line_linux " +str(n) + " 100000 1 /home/qian/workspace/gEnding/gencoding/encoding/labeled/data/preprocessing/OUTPUT.txt 1 0 0 2 0 0 0 1000 3 3 /home/qian/workspace/gEnding/gencoding/encoding/labeled/data/preprocessing/MotifCount.txt 0 1")
		#pdb.set_trace()
			#pdb.set_trace()
			subgs = self.parseOutput("/home/qian/workspace/gEnding/gencoding/encoding/labeled/data/preprocessing/MotifCount.txt.dump", n)
			#pdb.set_trace()
			os.remove("/home/qian/workspace/gEnding/gencoding/encoding/labeled/data/preprocessing/MotifCount.txt.dump")
			return subgs
		return []

	def parseOutput(self, path, n):
		pattern = re.compile('[0-9]+\,[0-9]+\,[0-9]+\,[0-9]+')
		subgraphs = []
		with open(path,'r') as f:
			data = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
			mo = re.findall(pattern, data)
			if mo:
				results = [map(int, v.split(',')[1:]) for v in mo]
				subgraphs = self.createGraphDirectly(results)
		return subgraphs

	def parseOutputByconditions(self, path, n):
		pattern = re.compile('[0-9]+\,[0-9]+\,[0-9]+\,[0-9]+')
		subgraphs = []
		with open(path,'r') as f:
			data = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
			mo = re.findall(pattern, data)
			if mo:
				results = [map(int, v.split(',')[1:]) for v in mo]
				subgraphs = self.create_Graphbycondition_Directly(results)
		return subgraphs

	def create_Graphbycondition_Directly(self, results):
		subgs = []
		for indexes in results:
			tg = template_graph()
			subg = self.g.subgraph(indexes)
			tg.updateG(subg)
			subgs.append(tg)
			del tg
		return subgs

	def createGraphDirectly(self, results):
		#pdb.set_trace()
		#subgs = [self.g.subgraph(indexes) for indexes in results]
		subgs = []
		for indexes in results:
			tg = template_graph()
			subg = self.g.subgraph(indexes)
			tg.updateG(subg)
			subgs.append(tg)
			del tg
		return subgs

	def createGraph(self, results, n):
		binary_value = int(results[0],2)
		indexes = [int(v) for v in results[1:]]
		fang = self.createG(results[0], n)
		if fang:
			tg = template_graph(binary_value)
			tg.updateG(fang, indexes, self.g)
			return tg
		pdb.set_trace()
		print "there is g which is none"

	def createG(self, binary_str, n):
		g = nx.DiGraph()
		l = [int(v) for v in binary_str]
		#pdb.set_trace()
		shape = (n, n)
		data = np.array(l)
		ad_matrix = data.reshape(shape)
		for i in xrange(n):
			for j in xrange(n):
				if ad_matrix[i][j] == 1:
					g.add_edge(i, j)
		return g
			


class raw_graphs:
	def __init__(self, binary_name):
		self.binary_name = binary_name
		self.raw_graph_list = []

	def append(self, raw_g):
		self.raw_graph_list.append(raw_g)

	def __len__(self):
		return len(self.raw_graph_list)


class graphlets:
	def __init__(self, funcname):
		self.funcname = funcname
		self.graphlets_list = []
		self.binary_name = None

	def updateBN(self, binary_name):
		self.binary_name = binary_name

	def append(self, subg):
		self.graphlets_list.append(subg)

	def appendSet(self, subgs):
		self.graphlets_list += subgs

	def __len__(self):
		return len(self.graphlets_list)

class template_graph:
	def __init__(self, value=None):
		self.value = value
		self.g = None

	def updateG(self,g):
		self.g = g
	#def updateIndexes(self, indexes):
	#	self.indexes = indexes

	#def updateAttributes(self, pg, indexes, maing):
	#	for id_ in xrange(len(indexes)):
	#		index = indexes[id_]
	#		gnode = self.findNode(index, maing)
	#		self.g.node[gnode] = pg.node[index]


class template_graphs:
	def __init__(self, size):
		self.size = size
		self.gs = []
		self.bit_len = None

	def enumeratingAll(self):
		subgs = []
		binary_value = self.genBinValue()
		for i in xrange(binary_value):
			if i == 0 :
				continue
			g = self.createG(i)
			if g:
				tg = template_graph(i)
				tg.updateG(g)
				self.gs.append(tg)

	def genBinValue(self):
		n = self.size
		self.bit_len = n*n
		return 2**(self.bit_len)

	def createG(self, i):
		g = nx.DiGraph()
		l = self.genArray(i)
		#pdb.set_trace()
		shape = (self.size, self.size)
		data = np.array(l)
		ad_matrix = data.reshape(shape)
		for i in xrange(self.size):
			for j in xrange(self.size):
				if ad_matrix[i][j] == 1:
					g.add_edge(i, j)
		u_g = g.to_undirected()
		if len(g) == self.size and nx.is_connected(u_g):
			return g
		return False

	def genArray(self, i):
		l = [int(x) for x in bin(i)[2:]]
		x = [0 for v in xrange(self.bit_len - len(l))]
		return x + l
