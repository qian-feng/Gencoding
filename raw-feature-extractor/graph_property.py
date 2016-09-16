import networkx as nx
import pdb
def betweeness(g):
	#pdb.set_trace()
	betweenness = nx.betweenness_centrality(g)
	return betweenness

def eigenvector(g):
	centrality = nx.eigenvector_centrality(g)
	return centrality

def closeness_centrality(g):
	closeness = nx.closeness_centrality(g)
	return closeness

def retrieveGP(g):
	bf = betweeness(g)
	#close = closeness_centrality(g)
	#bf_sim = 
	#close_sim = 
	x = sorted(bf.values())
	value = sum(x)/len(x)
	return round(value,5)

