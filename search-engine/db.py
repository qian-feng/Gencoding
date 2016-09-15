import cPickle as pickle 
from search import *
from nearpy import Engine
from nearpy.hashes import RandomDiscretizedProjections
from nearpy.filters import NearestFilter, UniqueFilter
from nearpy.distances import EuclideanDistance
from nearpy.distances import CosineDistance
from nearpy.hashes import RandomBinaryProjections
from nearpy.experiments import DistanceRatioExperiment
from redis import Redis
from nearpy.storage import RedisStorage
from feature import *
import numpy as np
import os
import pdb
import argparse
import time
import numpy as np
from refactoring import *
import pymongo
from pymongo import MongoClient

def initDB():
	client = MongoClient()
	client = MongoClient('localhost', 27017)
	client = MongoClient('mongodb://localhost:27017/')
	db = client.test_database
	db = client['iot-encoding']
	return db

db = initDB()
posts = db.posts

class db:
	
	def __init__(self):
		self.feature_list = {}
		self.engine = None

	def loadHashmap(self, feature_size, result_n):
		# Create redis storage adapter
		redis_object = Redis(host='localhost', port=6379, db=0)
		redis_storage = RedisStorage(redis_object)
		pdb.set_trace()
		try:
			# Get hash config from redis
			config = redis_storage.load_hash_configuration('test')
			# Config is existing, create hash with None parameters
			lshash = RandomBinaryProjections(None, None)
			# Apply configuration loaded from redis
			lshash.apply_config(config)
			
		except:
			# Config is not existing, create hash from scratch, with 10 projections
			lshash = RandomBinaryProjections('test', 0)
			

		# Create engine for feature space of 100 dimensions and use our hash.
		# This will set the dimension of the lshash only the first time, not when
		# using the configuration loaded from redis. Use redis storage to store
		# buckets.
		nearest = NearestFilter(1000)
		#self.engine = Engine(feature_size, lshashes=[], vector_filters=[])
		pdb.set_trace()
		self.engine = Engine(192, lshashes=[lshash], vector_filters=[nearest], storage=redis_storage, distance=EuclideanDistance())

		# Do some stuff like indexing or querying with the engine...

		# Finally store hash configuration in redis for later use
		redis_storage.store_hash_configuration(lshash)

	def appendToDB(self, binary_name, funcname, fvector, firmware_name=""):
		if fvector is None:
			return
		#ftuple = tuple([fvector])
		self.engine.store_vector(np.asarray(fvector), ".".join((firmware_name,binary_name,funcname)))

	def batch_appendDB(self, binary_name, features, firmware_name=""):
		for funcname in features:
			feature = features[funcname]
			#pdb.set_trace()
			self.appendToDB(binary_name, funcname, feature, firmware_name)

	def batch_appendDBbyDir(self, base_dir):
		cursor = posts.find({"firmware_name":"ddwrt-r21676_result"})
		i = 0
		for v in cursor:
			print i
			i+=1
			binary_name = v['binary_name']
			funcname = v['func_name']
			firmware_name = v['firmware_name']
			feature = v['fvector']
			self.appendToDB(binary_name, funcname, feature, firmware_name)

	def batch_appendDBbyDir1(self, base_dir):
		image_dir = os.path.join(base_dir, "image")
		firmware_featrues={}
		bnum = 0
		fnum = 0
		i  = 0
		pdb.set_trace()
		for firmware_name in os.listdir(image_dir):
			print firmware_name
			firmware_featrues[firmware_name] = {}
			firmware_dir = os.path.join(image_dir, firmware_name)
			for binary_name in os.listdir(firmware_dir):
				if binary_name.endswith(".features"):
					bnum += 1
					featrues_dir = os.path.join(firmware_dir, binary_name)
					featrues = pickle.load(open(featrues_dir, "r"))
					for funcname in featrues:
						fnum +=1
						#pdb.set_trace()
						feature = featrues[funcname]
						self.appendToDB(binary_name, funcname, feature, firmware_name)
					del featrues
		print("bnum ", bnum)
		print("fnum ", fnum)

	def dump(self, base_dir):
		db_dir = os.path.join(base_dir, "data/db/busybox.feature_mapping")
		pickle.dump(self.feature_list, open(db_dir, 'w'))
		db_dir = os.path.join(base_dir, "data/db/busybox.hashmap")
		pickle.dump(self.engine, open(db_dir, 'w'))

	def loadDB(self, base_dir):
		db_dir = os.path.join(base_dir, "data/db/busybox.feature_mapping")
		self.feature_list = pickle.load(open(db_dir, 'r'))
		db_dir = os.path.join(base_dir, "data/db/busybox.hashmap")
		self.engine = pickle.load(open(db_dir, 'r'))

	def findF(self, binary_name, funcname):
		x = [v for v in self.feature_list if binary_name in self.feature_list[v] and funcname in self.feature_list[v][binary_name]]
		return x[0]

def retrieveFeaturesByDir(n, base_dir):
	firmware_featrues={}
	i = 0
	for firmware_name in os.listdir(base_dir):
		if firmware_name.endWith(".features"):
			firmware_featrues[firmware_name] = {}
			firmware_dir = os.path.join(base_dir, firmware_name)
			if i > 0:
				break
			i += 1
			pdb.set_trace()
			for binary_name in os.listdir(firmware_dir):
				featrues_dir = os.path.join(firmware_dir, binary_name + "_cb" + str(n) + ".features")
				featrues = pickle.load(open(featrues_dir, "r"))
				for funcname in featrues:
					feature = featrues[funcname]
					self.appendToDB(firmware_name, binary_name, funcname, feature)
				del featrues

def retrieveFeatures(n, base_dir, filename, funcs):
	feature_dic = {}
	featrues_dir = os.path.join(base_dir, "5000", filename + "_cb" + str(n) + ".features")
	featrues = pickle.load(open(featrues_dir, "r"))
	#featuresx = retrieveFeaturesx(filename)
	for name in featrues:
		#if name in funcs:
		x = featrues[name] 
		#+ featuresx[name]
		feature_dic[name] = np.asarray(x)
	return feature_dic

def retrieveVuldb(base_input_dir):
	vul_path = os.path.join(base_input_dir, "vul")
	vul_db = pickle.load(open(vul_path, "r"))
	return vul_db


def retrieveFeaturesx(filename):
	ida_input_dir = os.path.join("./data/", filename + ".features")
	featuresx = pickle.load(open(ida_input_dir, "r"))
	return featuresx

def retrieveQueries(n, base_dir, filename1, featrues_src):
	queries = {}
	featrues_dir = os.path.join(base_dir, "5000", filename1 + "_cb" + str(n) + ".features")
	featrues = pickle.load(open(featrues_dir, "r"))
	#featuresx = retrieveFeaturesx(filename1)
	for name in featrues:
		#if name in featrues_src:
		x = featrues[name] 
		#+ featuresx[name]
		queries[name] = np.asarray(x)
	return queries

def retrieveQueriesbyDir(n, base_dir, firmware_name, filename1):
	queries = {}
	featrues_dir = os.path.join(base_dir, firmware_name, filename1 + "_cb" + str(n) + ".features")
	featrues = pickle.load(open(featrues_dir, "r"))
	for name in featrues:
		#del featrues[name][5]
		queries[name] = np.asarray(featrues[name])
	return queries

def retrieveQuery(n, base_dir, filename, funcname):
	featrues_dir = os.path.join(base_dir, filename + "_cb" + str(n) + ".features")
	featrues = pickle.load(open(featrues_dir, "r"))
	f = [featrues[v] for v in featrues if funcname in v ][0]
	return np.asarray(f)

def parse_command():
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument("--base_input_dir", type=str, help="raw binaries to process for training")
	parser.add_argument('--output_dir', type=str, help="output dir")
	parser.add_argument("--filename1", type=str, help="the size of each graphlet")
	parser.add_argument("--filename2", type=str, help="the size of each graphlet")
	parser.add_argument("--size", type=int, help="the size of each graphlet")
	#parser.add_argument("--size", type=int, help="the size of each graphlet")
	args = parser.parse_args()
	return args

def loadFuncs(path):
	funcs = {}
	x86_dir = os.path.join(path, "func_candid")
	#mips_dir = os.path.join(path, "openssl1.0.1a_mips.ida")
	fp = open(x86_dir,"r")
	for line in fp:
		items = line.split("\n")
		funcname = items[0]
		funcs[funcname] = 1
	return funcs

def dump(path, featrues, queries):
	fp = open(path + "/" + "matrix", 'w')
	for name in featrues:
		row = []
		row.append("x86")
		row.append(name)
		row += featrues[name]
		fp.write("%s\t%s\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n" %tuple(row))
	for name in queries:
		row = []
		row.append("mips")
		row.append(name)
		row += queries[name]
		fp.write("%s\t%s\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n" % tuple(row))
	fp.close()


def queryBytwo(base_input_dir, filename1, filename2, n):
	threthold = 50
	db_instance = db()
	funcs = loadFuncs(base_input_dir)
	db_instance.loadHashmap(n, 50000)
	#pdb.set_trace()
	featrues = retrieveFeatures(n, base_input_dir, filename1, funcs)
	queries = retrieveQueries(n, base_input_dir, filename2, funcs)
	#queries = refactoring(queries, featrues)
	vul_db = retrieveVuldb(base_input_dir)
	pdb.set_trace()
	#dump(base_input_dir, featrues, queries)
	#start = time.time()
	#db_instance.batch_appendDBbyDir(base_input_dir)
	#end = time.time()
	#total = end - start
	#print total
	db_instance.batch_appendDB(filename1, featrues)
	pdb.set_trace()
	ranks = []
	times = []
	for threthold in xrange(1, 210, 10):
		hit = []
		i = 0
		for name in queries:
			#print i 
			i += 1
			'''
			if i == 1000:
				print (sum(times)/len(times))
				pdb.set_trace()
				print "s"
			'''
			#if name not in vul_db['openssl']:
			#	continue
			if name not in featrues:
				continue
			#pdb.set_trace()
			query = queries[name]
			#start = time.time()
			x = db_instance.engine.neighbours(query)
			#end = time.time()
			#total = end - start
			#times.append(total)
			#print total
			#pdb.set_trace()
			try:
				rank = [v for v in xrange(len(x)) if name in x[v][1]][0]
				ranks.append((name, rank))
				if rank <= threthold:
					hit.append(1)
				else:
					hit.append(0)
			except:
				#pdb.set_trace()
				hit.append(0)
				pass
		#pdb.set_trace()
		acc = sum(hit) * 1.0 / len(hit)
		print acc

def queryAll(base_dir, firmware_name, filename1, n):
	threthold = 155
	db_instance = db()
	db_instance.loadHashmap(n, 50000)
	queries = retrieveQueriesbyDir(n, base_dir, firmware_name, filename1)
	start = time.time()
	pdb.set_trace()
	db_instance.batch_appendDBbyDir(n, base_dir)
	end = time.time()
	dur = end - start
	print dur
	pdb.set_trace()
	hit = []
	i = 0
	times = []
	for name in queries:
		print i 
		i += 1
		query = queries[name]
		start = time.clock()
		x = db_instance.engine.neighbours(query)
		end = time.clock()
		dur = end - start
		times.append(dur)
		#pdb.set_trace()
		try:
			rank = [v for v in xrange(len(x)) if name in x[v][1]]
			if len(rank) > 1:
				pdb.set_trace()
				print "stop"
			if rank[0] <= threthold:
				hit.append(1)
			else:
				hit.append(0)
		except:
			hit.append(0)
	
	acc = sum(hit) * 1.0 / len(hit)
	mean = np.mean(times)
	std =  np.std(times)
	#pdb.set_trace()
	print acc

if __name__ == "__main__":
	args = parse_command()
	base_dir = args.base_input_dir
	filename1 = args.filename1
	filename2 = args.filename2
	n = args.size
	pdb.set_trace()
	queryBytwo(base_dir, filename1, filename2, n)
