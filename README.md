This project provides two components of Genius, a graph-based bug search framework. The first component is the raw feature extraction. The second is the online bug search engine.

1. The raw feature extraction is designed to achieve following two goals:

	-> Extract the control flow graph for each binary function
	
	-> Extract the attributes for each node in the grap
	
	The feature extraction is built on top of IDA-pro. We wrote the scripts based on ida-python and extract the attributed control flow graph. ``preprocessing_ida.py'' is the main program to extract the ACFG.
	
2. The online bug search engine is used for real-time search:

	-> It utilized localality sensitive hashing for indexing
	
	-> Nearest-neighbor search algorithm for search
	
	The online search is based on nearpy (https://github.com/pixelogik/NearPy). 

