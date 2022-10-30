import multiprocessing as mp

# These are in globaly shared memory that probably only works with fork

# Should probably be called somehting like packetQ
# capture --> detectors/services
global sharedQ
sharedQ = mp.Queue()

# detectors --> services
global serviceQ
serviceQ = mp.Queue()

# services --> counts/times
global timesQ
timesQ = mp.Queue()
