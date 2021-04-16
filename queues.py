import multiprocessing as mp


# Should probably be called somehting like packetQ

# capture --> detectors/services
global sharedQ
sharedQ = mp.Queue()

# detectors/services --> counts/times
global timesQ
timesQ = mp.Queue()
