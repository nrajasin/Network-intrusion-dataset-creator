from queue import *

# Should probably be called somehting like packetQ

# capture --> detectors/services
global sharedQ
sharedQ = Queue()

# detectors/services --> counts/times
global timesQ
timesQ = Queue()
