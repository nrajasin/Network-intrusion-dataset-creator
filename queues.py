from queue import *

# Should probably be called somehting like packetQ

# capture --> detectors
global sharedQ
sharedQ = Queue()

# detectors --> services
global servicesQ
servicesQ = Queue()

# services --> counts/times
global timesQ
timesQ = Queue()

