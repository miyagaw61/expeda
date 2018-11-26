import gdb

import os
import sys

EXPEDAPATH = os.environ["EXPEDAPATH"]
sys.path.insert(0, EXPEDAPATH)
sys.path.insert(0, EXPEDAPATH + "/lib")
from peda import PEDA, PEDACmd
import utils
from enert2 import *

p = PEDA()
pc = PEDACmd()

def fuga(self, *arg):
    """
    FUGAFUGAFUGAFUGA
    Usage:
        MYNAME FUGAFUGA
        MYNAME FUGAFUGAFUGAOHE
    """
    print("fugafugafugafuga")
