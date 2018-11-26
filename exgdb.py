import os
import sys

import gdb
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
