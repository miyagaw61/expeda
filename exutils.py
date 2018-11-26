import gdb

import os
import sys
import traceback

EXPEDAPATH = "/home/miyagaw61/src/github.com/miyagaw61_expeda"
sys.path.insert(0, EXPEDAPATH)
sys.path.insert(0, EXPEDAPATH + "/lib")
from peda import PEDA, PEDACmd
import utils
from enert2 import *

p = PEDA()
pc = PEDACmd()

def to_str(s_baby):
    try:
        typ = type(s_baby)
        if typ == str:
            return s_baby
        else:
            return str(s_baby)
    except Exception as e:
        utils.msg("Exception in exutils.to_s(%s): %s" % (s_baby, e), "red")
        traceback.print_exc()
        return False

def to_i(i_baby):
    try:
        typ = type(i_baby)
        if typ == str and len(i_baby) > 1 and i_baby[0:2] == "0x":
            return int(i_baby, 16)
        else:
            return int(i_baby)
    except Exception as e:
        utils.msg("Exception in exutils.to_i(%s): %s" % (i_baby, e), "red")
        traceback.print_exc()
        return False
