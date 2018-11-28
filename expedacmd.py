import os
import sys
import re
import time

import gdb
from peda import PEDA, PEDACmd, REGISTERS
import utils
import config
from enert2 import *
from enert2.enert2.colorize import *

p = PEDA()
c = PEDACmd()

def ctn(self):
    """
    Continue
    Usage:
        MYNAME
    """
    gdb.execute("continue")

setattr(PEDACmd, "ctn", ctn)
setattr(PEDACmd, "c", ctn)

def brk(self, *arg):
    """
    Set break point
    Usage:
        MYNAME symbol
    """
    (sym, ) = utils.normalize_argv(arg, 1)
    p.set_breakpoint(sym)

setattr(PEDACmd, "brk", brk)
setattr(PEDACmd, "b", brk)

def next(self, *arg):
    """
    Next n times
    Usage:
        MYNAME [n]
    """
    (n, ) = utils.normalize_argv(arg, 1)

    if n == None:
        n = 1
    gdb.execute("nexti " + str(n))

setattr(PEDACmd, "next", next)
setattr(PEDACmd, "n", next)

def step(self, *arg):
    """
    Nexti n times
    Usage:
        MYNAME [n]
    """
    (n, ) = utils.normalize_argv(arg, 1)

    if n == None:
        n = 1
    gdb.execute("stepi " + str(n))

setattr(PEDACmd, "step", step)
setattr(PEDACmd, "s", step)

def afterpc(self, *arg):
    """
    Show n instructions after pc
    Usage:
        MYNAME n
    """
    arch = p.getarch()
    (expr, ) = utils.normalize_argv(arg,1)
    expr = str(expr)
    n = gdb.parse_and_eval(expr)
    if arch[1] == 64:
        ip = "$rip"
    else:
        ip = "$eip"
    p.execute('pdisas %s /%s' % (ip, n))

setattr(PEDACmd, "afterpc", afterpc)
setattr(PEDACmd, "af", afterpc)

def beforepc(self, *arg):
    """
    Show n instructions before pc
    Usage:
        MYNAME n
    """
    arch = p.getarch()
    (expr, ) = utils.normalize_argv(arg,1)
    expr = str(expr)
    n = gdb.parse_and_eval(expr)
    n = utils.to_int(n)
    if arch[1] == 64:
        ip = p.getreg("rip")
    else:
        ip = p.getreg("eip")
    if n == 1:
        p.execute('pdisas %s /%s' % (ip, n))
    else:
        addr = p.prev_inst(ip, n)[1][0]
        p.execute('pdisas %s /%s' % (addr, n))

setattr(PEDACmd, "beforepc", beforepc)
setattr(PEDACmd, "bef", beforepc)

def afteraddr(self, *arg):
    """
    Show n instructions after given addr
    Usage:
        MYNAME addr n
    """
    arch = p.getarch()
    (addr, expr) = utils.normalize_argv(arg,2)
    expr = str(expr)
    n = gdb.parse_and_eval(expr)
    n = utils.to_int(n)
    if arch[1] == 64:
        ip = p.getreg("rip")
    else:
        ip = p.getreg("eip")
    p.execute('pdisas %s /%s' % (addr, n))

setattr(PEDACmd, "afteraddr", afteraddr)
setattr(PEDACmd, "afad", afteraddr)

def beforeaddr(self, *arg):
    """
    Show n instructions after given addr
    Usage:
        MYNAME addr n
    """
    arch = p.getarch()
    (addr, expr) = utils.normalize_argv(arg,2)
    expr = str(expr)
    n = gdb.parse_and_eval(expr)
    n = utils.to_int(n)
    if arch[1] == 64:
        ip = p.getreg("rip")
    else:
        ip = p.getreg("eip")
    if n == 1:
        p.execute('pdisas %s /%s' % (ip, n))
    else:
        addr = p.prev_inst(ip, n)[1][0]
        p.execute('pdisas %s /%s' % (addr, n))

setattr(PEDACmd, "beforeaddr", beforeaddr)
setattr(PEDACmd, "befad", beforeaddr)

def grp(self, *arg):
    """
    Grep command-output
    Usage:
        MYNAME command regexp
    """
    try:
        (cmd, regex) = utils.normalize_argv(arg, 2)
        cmd = str(cmd)
        regex = str(regex)
        output = gdb.execute(cmd, to_string=True)
        regexed = re.findall(regex, output)
        for line in regexed:
            print(line)
    except Exception as e:
        utils.msg("Exception in grp(%s, %s): %s" % (repr(cmd), repr(regex), e), "red")
        traceback.print_exc()
        return False

setattr(PEDACmd, "grp", grp)

def allstack(self):
    """
    Show all stack
    Usage:
        MYNAME
    """
    arch = p.getarch()
    if arch[1] == 64:
        sp = p.getreg("rsp")
        bp = p.getreg("rbp")
    else:
        sp = p.getreg("esp")
        bp = p.getreg("ebp")
    arg = bp - sp
    intsize = p.intsize()
    arg = arg/intsize
    arg += 1
    arg = utils.to_i(arg)
    p.execute("stack %s" % arg)
    return

setattr(PEDACmd, "allstack", allstack)

def lpout(self):
    """
    Execute nexti until loop-end
    Usage:
        MYNAME
    """
    arch = getarch()
    if arch[1] == 64:
        peda.execute("nexti $rcx")
    else:
        peda.execute("nexti $ecx")
    return

setattr(PEDACmd, "lpout", lpout)

def nuntil(self, *arg):
    """
    Execute nexti until regex
    Usage:
        MYNAME regex callonlyflag=False
    """
    (regex, callonlyflag) = utils.normalize_argv(arg, 2)
    regex = str(regex)
    r = re.compile(regex)
    arch = p.getarch()
    ctx = config.Option.get("context")
    config.Option.set("context", "code")
    if callonlyflag == True or callonlyflag == "True":
        cmd = c.nextcall
    else:
        cmd = c.next
    c.next()
    while True:
        (addr, code) = p.current_inst(p.getreg("pc"))
        regexed_code = r.findall(code)
        if len(regexed_code) > 0:
            config.Option.set("context", ctx)
            gdb.execute("context")
            break
        else:
            cmd()

setattr(PEDACmd, "nuntil", nuntil)

def suntil(self, *arg):
    """
    Execute stepi until regex
    Usage:
        MYNAME regex depth=1 callonlyflag=False
    """
    (regex, depth, callonlyflag) = utils.normalize_argv(arg, 3)
    regex = str(regex)
    depth = utils.to_int(depth)
    r = re.compile(regex)
    r_call = re.compile("call")
    r_ret = re.compile("ret")
    if depth == None:
        depth = 1
    now_depth = 0
    if callonlyflag == True or callonlyflag == "True":
        cmd = c.nextcall
    else:
        cmd = c.next
    next_when_call = c.next
    step_when_call = c.step
    arch = p.getarch()
    ctx = config.Option.get("context")
    config.Option.set("context", "code")
    c.step()
    while True:
        (addr, code) = p.current_inst(p.getreg("pc"))
        regexed_code = r.findall(code)
        if len(regexed_code) > 0:
            config.Option.set("context", ctx)
            gdb.execute("context")
            break
        else:
            call_code = r_call.findall(code)
            ret_code = r_ret.findall(code)
            if len(call_code) > 0:
                if now_depth < depth:
                    c.step()
                    now_depth = now_depth + 1
                    continue
            elif len(ret_code) > 0:
                if now_depth <= depth:
                    now_depth = now_depth - 1
                    c.next()
                    continue
            cmd()

setattr(PEDACmd, "suntil", suntil)

def nextcalluntil(self, *arg):
    """
    Execute nextcall until regex
    Usage:
        MYNAME regex
    """
    (regex, ) = utils.normalize_argv(arg, 1)
    regex = str(regex)
    c.nuntil(regex, True)

setattr(PEDACmd, "nextcalluntil", nextcalluntil)

def stepcalluntil(self, *arg):
    """
    Execute stepcall until regex
    Usage:
        MYNAME regex depth=1
    """
    (regex, depth) = utils.normalize_argv(arg, 2)
    regex = str(regex)
    depth = utils.to_int(depth)
    if depth == None:
        depth = 1
    c.suntil(regex, depth, True)

setattr(PEDACmd, "stepcalluntil", stepcalluntil)

def nuntilxor(self):
    """
    Execute nexti until jmp-cmds
    Usage:
        MYNAME
    """
    c.nuntil("xor")

setattr(PEDACmd, "nuntilxor", nuntilxor)

def suntilxor(self, *arg):
    """
    Execute nexti until jmp-cmds
    Usage:
        MYNAME depth=1
    """
    (depth, ) = utils.normalize_argv(arg, 1)
    depth = utils.to_int(depth)
    if depth == None:
        depth = 1
    c.suntil("xor", depth)

setattr(PEDACmd, "suntilxor", suntilxor)

def infonow(self):
    """
    Show detail information of now instruction
    Usage:
        MYNAME
    """
    (addr, code) = p.current_inst(p.getreg("pc"))
    for reg in REGISTERS[8]:
        reg_A = " " + reg
        reg_B = "," + reg
        if reg_A in code or reg_B in code:
            reg = reg.replace(" ", "")
            print(green("%s : " % reg, "bold"), end="")
            c.infox(gdb.parse_and_eval("$%s" % reg))
    for reg in REGISTERS[16]:
        regexed_code = re.findall("[ ,]%s" % reg, code)
        if len(regexed_code) > 0:
            print(green("%s : " % reg, "bold"), end="")
            c.infox(gdb.parse_and_eval("$%s" % reg))
    for i in (32, 64):
        for reg in REGISTERS[i]:
            reg_A = " " + reg
            reg_B = "," + reg
            if reg_A in code or reg_B in code:
                if reg == "r8" or reg == "r9":
                    print(green("%s : " % reg, "bold"), end="")
                else:
                    reg = reg.replace(" ", "")
                    print(green("%s: " % reg, "bold"), end="")
                if reg == "rip":
                    now_code_str = gdb.execute("pdisass $rip /1", to_string=True)
                    print(now_code_str[6:])
                else:
                    c.infox(gdb.parse_and_eval("$%s" % reg))
    regexed_code = re.findall("0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]+", code)
    if len(regexed_code) > 0:
        for addr in regexed_code:
            print(green("%s: " % addr, "bold"), end="")
            c.infox(addr)
    regexed_code = re.findall(r"\[[^ ]*\]", code)
    if len(regexed_code) > 0:
        for addr in regexed_code:
            print(green("%s: " % addr, "bold"), end="")
            for reg in REGISTERS[8]:
                if reg in code:
                    addr = addr.replace(reg, "$" + reg)
            for reg in REGISTERS[16]:
                regexed_code = re.findall("[ ,]%s" % reg, code)
                if len(regexed_code) > 0:
                    addr = addr.replace(reg, "$" + reg)
            for i in (32, 64):
                for reg in REGISTERS[i]:
                    addr = addr.replace(reg, "$" + reg)
            addr = addr.replace("[", "")
            addr = addr.replace("]", "")
            addr = str(gdb.parse_and_eval(addr))
            addr = re.findall("0x[0-9a-f]+", addr)[0] # "0x12341234 <'hogefunction'>" -> "0x12341234"
            c.infox(addr)

setattr(PEDACmd, "infonow", infonow)
setattr(PEDACmd, "inow", infonow)

def infox(self, *arg):
    """
    Customed xinfo command
    Usage:
        MYNAME address
        MYNAME register [reg1 reg2]
    """

    (address, regname) = utils.normalize_argv(arg, 2)
    if address is None:
        self._missing_argument()

    text = ""
    #if not self._is_running():
    if False:
        return

    def get_reg_text(r, v):
        text = green("%s" % r.upper().ljust(3)) + ": "
        chain = p.examine_mem_reference(v)
        text += utils.format_reference_chain(chain)
        text += "\n"
        return text

    (arch, bits) = p.getarch()
    if str(address).startswith("r"):
        # Register
        regs = p.getregs(" ".join(arg[1:]))
        if regname is None:
            for r in REGISTERS[bits]:
                if r in regs:
                    text += get_reg_text(r, regs[r])
        else:
            for (r, v) in sorted(regs.items()):
                text += get_reg_text(r, v)
        if text:
            utils.msg(text.strip())
        if regname is None or "eflags" in regname:
            self.eflags()
        return

    elif utils.to_int(address) is None:
        warning_utils.msg("not a register nor an address")
    else:
        # Address
        chain = p.examine_mem_reference(address)
        #text += '\n'
        #text += 'info: '
        text += utils.format_reference_chain(chain) # + "\n"
        vmrange = p.get_vmrange(address)
        if vmrange:
            (start, end, perm, name) = vmrange
    utils.msg(text)
    return

setattr(PEDACmd, "infox", infox)

def contextmode(self, *arg):
    """
    Set context options
    Usage:
        MYNAME options
    """
    (opt, ) = utils.normalize_argv(arg, 1)
    print(opt)
    if opt == None:
        return
    config.Option.set("context", opt)

setattr(PEDACmd, "contextmode", contextmode)

##def my_normalize_argv(args, size=0):
##    """
##    Normalize argv to list with predefined length
##    """
##    args = list(args)
##    for (idx, val) in enumerate(args):
##        if to_int(val) is not None:
##            args[idx] = utils.to_int(val)
##        if size and idx == size:
##            return args[:idx]
##
##    if size == 0:
##        return args
##    for i in range(len(args), size):
##        args += [None]
##    return args
##
##def str_normalize_argv(args, size=0):
##    """
##    Normalize argv to list with predefined length
##    """
##    args = list(args)
##    for (idx, val) in enumerate(args):
##       if size and idx == size:
##            return args[:idx]
##
##    if size == 0:
##        return args
##    for i in range(len(args), size):
##        args += [None]
##    return args
##
##def flg(self,*arg):
##    """
##    hogehoge
##    """
##    peda.execute('xinfo register eflags')
##    return
##
##def regmake(self, *arg):
##    """
##    Usage: regmake
##    """
##    arch = getarch()
##    os.system('mkdir reg')
##    if(arch == "x86-64"):
##        peda.execute('infox_new register rax')
##        peda.execute('infox_new register rbx')
##        peda.execute('infox_new register rcx')
##        peda.execute('infox_new register rdx')
##        peda.execute('infox_new register rsi')
##        peda.execute('infox_new register rdi')
##        peda.execute('infox_new register rbp')
##        peda.execute('infox_new register rsp')
##        peda.execute('infox_new register rip')
##    else:
##        peda.execute('infox_new register eax')
##        peda.execute('infox_new register ebx')
##        peda.execute('infox_new register ecx')
##        peda.execute('infox_new register edx')
##        peda.execute('infox_new register esi')
##        peda.execute('infox_new register edi')
##        peda.execute('infox_new register ebp')
##        peda.execute('infox_new register esp')
##        peda.execute('infox_new register eip')
##
##def code(self, *arg):
##    """
##    hogehoge
##    """
##    arch = getarch()
##    arg = normalize_argv(arg,2)
##    arg0 = arg[0]
##    arg1 = arg[1]
##    arg1str = str(arg1)
##    if(arch == "x86-64"):
##        ripbk = peda.getreg('rip')
##        peda.execute('set $rip=%d' % arg0)
##        peda.execute('pc %d' % arg1)
##        peda.execute('set $rip=%d' % ripbk)
##    else:
##        eipbk = peda.getreg('eip')
##        peda.execute('set $eip=%d' % arg0)
##        peda.execute('pc %d' % arg1)
##        peda.execute('set $eip=%d' % eipbk)
##    return
##
###def dword(self, *arg):
###    """
###    hogehoge
###    """
###    arg = normalize_argv(arg,2)
###    addr = arg[0]
###    i = arg[1]
###    istr = str(i)
###    i = gdb.parse_and_eval(istr)
###    cnt = 0
###    while(i > 0):
###        peda.execute('infox %d+%d' % (addr,cnt))
###        cnt = cnt + 4
###        i = i - 1
##
###def qword(self, *arg):
###    """
###    hogehoge
###    """
###    arg = normalize_argv(arg,2)
###    addr = arg[0]
###    i = arg[1]
###    istr = str(i)
###    i = gdb.parse_and_eval(istr)
###    cnt = 0
###    while(i > 0):
###        peda.execute('infox %d+%d' % (addr,cnt))
###        cnt = cnt + 8
###        i = i - 1
##
##def regtrace(self, *arg):
##    """
##    Usage: regtrace
##    """
##    arch = getarch()
##    arg = normalize_argv(arg,2)
##    flag = arg[0]
##    file_name = arg[1]
##    if(arch == "x86-64"):
##        prev_rax = open('./reg/rax', 'r').read()
##        prev_rbx = open('./reg/rbx', 'r').read()
##        prev_rcx = open('./reg/rcx', 'r').read()
##        prev_rdx = open('./reg/rdx', 'r').read()
##        prev_rsi = open('./reg/rsi', 'r').read()
##        prev_rdi = open('./reg/rdi', 'r').read()
##        prev_rbp = open('./reg/rbp', 'r').read()
##        prev_rsp = open('./reg/rsp', 'r').read()
##        prev_rip = open('./reg/rip', 'r').read()
##        peda.execute('infox_new register rax')
##        peda.execute('infox_new register rbx')
##        peda.execute('infox_new register rcx')
##        peda.execute('infox_new register rdx')
##        peda.execute('infox_new register rsi')
##        peda.execute('infox_new register rdi')
##        peda.execute('infox_new register rbp')
##        peda.execute('infox_new register rsp')
##        peda.execute('infox_new register rip')
##        rax = open('./reg/rax', 'r').read()
##        rbx = open('./reg/rbx', 'r').read()
##        rcx = open('./reg/rcx', 'r').read()
##        rdx = open('./reg/rdx', 'r').read()
##        rsi = open('./reg/rsi', 'r').read()
##        rdi = open('./reg/rdi', 'r').read()
##        rbp = open('./reg/rbp', 'r').read()
##        rsp = open('./reg/rsp', 'r').read()
##        rip = open('./reg/rip', 'r').read()
##        prev_rip = re.sub(r'\n', '', prev_rip)
##        prev_rip = re.sub(r'.*: ', '', prev_rip)
##        os.system('echo "\n' + prev_rip + '" >> ./reg/regtrace')
##        if(prev_rax != rax):
##            rax = re.sub(r'\n', '', rax)
##            os.system('echo "' + rax + '" >> ./reg/regtrace')
##        if(prev_rbx != rbx):
##            rbx = re.sub(r'\n', '', rbx)
##            os.system('echo "' + rbx + '" >> ./reg/regtrace')
##        if(prev_rcx != rcx):
##            rcx = re.sub(r'\n', '', rcx)
##            os.system('echo "' + rcx + '" >> ./reg/regtrace')
##        if(prev_rdx != rdx):
##            rdx = re.sub(r'\n', '', rdx)
##            os.system('echo "' + rdx + '" >> ./reg/regtrace')
##        if(prev_rsi != rsi):
##            rsi = re.sub(r'\n', '', rsi)
##            os.system('echo "' + rsi + '" >> ./reg/regtrace')
##        if(prev_rdi != rdi):
##            rdi = re.sub(r'\n', '', rdi)
##            os.system('echo "' + rdi + '" >> ./reg/regtrace')
##        if(prev_rbp != rbp):
##            rbp = re.sub(r'\n', '', rbp)
##            os.system('echo "' + rbp + '" >> ./reg/regtrace')
##        if(prev_rsp != rsp):
##            rsp = re.sub(r'\n', '', rsp)
##            os.system('echo "' + rsp + '" >> ./reg/regtrace')
##    else:
##        prev_eax = open('./reg/eax', 'r').read()
##        prev_ebx = open('./reg/ebx', 'r').read()
##        prev_ecx = open('./reg/ecx', 'r').read()
##        prev_edx = open('./reg/edx', 'r').read()
##        prev_esi = open('./reg/esi', 'r').read()
##        prev_edi = open('./reg/edi', 'r').read()
##        prev_ebp = open('./reg/ebp', 'r').read()
##        prev_esp = open('./reg/esp', 'r').read()
##        prev_eip = open('./reg/eip', 'r').read()
##        peda.execute('infox_new register eax')
##        peda.execute('infox_new register ebx')
##        peda.execute('infox_new register ecx')
##        peda.execute('infox_new register edx')
##        peda.execute('infox_new register esi')
##        peda.execute('infox_new register edi')
##        peda.execute('infox_new register ebp')
##        peda.execute('infox_new register esp')
##        peda.execute('infox_new register eip')
##        eax = open('./reg/eax', 'r').read()
##        ebx = open('./reg/ebx', 'r').read()
##        ecx = open('./reg/ecx', 'r').read()
##        edx = open('./reg/edx', 'r').read()
##        esi = open('./reg/esi', 'r').read()
##        edi = open('./reg/edi', 'r').read()
##        ebp = open('./reg/ebp', 'r').read()
##        esp = open('./reg/esp', 'r').read()
##        eip = open('./reg/eip', 'r').read()
##        prev_eip = re.sub(r'\n', '', prev_eip)
##        prev_eip = re.sub(r'.*: ', '', prev_eip)
##        os.system('echo "\n' + prev_eip + '" >> ./reg/regtrace')
##        if(prev_eax != eax):
##            eax = re.sub(r'\n', '', eax)
##            os.system('echo "' + eax + '" >> ./reg/regtrace')
##        if(prev_ebx != ebx):
##            ebx = re.sub(r'\n', '', ebx)
##            os.system('echo "' + ebx + '" >> ./reg/regtrace')
##        if(prev_ecx != ecx):
##            ecx = re.sub(r'\n', '', ecx)
##            os.system('echo "' + ecx + '" >> ./reg/regtrace')
##        if(prev_edx != edx):
##            edx = re.sub(r'\n', '', edx)
##            os.system('echo "' + edx + '" >> ./reg/regtrace')
##        if(prev_esi != esi):
##            esi = re.sub(r'\n', '', esi)
##            os.system('echo "' + esi + '" >> ./reg/regtrace')
##        if(prev_edi != edi):
##            edi = re.sub(r'\n', '', edi)
##            os.system('echo "' + edi + '" >> ./reg/regtrace')
##        if(prev_ebp != ebp):
##            ebp = re.sub(r'\n', '', ebp)
##            os.system('echo "' + ebp + '" >> ./reg/regtrace')
##        if(prev_esp != esp):
##            esp = re.sub(r'\n', '', esp)
##            os.system('echo "' + esp + '" >> ./reg/regtrace')
##    peda.execute('n')
##    
##def infox_new(self, *arg):
##    """
##    Display detail information of address/registers
##    Usage:
##        MYNAME address
##        MYNAME register [reg1 reg2]
##    """
##
##    (address, regname) = normalize_argv(arg, 2)
##    if address is None:
##        self._missing_argument()
##
##    text = ""
##    if not self._is_running():
##        return
##
##    def get_reg_text(r, v):
##        text = green("%s" % r.upper().ljust(3)) + ": "
##        chain = peda.examine_mem_reference(v)
##        text += format_reference_chain(chain)
##        tmp = re.sub(r'\n', '', text)
##        os.system('echo ' + '"' + text + '"' + ' > ./reg/' + regname)
##        return text
##
##    (arch, bits) = peda.getarch()
##    if str(address).startswith("r"):
##        # Register
##        regs = peda.getregs(" ".join(arg[1:]))
##        if regname is None:
##            for r in REGISTERS[bits]:
##                if r in regs:
##                    text += get_reg_text(r, regs[r])
##        else:
##            for (r, v) in sorted(regs.items()):
##                text += get_reg_text(r, v)
##        if text:
##            #msg(text.strip())
##            a = 'a'
##        if regname is None or "eflags" in regname:
##            self.eflags()
##        return
##
##    elif to_int(address) is None:
##        warning_msg("not a register nor an address")
##    else:
##        # Address
##        chain = peda.examine_mem_reference(address, depth=0)
##        text += format_reference_chain(chain) + "\n"
##        vmrange = peda.get_vmrange(address)
##        if vmrange:
##            (start, end, perm, name) = vmrange
##            text += "Virtual memory mapping:\n"
##            text += green("Start : %s\n" % to_address(start))
##            text += green("End   : %s\n" % to_address(end))
##            text += yellow("Offset: 0x%x\n" % (address-start))
##            text += red("Perm  : %s\n" % perm)
##            text += blue("Name  : %s" % name)
##    #msg(text)
##
##    return
##
##def uc(self, *arg):
##    """
##    stop.
##    """
##    if not (os.path.exists("reg")):
##       gdb.execute("regmake") 
##    arch = getarch()
##    argc = len(arg)
##    if(argc == 1):
##        #(arg, ) = normalize_argv(arg,1)
##        arg = arg[0]
##        if(arch == "x86-64"):
##            while(True):
##                peda.execute('nextcall')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg + '.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            while(True):
##                peda.execute('nextcall')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg + '.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    break
##    elif(argc == 2):
##        #(arg1, arg2) = normalize_argv(arg, 2)
##        arg1 = arg[0]
##        arg2 = arg[1]
##        i = 0
##        if(arch == "X86-64"):
##            while(i < arg2):
##                peda.execute('nextcall')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg1 + '.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##        else:
##            while(i < arg2):
##                peda.execute('nextcall')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg1 + '.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##
##def uu(self, *arg):
##    """
##    stop.
##    """
##    if not (os.path.exists("reg")):
##       gdb.execute("regmake") 
##    arch = getarch()
##    argc = len(arg)
##    if(arch == "x86-64"):
##        if(argc == 1):
##            #(arg, ) = normalize_argv(arg,1)
##            arg = arg[0]
##            while(True):
##                peda.execute('ni')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg + '.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        elif(argc == 2):
##            #(arg1, arg2, ) = normalize_argv(arg, 2)
##            arg1 = arg[0]
##            arg2 = arg[1]
##            i = 0
##            while(i < arg2):
##                peda.execute('ni')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg1 + '.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##    else:
##        if(argc == 1):
##            #(arg, ) = normalize_argv(arg,1)
##            arg = arg[0]
##            while(True):
##                peda.execute('ni')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg + '.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        elif(argc == 2):
##            #(arg1, arg2, ) = normalize_argv(arg, 2)
##            arg1 = arg[0]
##            arg2 = arg[1]
##            i = 0
##            while(i < arg2):
##                peda.execute('ni')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg1 + '.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##
##def uui(self, *arg):
##    """
##    stop.
##    """
##    if not (os.path.exists("reg")):
##       gdb.execute("regmake") 
##    arch = getarch()
##    argc = len(arg)
##    if(arch == "x86-64"):
##        if(argc == 1):
##            #(arg, ) = normalize_argv(arg,1)
##            arg = arg[0]
##            while(True):
##                peda.execute('si')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg + '.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        elif(argc == 2):
##            #(arg1, arg2) = normalize_argv(arg, 2)
##            arg1 = arg[0]
##            arg2 = arg[1]
##            i = 0
##            while(i < arg2):
##                peda.execute('ni')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg1 + '.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##    else:
##        if(argc == 1):
##            #(arg, ) = normalize_argv(arg,1)
##            arg = arg[0]
##            while(True):
##                peda.execute('si')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg + '.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        elif(argc == 2):
##            #(arg1, arg2) = normalize_argv(arg, 2)
##            arg1 = arg[0]
##            arg2 = arg[1]
##            i = 0
##            while(i < arg2):
##                peda.execute('ni')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*' + arg1 + '.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##
##def cc(self, *arg):
##    """
##    Usage: cc
##    """
##    if not (os.path.exists("reg")):
##       gdb.execute("regmake") 
##    arch = getarch()
##    argc = len(arg)
##    if(arch == "x86-64"):
##        if(argc != 1):
##            while(True):
##                peda.execute('ni')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*call.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            #(arg1, ) = normalize_argv(arg, 1)
##            arg1 = arg[0]
##            i = 0
##            while(i < arg1):
##                peda.execute('ni')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*call.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##    else:
##        if(argc != 1):
##            while(True):
##                peda.execute('ni')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*call.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            #(arg1, ) = normalize_argv(arg, 1)
##            arg1 = arg[0]
##            i = 0
##            while(i < arg1):
##                peda.execute('ni')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*call.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##
##def cci(self, *arg):
##    """
##    Usage: cc
##    """
##    if not (os.path.exists("reg")):
##       gdb.execute("regmake") 
##    arch = getarch()
##    argc = len(arg)
##    if(arch == "x86-64"):
##        if(argc != 1):
##            while(True):
##                peda.execute('si')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*call.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            #(arg1, ) = normalize_argv(arg, 1)
##            arg1 = arg[0]
##            i = 0
##            while(i < arg1):
##                peda.execute('si')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*call.*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##    else:
##        if(argc != 1):
##            while(True):
##                peda.execute('si')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*call.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            #(arg1, ) = normalize_argv(arg, 1)
##            arg1 = arg[0]
##            i = 0
##            while(i < arg1):
##                peda.execute('si')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*call.*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##
##def jj(self, *arg):
##    """
##    Usage: jj
##    """
##    if not (os.path.exists("reg")):
##       gdb.execute("regmake") 
##    arch = getarch()
##    argc = len(arg)
##    if(arch == "x86-64"):
##        if(argc != 1):
##            while(True):
##                peda.execute('ni')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*(call|jmp|je|jne|jb|ja).*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            #(arg1, ) = normalize_argv(arg, 1)
##            arg1 = arg[0]
##            i = 0
##            while(i < arg1):
##                peda.execute('ni')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*(call|jmp|je|jne|jb|ja).*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##    else:
##        if(argc != 1):
##            while(True):
##                peda.execute('ni')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*(call|jmp|je|jne|jb|ja).*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            #(arg1, ) = normalize_argv(arg, 1)
##            arg1 = arg[0]
##            i = 0
##            while(i < arg1):
##                peda.execute('ni')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*(call|jmp|je|jne|jb|ja).*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##
##def jji(self, *arg):
##    """
##    Usage: jj
##    """
##    if not (os.path.exists("reg")):
##       gdb.execute("regmake") 
##    arch = getarch()
##    argc = len(arg)
##    if(arch == "x86-64"):
##        if(argc != 1):
##            while(True):
##                peda.execute('si')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*(call|jmp|je|jne|jb|ja).*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            #(arg1, ) = normalize_argv(arg, 1)
##            arg1 = arg[0]
##            i = 0
##            while(i < arg1):
##                peda.execute('si')
##                peda.execute('infox_new register rip')
##                rip = open('./reg/rip', 'r').read()
##                callOrJmp = re.sub(r'.*(call|jmp|je|jne|jb|ja).*', '', rip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##    else:
##        if(argc != 1):
##            while(True):
##                peda.execute('si')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*(call|jmp|je|jne|jb|ja).*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    break
##        else:
##            #(arg1, ) = normalize_argv(arg, 1)
##            arg1 = arg[0]
##            i = 0
##            while(i < arg1):
##                peda.execute('si')
##                peda.execute('infox_new register eip')
##                eip = open('./reg/eip', 'r').read()
##                callOrJmp = re.sub(r'.*(call|jmp|je|jne|jb|ja).*', '', eip)
##                if(callOrJmp.find(':') == -1):
##                    i = i + 1
##
##def ii(self, *arg):
##    """
##    Usage: ii
##    """
##    if not (os.path.exists("reg")):
##       gdb.execute("regmake") 
##    arch = getarch()
##    if(arch == "x86-64"):
##        peda.execute('infox_new register rip')
##        nowrip = open('./reg/rip', 'r').read()
##        #beforeRegisterX = re.sub(r'.*(r.x).*.*', '\\1', nowrip)
##        #beforeRegisterP = re.sub(r'.*(r.p).*.*', '\\1', nowrip)
##        #beforeRegisterI = re.sub(r'.*(r.i).*.*', '\\1', nowrip)
##        rax = re.sub(r'.*(rax).*', '\\1', nowrip)
##        rbx = re.sub(r'.*(rbx).*', '\\1', nowrip)
##        rcx = re.sub(r'.*(rcx).*', '\\1', nowrip)
##        rdx = re.sub(r'.*(rdx).*', '\\1', nowrip)
##        rsi = re.sub(r'.*(rsi).*', '\\1', nowrip)
##        rdi = re.sub(r'.*(rdi).*', '\\1', nowrip)
##        rbp = re.sub(r'.*(rbp).*', '\\1', nowrip)
##        rsp = re.sub(r'.*(rsp).*', '\\1', nowrip)
##        rip = re.sub(r'.*(rip).*', '\\1', nowrip)
##        r8 = re.sub(r'.*(r8).*', '\\1', nowrip)
##        r9 = re.sub(r'.*(r9).*', '\\1', nowrip)
##        r10 = re.sub(r'.*(r10).*', '\\1', nowrip)
##        r11 = re.sub(r'.*(r11).*', '\\1', nowrip)
##        r12 = re.sub(r'.*(r12).*', '\\1', nowrip)
##        r13 = re.sub(r'.*(r13).*', '\\1', nowrip)
##        r14 = re.sub(r'.*(r14).*', '\\1', nowrip)
##        r15 = re.sub(r'.*(r15).*', '\\1', nowrip)
##        eax = re.sub(r'.*(eax).*', '\\1', nowrip)
##        ebx = re.sub(r'.*(ebx).*', '\\1', nowrip)
##        ecx = re.sub(r'.*(ecx).*', '\\1', nowrip)
##        edx = re.sub(r'.*(edx).*', '\\1', nowrip)
##        esi = re.sub(r'.*(esi).*', '\\1', nowrip)
##        edi = re.sub(r'.*(edi).*', '\\1', nowrip)
##        ebp = re.sub(r'.*(ebp).*', '\\1', nowrip)
##        esp = re.sub(r'.*(esp).*', '\\1', nowrip)
##        eip = re.sub(r'.*(eip).*', '\\1', nowrip)
##        #afterRegisterX = re.sub(r'.*,.*(r.x).*', '\\1', nowrip)
##        #afterRegisterP = re.sub(r'.*,.*(r.p).*', '\\1', nowrip)
##        #afterRegisterI = re.sub(r'.*,.*(r.i).*', '\\1', nowrip)
##        inregister = re.sub(r'.*(\[.*\]).*', '\\1', nowrip)
##        #registerInregister = re.sub(r'.*\[.*(r..).*\].*', '\\1', nowrip)
##        addr = re.sub(r'.*0x.*(0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]+).*', '\\1', nowrip)
##        if(rax.find(':') == -1):
##            peda.execute('xinfo register ' + rax)
##        if(rbx.find(':') == -1):
##            peda.execute('xinfo register ' + rbx)
##        if(rcx.find(':') == -1):
##            peda.execute('xinfo register ' + rcx)
##        if(rdx.find(':') == -1):
##            peda.execute('xinfo register ' + rdx)
##        if(rsi.find(':') == -1):
##            peda.execute('xinfo register ' + rsi)
##        if(rdi.find(':') == -1):
##            peda.execute('xinfo register ' + rdi)
##        if(rbp.find(':') == -1):
##            peda.execute('xinfo register ' + rbp)
##        if(rsp.find(':') == -1):
##            peda.execute('xinfo register ' + rsp)
##        if(rip.find(':') == -1):
##            peda.execute('xinfo register ' + rip)
##        if(r8.find(':') == -1):
##            peda.execute('xinfo register ' + r8)
##        if(r9.find(':') == -1):
##            peda.execute('xinfo register ' + r9)
##        if(r10.find(':') == -1):
##            peda.execute('xinfo register ' + r10)
##        if(r11.find(':') == -1):
##            peda.execute('xinfo register ' + r11)
##        if(r12.find(':') == -1):
##            peda.execute('xinfo register ' + r12)
##        if(r13.find(':') == -1):
##            peda.execute('xinfo register ' + r13)
##        if(r14.find(':') == -1):
##            peda.execute('xinfo register ' + r14)
##        if(r15.find(':') == -1):
##            peda.execute('xinfo register ' + r15)
##        if(eax.find(':') == -1):
##            peda.execute('xinfo register ' + eax)
##        if(ebx.find(':') == -1):
##            peda.execute('xinfo register ' + ebx)
##        if(ecx.find(':') == -1):
##            peda.execute('xinfo register ' + ecx)
##        if(edx.find(':') == -1):
##            peda.execute('xinfo register ' + edx)
##        if(esi.find(':') == -1):
##            peda.execute('xinfo register ' + esi)
##        if(edi.find(':') == -1):
##            peda.execute('xinfo register ' + edi)
##        if(ebp.find(':') == -1):
##            peda.execute('xinfo register ' + ebp)
##        if(esp.find(':') == -1):
##            peda.execute('xinfo register ' + esp)
##        if(eip.find(':') == -1):
##            peda.execute('xinfo register ' + eip)
##        if(addr.find(':') == -1):
##            peda.execute('infox ' + addr)
##        if(inregister.find(':') == -1):
##            after = re.sub(r'\n', '', inregister)
##            peda.execute("shell echo -n -e '\e[32m" + after + "\e[m: '")
##            after = re.sub(r'\[(r..*)\].*', '$\\1', after)
##            after2 = re.sub(r'\[(e..*)\].*', '$\\1', after)
##            if(len(after) < len(after2)):
##                after = after2
##            peda.execute('infox ' + after)
##        return
##    else:
##        peda.execute('infox_new register eip')
##        noweip = open('./reg/eip', 'r').read()
##        #beforeRegisterX = re.sub(r'.*(e.x).*.*', '\\1', noweip)
##        #beforeRegisterP = re.sub(r'.*(e.p).*.*', '\\1', noweip)
##        #beforeRegisterI = re.sub(r'.*(e.i).*.*', '\\1', noweip)
##        eax = re.sub(r'.*(eax).*', '\\1', noweip)
##        ebx = re.sub(r'.*(ebx).*', '\\1', noweip)
##        ecx = re.sub(r'.*(ecx).*', '\\1', noweip)
##        edx = re.sub(r'.*(edx).*', '\\1', noweip)
##        esi = re.sub(r'.*(esi).*', '\\1', noweip)
##        edi = re.sub(r'.*(edi).*', '\\1', noweip)
##        ebp = re.sub(r'.*(ebp).*', '\\1', noweip)
##        esp = re.sub(r'.*(esp).*', '\\1', noweip)
##        eip = re.sub(r'.*(eip).*', '\\1', noweip)
##        #afterRegisterX = re.sub(r'.*,.*(e.x).*', '\\1', noweip)
##        #afterRegisterP = re.sub(r'.*,.*(e.p).*', '\\1', noweip)
##        #afterRegisterI = re.sub(r'.*,.*(e.i).*', '\\1', noweip)
##        inregister = re.sub(r'.*(\[.*\]).*', '\\1', noweip)
##        #registerInregister = re.sub(r'.*\[.*(e..).*\].*', '\\1', noweip)
##        addr = re.sub(r'.*0x.*(0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]+).*', '\\1', noweip)
##        #if(beforeRegisterX.find(':') == -1):
##        #    peda.execute('xinfo register ' + beforeRegisterX)
##        #if(beforeRegisterP.find(':') == -1):
##        #    peda.execute('xinfo register ' + beforeRegisterP)
##        #if(beforeRegisterI.find(':') == -1):
##        #    peda.execute('xinfo register ' + beforeRegisterI)
##        if(eax.find(':') == -1):
##            peda.execute('xinfo register ' + eax)
##        if(ebx.find(':') == -1):
##            peda.execute('xinfo register ' + ebx)
##        if(ecx.find(':') == -1):
##            peda.execute('xinfo register ' + ecx)
##        if(edx.find(':') == -1):
##            peda.execute('xinfo register ' + edx)
##        if(esi.find(':') == -1):
##            peda.execute('xinfo register ' + esi)
##        if(edi.find(':') == -1):
##            peda.execute('xinfo register ' + edi)
##        if(ebp.find(':') == -1):
##            peda.execute('xinfo register ' + ebp)
##        if(esp.find(':') == -1):
##            peda.execute('xinfo register ' + esp)
##        if(eip.find(':') == -1):
##            peda.execute('xinfo register ' + eip)
##        #if(afterRegisterX.find(':') == -1):
##        #    peda.execute('xinfo register ' + afterRegisterX)
##        #if(afterRegisterP.find(':') == -1):
##        #    peda.execute('xinfo register ' + afterRegisterP)
##        #if(afterRegisterI.find(':') == -1):
##        #    peda.execute('xinfo register ' + afterRegisterI)
##        #if(registerInregister.find(':') == -1):
##        #    peda.execute('xinfo register ' + registerInregister)
##        if(addr.find(':') == -1):
##            peda.execute('infox ' + addr)
##        if(inregister.find(':') == -1):
##            after = re.sub(r'\n', '', inregister)
##            peda.execute("shell echo -n -e '\e[32m" + after + "\e[m: '")
##            after = re.sub(r'\[(e..*)\].*', '$\\1', after)
##            peda.execute('infox ' + after)
##        return
##
##def kdbg(self, *arg):
##    """
##    Usage: kerneldbg [tty]
##    """
##    arg = arg[0]
##    gdb.execute("file vmlinux")
##    gdb.execute("target remote /dev/pts/" + str(arg))
##    return
##
##def dtel(self, *arg):
##    """
##    Display memory content at an address with smart dereferences
##    Usage:
##        MYNAME [linecount] (analyze at current $SP)
##        MYNAME address [linecount]
##    """
##
##    (address, count) = normalize_argv(arg, 2)
##
##    if(1==1):
##        sp = peda.getreg("sp")
##    else:
##        sp = None
##
##    if count is None:
##        count = 8
##        if address is None:
##            address = sp
##        elif address < 0x1000:
##            count = address
##            address = sp
##
##    if not address:
##        return
##
##    step = peda.intsize()*2
##    if not peda.is_address(address): # cannot determine address
##        for i in range(count):
##            if not peda.execute("x/%sx 0x%x" % ("g" if step == 8 else "w", address + i*step)):
##                break
##        return
##
##    result = []
##    for i in range(count):
##        value = address + i*step
##        if peda.is_address(value):
##            result += [peda.examine_mem_reference(value)]
##        else:
##            result += [None]
##    idx = 0
##    text = ""
##    for chain in result:
##        text += "%04d| " % (idx)
##        text += format_reference_chain(chain)
##        text += "\n"
##        idx += step
##
##    pager(text)
##
##    return
##
##def nii(self, *arg):
##    """
##    Usage: ii
##    """
##    gdb.execute("nexti")
##    gdb.execute("ii")
