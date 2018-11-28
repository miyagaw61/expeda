expeda
======

EXPEDA - Extended PEDA

## New Key Features:

* `ctn, c` -- Execute continue command
* `brk, b` -- Execute break command
* `next, n` -- Execute nexti command
* `step, s` -- Execute stepi command
* `afterpc, af` -- Show instructions after now program-counter
* `beforepc, bef` -- Show instructions before now program-counter
* `grp` -- Grep strings
* `allstack` -- Show all stack data
* `nuntil` -- Execute nexti command until given regexp
* `suntil` -- Execute stepi command until given regexp
* `nextcalluntil` -- Execute nextcall command until given regexp
* `stepcalluntil` -- Execute nextcall and step command until given regexp and given depth
* `infonow, inow` -- Show detail information of the instruction now specified program-counter
* `infox` -- Customed xinfo command
* `contextmode` -- Set context mode
* ... and all commands of peda.

## Usage as a library:

    $ cat gdbrc.py
    p = PEDA()
    c = PEDACmd()
    c.start()
    c.nuntil("call")
    c.grp("afterpc 10", ".*call.*")
    $ gdb /bin/ls -x gdbrc.py

    ...

    => 0x402a2c:    call   0x40db00
       0x402a3b:    call   0x402840 <setlocale@plt>
       0x402a4a:    call   0x4024b0 <bindtextdomain@plt>
       0x402a54:    call   0x402470 <textdomain@plt>
    gdb-expeda$ 

## Usage when just debugging:

    $ gdb /bin/ls -x gdbrc.py

    ...

    => 0x402a2c:    call   0x40db00
       0x402a3b:    call   0x402840 <setlocale@plt>
       0x402a4a:    call   0x4024b0 <bindtextdomain@plt>
       0x402a54:    call   0x402470 <textdomain@plt>
    gdb-expeda$ editor tmp.py # You must have set `$EDITOR` . And you can use `vim` or `emacs` instead of `editor` .
    gdb-expeda$ cat tmp.py
    while True:
        c.next() # You can use `p` and `c` suddenly if you have used `p = PEDA()` and `c = PEDACmd()` in `gdbrc.py` .
        eax = p.getreg("eax")
        if eax == 0:
            break
    gdb-expeda$ source tmp.py

## Installation:

    $ git clone https://github.com/miyagaw61/expeda.git /path/to/expeda
    $ echo "source /path/to/expeda/peda.py" >> ~/.gdbinit
