# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author:       Mariano `emdel` Graziano
@license:      GNU General Public License 2.0 or later
@contact:      graziano@eurecom.fr
@organization: Eurecom
"""


import volatility.plugins.linux.pslist as linux_pslist
import struct


# x86 offset - It works on my Linux machine.
ir_offset = {
"eax" : 0xfcc,
"ebx" : 0xfb4,
"ecx" : 0xfb8,
"edx" : 0xfbc,
"esp" : 0xff0,
"ebp" : 0xfc8,
"edi" : 0xfc4,
"esi" : 0xfc0,
"eip" : 0xfe4,
"eflags" : 0xfec,
"cs" : 0xfe8,
"ds" : 0xfd0,
"es" : 0xfd4,
"fs" : 0xfd8,
"gs" : 0xfdc,
"ss" : 0xff4 
}


class info_regs(linux_pslist.linux_pslist):
    '''It's like 'info registers' in GDB. It prints out all the 
    processor registers involved during the context switch.'''


    def calculate(self):

        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            name = self.get_task_name(task)
            yield task, name


    def render_text(self, outfd, data):

        #outfd.write("[-- Info Registers:\n")

        for task, name in data:
            outfd.write("\t>> Name: %s - PID: %s\n" % (name, str(task.pid)))
            #outfd.write("\t\tsp0: 0x%08x\n" % (task.thread.sp0))            
            #outfd.write("\t\tsp: 0x%08x\n" % (task.thread.sp))
            #outfd.write("\t\tsysenter_cs: 0x%08x\n" % (task.thread.sysenter_cs))
            #outfd.write("\t\tip: 0x%08x\n" % (task.thread.ip))
            #outfd.write("\t\tgs: 0x%08x\n" % (task.thread.gs))
            ret = self.parse_kernel_stack(task, outfd) 
            



    def parse_kernel_stack(self, task, outfd):
        sp0 = task.thread.sp0 & 0xfffff000
        if task.mm:
            proc_as = task.get_process_address_space()
            for k, v in sorted(ir_offset.items(), key = lambda (k, v): (v, k)):
                val_raw = proc_as.read(sp0 + v, 0x04)
                val = struct.unpack('<I', val_raw)[0]
                outfd.write("\t\t%s: \t%08x\n" % (k, val))
            
            #
            # Debug: print the whole page
            #
            #for n in range(0x00, 0x1000, 0x04):
            #    stack_raw = proc_as.read(sp0 + n, 0x04)
            #    stack = struct.unpack('<I', stack_raw)[0]
            #    outfd.write("\t\t%08x) %08x\n" % (n, stack))



    def get_task_name(self, task):

        if task.mm:
            # set the as with our new dtb so we can read from userland
            proc_as = task.get_process_address_space()

            # read argv from userland
            start = task.mm.arg_start.v()

            argv = proc_as.read(start, task.mm.arg_end - task.mm.arg_start)

            # split the \x00 buffer into args
            name = " ".join(argv.split("\x00"))

        else:
            # kernel thread
            name = "[" + task.comm + "]"

        return name
