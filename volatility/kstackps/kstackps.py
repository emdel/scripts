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

import volatility.utils as utils
import volatility.scan as scan
import volatility.plugins.linux.common as linux_common
import volatility.obj as obj
import struct


'''
References: 
- A guide to kernel exploitation - pages 126-132
- https://jon.oberheide.org/blog/2010/11/29/exploiting-stack-overflows-in-the-linux-kernel/
- Linux kernel source code
'''


SIZE_x32 = 0x04
KERNEL_BASE_x32 = 0xc0000000
KERNEL_MAX_x32 = 0xffffffff


class kstackps(linux_common.AbstractLinuxCommand):
    '''
    Walk the kernel pages to discover task_structs.
    We are interested in kernel stack pages and we 
    leverage the thread_info data structure, the first 
    field is a pointer to the task_struct owning 
    the current kernel stack.
    This is just a POC.
    TODO: 
        * x64 support
        * stronger signature for the task_struct
        * psscan like plugin (see the previous point)
        * Find a way to distinguish between dead and hidden
          processes - Exit_state?
        * Create a real Scanner - I had some issues today
    '''
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        linux_common.set_plugin_members(self)
        for offset in xrange(KERNEL_BASE_x32, KERNEL_MAX_x32, 0x2000):
            try: thread_info_addr = struct.unpack('<I', self.addr_space.read(offset, SIZE_x32))[0]
            except: continue
            cur = obj.Object("task_struct", thread_info_addr, self.addr_space)
            # TODO: improve task_struct signature
            if cur.is_valid_task() and cur.pid > 0 and cur.pid < 32768 \
            and cur.state >= 0 and cur.state < 512 and cur.parent > KERNEL_BASE_x32\
            and cur.parent < KERNEL_MAX_x32 and cur.exit_state >= 0 and \
            cur.exit_state <= 32:
                yield cur
            
    def render_text(self, outfd, data):
        processes = {}
        proc_hits = {}
        for task in data:
           if task.pid not in processes:
                processes[task.pid] = task.comm
                proc_hits[task.pid] = 0
           else:
                proc_hits[task.pid] += 1
        for k, v in processes.items():
            print "%d - %s" % (k, v)
        # Why some procs are so many times in memory? Cache?
        #for k, v in proc_hits.items():
        #    print k, v
