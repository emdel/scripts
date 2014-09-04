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

import volatility.obj as obj
import volatility.plugins.linux.pslist as linux_pslist
import struct


# http://www.kernel.org/doc/Documentation/x86/x86_64/kernel-stacks
KERNEL_STACK_MASK_x64 = 0xffffffffffffe000
SIZE_x64 = 0x08

class running(linux_pslist.linux_pslist):
    '''Show you which process was running on the CPU when you dumped the target one.'''

    def calculate(self):
        tasks = linux_pslist.linux_pslist.calculate(self)
        for task in tasks:
            name = self.get_task_name(task)
            yield task, name


    def render_text(self, outfd, data):
        for task, name in data:
            outfd.write("\t- Name: %s - PID: %s\n" % (name, str(task.pid)))
            self.parse_kernel_stack(task, outfd) 
            
    
    def parse_kernel_stack(self, task, outfd):
        '''I use the thread_info trick well documented online:
           - http://www.informit.com/articles/article.aspx?p=368650
           - http://humblec.com/retrieving-current-processtask_struct-in-linux-kernel/
           as well as the Linux Kernel :)
        '''
        thread_info = task.thread.sp0 & KERNEL_STACK_MASK_x64
        thread_info_addr = struct.unpack('<Q', self.addr_space.read(thread_info, SIZE_x64))[0]
        cur = obj.Object("task_struct", thread_info_addr, self.addr_space) 
        # TODO: Understand why this check fails and think about a clever way to
        # validate task_struct
        if cur.comm and cur.pid > 0:
            outfd.write("\t\t+ Current: %s - PID %d\n" % (cur.comm, cur.pid))


    def get_task_name(self, task):
        name = task.comm
        if not task.mm:
            name = "[" + task.comm + "]" 
        return name
