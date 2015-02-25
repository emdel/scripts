# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Mariano `emdel` Graziano
@license:      GNU General Public License 2.0
@contact:      graziano@eurecom.fr
@organization: 
"""

import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address


# http://lxr.free-electrons.com/source/include/linux/sched.h?v=3.6
class linux_pstate(linux_common.AbstractLinuxCommand):
    """Give you state information about a task"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')
        self.runnability = {}
        self.runnability[0] = "TASK_RUNNING"
        self.runnability[1] = "TASK_INTERRUPTIBLE"
        self.runnability[2] = "TASK_UNINTERRUPTIBLE" 
        self.runnability[4] = "__TASK_STOPPED"
        self.runnability[8] = "__TASK_TRACED"
        self.runnability[64] = "TASK_DEAD"
        self.runnability[128] = "TASK_WAKEKILL"
        self.runnability[256] = "TASK_WAKING"
        self.runnability[512] = "TASK_STATE_MAX"
        # 204: #define TASK_KILLABLE           (TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
        self.runnability[130] = "TASK_KILLABLE"
        # 205 #define TASK_STOPPED            (TASK_WAKEKILL | __TASK_STOPPED) 
        self.runnability[132] = "TASK_STOPPED"
        # 206 #define TASK_TRACED             (TASK_WAKEKILL | __TASK_TRACED)
        self.runnability[136] = "TASK_TRACED"
        # 209 #define TASK_NORMAL             (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE) 
        self.runnability[3] = "TASK_NORMAL"
        # 210 #define TASK_ALL                (TASK_NORMAL | __TASK_STOPPED | __TASK_TRACED)
        self.runnability[136] = "TASK_TRACED"
        self.exit = {}
        self.exit[16] = "EXIT_ZOMBIE"
        self.exit[32] = "EXIT_DEAD"
        self.exit[0] = "ALIVE" 


    @staticmethod
    def virtual_process_from_physical_offset(addr_space, offset):
        pspace = utils.load_as(addr_space.get_config(), astype = 'physical')
        task = obj.Object("task_struct", vm = pspace, offset = offset)
        parent = obj.Object("task_struct", vm = addr_space, offset = task.parent)
        
        for child in parent.children.list_of_type("task_struct", "sibling"):
            if child.obj_vm.vtop(child.obj_offset) == task.obj_offset:
                return child
        
        return obj.NoneObject("Unable to bounce back from task_struct->parent->task_struct")

    def allprocs(self):
        linux_common.set_plugin_members(self)

        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
            yield task

    def calculate(self):
        linux_common.set_plugin_members(self)

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        for task in self.allprocs():
            if not pidlist or task.pid in pidlist:
                yield task

    def unified_output(self, data):
        return TreeGrid([
                       ("Name", str),
                       ("Pid", int),
                       ("Uid", str),
                       ("Gid", str),
                       ("State", str),
                       ("Exit State", str)],
                        self.generator(data))

    def get_state(self, state):
       return self.runnability[int(state)]

    def get_exit(self, exit):
        return self.exit[int(exit)]

    def generator(self, data):
        for task in data:
            if task.mm.pgd == None:
                dtb = task.mm.pgd
            else:
                dtb = self.addr_space.vtop(task.mm.pgd) or task.mm.pgd
            yield (0, [
                                  str(task.comm),
                                  int(task.pid),
                                  str(task.uid) if task.uid else "-",
                                  str(task.gid) if task.gid else "-",
                                  self.get_state(task.state),
                                  self.get_exit(task.exit_state)])

