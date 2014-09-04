[-- WHAT:
This Volatility plugin should show you which process was running on the CPU 
when the target application was dumped.


[-- KNOWN LIMITATIONS:
	- Tested only on few dumps and on Volatility 2.3.1
	- only for x64 kernels


[-- INSTALLATION:
Copy running.py under volatility/plugins/linux


[-- USAGE:
> python vol.py -f /home/emdel/dumps/dump.ram --profile Linuxubuntu-x64 running
 - Name: init - PID: 1
        - Name: [kthreadd] - PID: 2
                + Current: ksoftirqd/0 - PID 3
        - Name: [ksoftirqd/0] - PID: 3
        - Name: [kworker/0:0H] - PID: 5
                + Current: kworker/u:0 - PID 6
        - Name: [kworker/u:0] - PID: 6
        - Name: [kworker/u:0H] - PID: 7
                + Current: migration/0 - PID 8
	.......................................
	.......................................
	.......................................
 	- Name: console-kit-dae - PID: 1244
                + Current: console-kit-dae - PID 1247
 	- Name: xfwm4 - PID: 1562
        - Name: Thunar - PID: 1564
                + Current: gmain - PID 1563
        - Name: xfce4-panel - PID: 1565
	- Name: dd - PID: 1874
                + Current: sudo - PID 1873
        - Name: x-terminal-emul - PID: 1879
        - Name: gnome-pty-helpe - PID: 1880
        - Name: bash - PID: 1881
	.......................................
        .......................................
        .......................................



[-- DOUBT:
I'm not sure if we can conclude that during the dump of process X process Y was 
running on the CPU. I think this is due to the fact the dumping tools don't freeze the system.
In addition the plugin works only for some processes, and I don't know why :)


If you have any idea please contact me @emd3l
I hope to update soon this file with the right explanation.


Happy hacking,


/emdel
