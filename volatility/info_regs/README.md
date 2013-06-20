[-- Info Register Plugin
It has been tested on x86 systems running Linux.
It should be quite easy to add the x64 support (Do you agree Dutchy?) :)


[-- Usage:
Run linux_psaux plugin:

[output snippet]
...
2179   1000   1000   i3        
3095   1000   1000   -bash                                                           
3220   1000   1000   ./waiter
...
[end output snipper]


-----------------------------------------------------------------------------------------------------------------------------
[~/vol-latest]
09:58:41 emdel -> python vol.py -f /home/emdel/firewire/waiter_0x02.ram --profile=LinuxLinuxKVM_3_6_0-rc3+x86 info_regs -h
Volatile Systems Volatility Framework 2.3_alpha
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/home/emdel/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --plugins=PLUGINS     Additional plugin directories to use (colon separated)
  --info                Print information about all registered objects
  --cache-directory=/home/emdel/.cache/volatility
                        Directory where cache files are stored
  --cache               Use caching
  --tz=TZ               Sets the timezone for displaying timestamps
  -f FILENAME, --filename=FILENAME
                        Filename to use when opening an image
  --profile=LinuxLinuxKVM_3_6_0-rc3+x86
                        Name of the profile to load
  -l file:///home/emdel/firewire/waiter_0x02.ram, --location=file:///home/emdel/firewire/waiter_0x02.ram
                        A URN location from which to load an address space
  -w, --write           Enable write support
  --use-old-as          Use the legacy address spaces
  --dtb=DTB             DTB Address
  --cache-dtb           Cache virtual to physical mappings
  --output=text         Output in this format (format support is module
                        specific)
  --output-file=OUTPUT_FILE
                        write output in this file
  -v, --verbose         Verbose information
  --shift=SHIFT         Mac KASLR shift address
  -g KDBG, --kdbg=KDBG  Specify a specific KDBG virtual address
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address
  -p PID, --pid=PID     Operate on these Process IDs (comma-separated)

---------------------------------
Module info_regs
---------------------------------
It's like 'info registers' in GDB. It prints out all the 
    processor registers involved during the context switch.


----------------------------------------------------------------------------------------------------------------------------
[~/vol-latest]
09:57:48 emdel -> python vol.py -f /home/emdel/firewire/waiter_0x02.ram --profile=LinuxLinuxKVM_3_6_0-rc3+x86 info_regs -p 2179
Volatile Systems Volatility Framework 2.3_alpha
WARNING : volatility.obj      : Overlay structure tty_struct not present in vtypes
	>> Name: i3  - PID: 2179
		ebx: 	00000005
		ecx: 	08297930
		edx: 	00000040
		esi: 	0000e95f
		edi: 	00000003
		ebp: 	00000000
		eax: 	00000100
		ds: 	0000007b
		es: 	0000007b
		fs: 	00000000
		gs: 	00000033
		eip: 	b776e424
		cs: 	00000073
		eflags: 	00200246
		esp: 	bfcce644
		ss: 	0000007b


