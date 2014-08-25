[-- WHAT: 
Windows version for /proc/PID/maps, it based on the VAD information.
It uses Volatility as a library. 
N.B.: As @iMHLv2 pointed me out:
"The Protection in the VAD is the initial protection passed to VirtualAlloc/Ex when the memory is reserved or committed."


[-- INSTALLATION:
Copy the script under your Volatility 2.4 root directory.
Notice that the script has been tested only on Windows 8.


[-- USAGE: 
> python wincodeinfo.py
Usage: wincodeinfo.py profile memdump targetprocname


[-- RUN:
> python wincodeinfo.py Win8SP0x86 file:///home/emdel/leaks/dumpz/windows8_x86_notepad0x00.ram notepad
0xd71000-0xd8c200 PAGE_EXECUTE_WRITECOPY .text
0x70ee0000-0x70f49000 PAGE_EXECUTE_WRITECOPY C:\Program Files\Common Files\microsoft shared\ink\tiptsf.dll
0x76f20000-0x76f94000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\clbcatq.dll
0x730d0000-0x732c7000 PAGE_EXECUTE_WRITECOPY C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.9200.16384_none_893961408605e985\COMCTL32.dll
0x764e0000-0x765f9000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\ole32.dll
0x722f0000-0x72340000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\oleacc.dll
0x734c0000-0x734d9000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\dwmapi.dll
0x74fd0000-0x7508d000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\KERNELBASE.dll
0x74aa0000-0x74af1000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\bcryptPrimitives.dll
0x73e50000-0x73ef7000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\uxtheme.dll
0x77000000-0x7708b000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\OLEAUT32.dll
0x76a00000-0x76adc000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\MSCTF.dll
0x770e0000-0x7718e000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\ADVAPI32.dll
0x77360000-0x77411000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\msvcrt.dll
0x77090000-0x770c4000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\sechost.dll
0x707e0000-0x70840000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\WINSPOOL.DRV
0x74b00000-0x74b09000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\CRYPTBASE.dll
0x77420000-0x7744b000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\IMM32.DLL
0x75410000-0x764d5000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\SHELL32.dll
0x76cd0000-0x76da2000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\RPCRT4.dll
0x77590000-0x77619000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\COMDLG32.dll
0xd70000-0xdae000 PAGE_EXECUTE_WRITECOPY C:\Windows\notepad.exe
0x77450000-0x77586000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\combase.dll
0x768d0000-0x76945000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\SHCORE.DLL
0x751d0000-0x752f1000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\USER32.dll
0x77620000-0x77787000 PAGE_EXECUTE_WRITECOPY C:\Windows\SYSTEM32\ntdll.dll
0x769c0000-0x76a00000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\SHLWAPI.dll
0x75300000-0x7540a000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\GDI32.dll
0x767d0000-0x768c8000 PAGE_EXECUTE_WRITECOPY C:\Windows\system32\KERNEL32.DLL
0x720000-0x81f000 PAGE_READWRITE [heap]
0x580000-0x590000 PAGE_READWRITE [heap]
0x9e0000-0x9ef000 PAGE_READWRITE [heap]
0xcb0000-0xcef000 PAGE_READWRITE [heap]
0x5f0000-0x5df000 PAGE_READONLY [stack]


Happy hacking,


/emdel
