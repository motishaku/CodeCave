# CodeCave
A python script to find a code cave inside of a PE file.

Code caves can be used to inject payload into a PE file, using a debugger such as Immunity debugger or ollydbg while changing the execution flow of the program.

The scipt works by looking into the different sections of the file, looking for a series of null bytes that is longer than the length specified by the user.

I would like to thank ired.team for [the great article](https://ired.team/offensive-security/code-injection-process-injection/backdooring-portable-executables-pe-with-shellcode) about the subject.


## Usage

By running the script using ```py CodeCave.py putty.exe 500``` we would get the following output:
```
[*] Searching for code cave with minimal size of 500 bytes.
[*] Image base is 0x5368709120
[*] ASLR is enabled, Virtual address might be different while program will be executed.
[*] A code cave was found in section .rsrc   , raw address 866422, virtual address: 5369618038 with the size 1737 bytes. Permissions: Readable 
[*] A code cave was found in section .rsrc   , raw address 868273, virtual address: 5369619889 with the size 4009 bytes. Permissions: Readable 
[*] A code cave was found in section .rsrc   , raw address 872544, virtual address: 5369624160 with the size 4027 bytes. Permissions: Readable 
```

Notice how the script mentions that ASLR is enabled, this is an important step while injecting the payload, since you would need to inject the payload relativly to the image base address, and not to a static address.
