# CodeCave
A python script to find a code cave inside of a PE file.

Code caves can be used to inject payload into a PE file, using a debugger such as Immunity debugger or ollydbg while changing the execution flow of the program.

The scipt works by looking into the different sections of the file, looking for a series of null bytes that is longer than the length specified by the user.

I would like to thank ired.team for [the great article](https://ired.team/offensive-security/code-injection-process-injection/backdooring-portable-executables-pe-with-shellcode) about the subject.
