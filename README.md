# BlockETW
.Net 3.5 / 4.5  Assembly to block ETW telemetry in current process

Usage: execute-assembly /opt/dotnet/blocketw.exe 

With Aggressor script added to Cobalt Strike:
> blocketw

For injecting into a process:   shinject <pid> /opt/shellcode/blocketw.bin

There is no output currently for the command. 

Credits go to RastaMouse and XPN for creating SharpC2 from which this tool is based
and thier research on ETW bypassing.

Release Build is built with .net 4.5 (but can be built for 3.5)

https://rastamouse.me/2020/05/sharpc2/

https://blog.xpnsec.com/hiding-your-dotnet-etw/
