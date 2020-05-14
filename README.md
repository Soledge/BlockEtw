# BlockETW
.Net 3.5 / 4.5 Assembly to block ETW telemetry in a process

You must "Self-Inject" the blocketw.bin to the session that your beacon lives in

For injecting into a process:  

shinject <pid> /opt/shellcode/blocketw.bin

There is no output currently for the command. 
It WILL NOT WORK if your using  spawnto

Credits go to RastaMouse and XPN for creating SharpC2 from which this tool is based
and thier research on ETW bypassing.

Release Build is built with .net 4.5 (but can be built for 3.5)

https://rastamouse.me/2020/05/sharpc2/

https://blog.xpnsec.com/hiding-your-dotnet-etw/
