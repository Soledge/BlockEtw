# BlockETW
.Net Assembly to block ETW telemetry in current process

Usage: execute-assembly /opt/dotnet/blocketw.exe 

With Aggressor script added to Cobalt Strike:
> blocketw

There is no output currently for the command. 
Credits go to RastaMouse and XPN for creating SharpC2 from which this tool is based
and thier research on ETW bypassing.

Built with .net 4.5

https://rastamouse.me/2020/05/sharpc2/

https://blog.xpnsec.com/hiding-your-dotnet-etw/
