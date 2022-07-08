:: Run this script from root folder of cilium repo

:: Remove first line // +build !windows
more +1 vendor\github.com\miekg\dns\udp.go > udp.go
move udp.go vendor\github.com\miekg\dns\udp.go
del vendor\github.com\miekg\dns\udp_windows.go

:: Build windows
cd slim-daemon
go build -o anet-agent.exe
