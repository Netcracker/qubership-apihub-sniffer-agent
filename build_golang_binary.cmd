set GOSUMDB=off
set CGO_ENABLED=1
set GOOS=linux
cd ./qubership-apihub-sniffer-agent
go mod tidy
go mod download
go build .
cd ..