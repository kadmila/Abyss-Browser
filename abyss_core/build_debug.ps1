Write-Output "building abyssnet.dll"
go build -tags=debug -o abyssnet.dll -buildmode=c-shared .\windll\.