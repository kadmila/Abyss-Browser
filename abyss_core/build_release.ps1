
if (Test-Path -Path ./release) {
    Remove-Item ./release -Recurse -Force
}

Write-Output "Building abyssnet.dll"
$env:GOOS="windows"; $env:GOARCH="amd64"; $env:CGO_ENABLED="1"; go build -buildmode=c-shared -o ./release/win-amd64/abyssnet.dll ./windll/.
