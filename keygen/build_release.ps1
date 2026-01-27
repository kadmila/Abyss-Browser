if (Test-Path -Path ./release) {
    Remove-Item ./release -Recurse -Force
}

Write-Output "building keygen.exe"
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -o ./release/win-amd64/keygen.exe .
