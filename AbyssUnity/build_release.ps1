$UnityExe = (Get-Content ".\build.config" | ConvertFrom-Json).UnityExe
$LogFile = "build_win64.log"

Write-Output "Building AbyssUnity. This will take a while. See AbyssUnity/build_*.log"

& $UnityExe `
  -quit `
  -projectPath "." `
  -executeMethod BuildScript.BuildWin64Mono `
  -logFile "$LogFile"

if ($LASTEXITCODE -ne 0) {
    throw "Unity build failed. Check ${PWD}/${LogFile}"
}