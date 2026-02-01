$UnityExe = (Get-Content ".\build.config" | ConvertFrom-Json).UnityExe
$LogFile = "build_win64.log"

& $UnityExe `
  -batchmode `
  -quit `
  -nographics `
  -projectPath "." `
  -executeMethod BuildScript.BuildWin64Mono `
  -logFile "$LogFile"

if ($LASTEXITCODE -ne 0) {
    throw "Unity build failed. Check ${PWD}/${LogFile}"
}