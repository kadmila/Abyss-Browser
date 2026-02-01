$env:CGO_ENABLED = "1"

Set-Location ./AbyssUnity
Copy-Item ".\build.config.origin" ".\build.config"
Set-Location ..

# TODO: create unity project and import abyss_unity
# Create AbyssUI/build.config file.