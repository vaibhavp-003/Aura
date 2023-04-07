param (
    [Parameter(Mandatory)][string] $sln,
    [Parameter(Mandatory)][string] $configuration,
    [Parameter(Mandatory)][string] $platform
)

function TrowIfLastError {
    param( [string] $Message = "Operation failed." )
    $errorCode = $LASTEXITCODE
    if ($errorCode) {
        $host.SetShouldExit($errorCode);
        throw $Message
    }  
}

Write-Host "Building $sln $confgiguration $platform..."
& msbuild @($sln, "/t:Restore;Rebuild", "/p:Configuration=$configuration", "/p:Platform=`"$platform`"", "/m", "/nr:false")
TrowIfLastError "Building $sln $confgiguration $platform failed."
Write-Host "Building $sln $confgiguration $platform done."