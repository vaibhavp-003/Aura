$buildConfiguration = "Release"

$upxUnpackerSln = ".\MaxUPXUnpacker_X64_File\UPX-Visual-Studio-master\upx-3.95-WithDependancy.sln"
.\build.ps1 $upxUnpackerSln $buildConfiguration "x64"
.\build.ps1 $upxUnpackerSln $buildConfiguration "x86"

# $amsiProviderSln = ".\AmsiProvider\AmsiProvider.sln"
# Build $amsiProviderSln $buildConfiguration "x64"
# Build $amsiProviderSln $buildConfiguration "x86"

# $maxSecureSln = ".\Max Secure.sln"
# Build $maxSecureSln $buildConfiguration "x64"
# Build $maxSecureSln $buildConfiguration "win32"

# $maxAntivirusSln = ".\MaxAntiVirus.sln"
# Build $maxAntivirusSln $buildConfiguration "x64"
# Build $maxAntivirusSln $buildConfiguration "win32"

# $maxSpywareDetectorSln = ".\MaxSpywareDetector.sln"
# Build $maxSpywareDetectorSln $buildConfiguration "x64"
# Build $maxSpywareDetectorSln $buildConfiguration "win32"

# $maxPPMigrateSln = ".\MaxPPMigrateSD\MaxPPMigrateSD.sln"
# Build $maxPPMigrateSln $buildConfiguration "x64"
# Build $maxPPMigrateSln $buildConfiguration "x86"

# $maxUnpackerSln = ".\MaxUnpacker.sln"
# Build $maxUnpackerSln $buildConfiguration "x64"
# Build $maxUnpackerSln $buildConfiguration "win32"

# $yaraSln = ".\yara-4.2.3_Developement\windows\vs2017\yara.sln"
# Build $yaraSln $buildConfiguration "x64"
# Build $yaraSln $buildConfiguration "x86"

# $maxDriversSln = ".\MaxDrivers.sln"
# Build $maxDriversSln $buildConfiguration "x64"
# Build $maxDriversSln $buildConfiguration "x86"

# $elamSln = ".\Elam\elam.sln"
# Build $elamSln $buildConfiguration "x64"
# Build $elamSln $buildConfiguration "win32"