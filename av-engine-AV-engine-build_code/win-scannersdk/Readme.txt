Project Details:

AmsiProvider: This solution is for AMSI scanner.

Elam: This solution is for Elam drivers.

Max Secure folder and Max Secure.sln: This solution is for archive libraries and all the common class are present in "Max Secure\Source\Common" folder.

MaxAntiVirus folder and MaxAntiVirus.sln: This solution is for scanner backend. It contains multiple anti-virus scanner.

MaxDrivers folder and MaxDrivers.sln: This solution is for real-time protection and self-protection drivers.

MaxPPMigrateSD: This solution is for PLL service registration and unregistration. 

MaxSpywareDetector and MaxSpywareDetector.sln: This solution contains all the service and scanner related projects with dependencies.

MaxUPXUnpacker_X64_File: This solution is use to unpack UPX files.

NIH: It contains scanner related dependencies.

WscSerDepends: It contains PPL service related dependencies.

yara-4.2.3_Developement: This solution is for Yara scanner.

MaxUnpacker.sln: This solution is use to unpack samples.



MFC Dll for backend communication:
Project AuBKComDll in MaxSpywareDetector.sln is MFC dll that we are using for backend communication with scanner and service.
AuLiveUpdateDLL in MaxSpywareDetector.sln is MFC dll that we are using for backend communication with Live update.


To Sign binaries, we use below command in our C++ code:

C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x86\signtool.exe sign /a /s my /sha1 626FE27D774CA73B1D978E5C6877D2111792619F /fd sha256 /tr http://timestamp.digicert.com /td SHA256 /v "F:\win-scannersdk\MaxSpywareDetector\Output\x64\Release\Binaries\AuScanner.exe"


To build Visual Studio solutions we use following commands in our C++ code.

x86 Files:

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /build Release|Win32 "Solution Path"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|Win32 "Solution Path"
OR
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /build Release|x86 "Solution Path"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|86 "Solution Path"


x64 Files:

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /build Release|x64 "Solution Path"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "Solution Path"

Solution Path Example= "F:\win-scannersdk\MaxAntiVirus.sln"


We have multiple Visual Studio solutions for different type of projects:

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\MaxUPXUnpacker_X64_File\UPX-Visual-Studio-master\upx-3.95-WithDependancy.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x86 "F:\win-scannersdk\MaxUPXUnpacker_X64_File\UPX-Visual-Studio-master\upx-3.95-WithDependancy.sln"


"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\AmsiProvider\AmsiProvider.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x86 "F:\win-scannersdk\AmsiProvider\AmsiProvider.sln"

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\Max Secure.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|Win32 "F:\win-scannersdk\Max Secure.sln"

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\MaxAntiVirus.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|Win32 "F:\win-scannersdk\MaxAntiVirus.sln"

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\MaxSpywareDetector.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|Win32 "F:\win-scannersdk\MaxSpywareDetector.sln"

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\Development_2023\MaxPPMigrateSD\MaxPPMigrateSD.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x86 "F:\Development_2023\MaxPPMigrateSD\MaxPPMigrateSD.sln"

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\MaxUnpacker.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|Win32 "F:\win-scannersdk\MaxUnpacker.sln"

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\yara-4.2.3_Developement\windows\vs2017\yara.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x86 "F:\win-scannersdk\yara-4.2.3_Developement\windows\vs2017\yara.sln"


To build drivers install latest SDK and WDK for windows 10. Drivers are build in Visual Studio 2019 in Windows 10


"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\MaxDrivers.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x86 "F:\win-scannersdk\MaxDrivers.sln"

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x64 "F:\win-scannersdk\Elam\elam.sln"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe" /Rebuild Release|x86 "F:\win-scannersdk\Elam\elam.sln"
