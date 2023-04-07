
#include "pch.h"
#include "MaxDeleteRegistryEntry.h"
#include "Registry.h"

CMaxDeleteRegistryEntry::CMaxDeleteRegistryEntry(void)
{
}

CMaxDeleteRegistryEntry::~CMaxDeleteRegistryEntry(void)
{

}

void CMaxDeleteRegistryEntry::DeleteAdwareRegitryEntry(DWORD index)
{	
	switch(index)
	{
		case 1:
			DeleteMailRu_Reg();
			break;
		
		case 2:
			DeleteAdwareDNSUnLockr();
			break;
	}
}


void CMaxDeleteRegistryEntry::DeleteMailRu_Reg()
{			
	CRegistry objReg;
	objReg.DeleteKey(_T("SOFTWARE\\"),_T("Mail.Ru"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SOFTWARE\\Classes\\"),_T("IESearchPlugin.MailRuBHO"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SOFTWARE\\Classes\\"),_T("IESearchPlugin.MailRuBHO.1"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SYSTEM\\ControlSet001\\services\\"),_T("mrupdsrv"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SYSTEM\\ControlSet001\\services\\"),_T("Updater.Mail.Ru"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SYSTEM\\CurrentControlSet\\services\\"),_T("mrupdsrv"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SYSTEM\\CurrentControlSet\\services\\"),_T("Updater.Mail.Ru"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("S-1-5-21-1044670178-1595907161-1762896494-1000\\Software\\AppDataLow\\Software\\"),_T("Mail.Ru"),HKEY_USERS);
	objReg.DeleteKey(_T("S-1-5-21-1044670178-1595907161-1762896494-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"),_T("MailRuUpdater"),HKEY_USERS);
	objReg.DeleteKey(_T("S-1-5-21-1044670178-1595907161-1762896494-1000\\Software\\"),_T("Mail.Ru"),HKEY_USERS);
	objReg.DeleteKey(_T("SOFTWARE\\Classes\\CLSID\\"),_T("{8E8F97CD-60B5-456F-A201-73065652D099}"),HKEY_LOCAL_MACHINE);	
	objReg.DeleteValue(_T("SOFTWARE\Microsoft\\Internet Explorer\\Low Rights\ElevationPolicy\\{68AE298D-7E8A-4F53-BE55-15D2B065F6C0}\\"),_T("AppPath"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("S-1-5-21-1044670178-1595907161-1762896494-1000\\Software\\Microsoft\\Internet Explorer\\SearchScopes\\"),_T("{FFEBBF0A-C22C-4172-89FF-45215A135AC7}"),HKEY_USERS);
	objReg.DeleteKey(_T("S-1-5-21-1044670178-1595907161-1762896494-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\"),_T("Run"),HKEY_USERS);
	objReg.DeleteKey(_T("S-1-5-21-1044670178-1595907161-1762896494-1000\\Software\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"),_T("MailRuUpdater"),HKEY_USERS);
	objReg.DeleteKey(_T("S-1-5-21-1044670178-1595907161-1762896494-1000\\Software\\Mozilla\\NativeMessagingHosts\\"),_T("ru.mail.go.ext_info_host"),HKEY_USERS);
}


void CMaxDeleteRegistryEntry::DeleteAdwareDNSUnLockr(){

	CRegistry objReg;
	objReg.DeleteKey(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"),_T("11598763487076930564"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\MICROSOFT\\"),_T("TechnologyDesktopnew"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SOFTWARE\\MICROSOFT\\"),_T("Speedycar"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS\\"),_T("VOYASOLLAM.EXE"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\"),_T("mtVoyasollam"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Ext\\Settings\\"),_T("{C0D38E5A-7CF8-4105-8FE8-31B81443A114}"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Ext\\Stats\\"),_T("{C0D38E5A-7CF8-4105-8FE8-31B81443A114}"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("Software\\Classes\\CLSID\\"),_T("{C0D38E5A-7CF8-4105-8FE8-31B81443A114}"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\Microsoft\\"),_T("BigTime"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("Software\\"),_T("FastDataX"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("Software\\Microsoft\\"),_T("DMunversion"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\"),_T("Speedownloader0099"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\"),_T("VoyasollamU"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SILENTPROCESSEXIT\\"),_T("Voyasollam.exe"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("System\\CurrentControlSet\\Services\\EventLog\\Application\\"),_T("Application Hosting"),HKEY_LOCAL_MACHINE);
	objReg.DeleteValue(_T("Software\\Microsoft\\Internet Explorer\\SearchScopes\\"),_T("DefaultScope"),HKEY_LOCAL_MACHINE);
	objReg.DeleteValue(_T("Environment\\"),_T("SNP"),HKEY_CURRENT_USER);
	objReg.DeleteValue(_T("Environment\\"),_T("SNF"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("Software\\"),_T("SpeeDownloader"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("Software\\MICROSOFT\\"),_T("wewewe"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("Software\\"),_T("SrcAAAesom Browser Enhancer"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\"),_T("WajIEnhance"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("SOFTWARE\\CLASSES\\APPID\\"),_T("56BF5154-0B48-4ADB-902A-6C8B12E270D9"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\Microsoft\\"),_T("{cc6eb6d8-85b7-435p-8b86-51e4d16ea76d}"),HKEY_CURRENT_USER);
	objReg.DeleteKey(_T("Software\\Microsoft\\"),_T("PrIncub"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\Microsoft\\"),_T("MPrForShutT"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\Microsoft\\"),_T("PrAmNP"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\Microsoft\\"),_T("NSaveA"),HKEY_LOCAL_MACHINE);
	objReg.DeleteKey(_T("Software\\Microsoft\\"),_T("APreSam"),HKEY_LOCAL_MACHINE);
	objReg.DeleteValue(_T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"),_T("Userinit"),HKEY_LOCAL_MACHINE);
	objReg.DeleteValue(_T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"),_T("Shell"),HKEY_LOCAL_MACHINE);
}