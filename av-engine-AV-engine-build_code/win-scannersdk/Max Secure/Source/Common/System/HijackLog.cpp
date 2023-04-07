/*=============================================================================
   FILE			: HijackLog.cpp
   DESCRIPTION	: Implementation of the CHijackLog class.	
   DOCUMENTS	: CommonSystem DesignDoc.doc
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 22/09/2006
   NOTES		:
VERSION HISTORY	: 24 Aug 2007, Avinash B : Unicode Supported
============================================================================*/

#include "StdAfx.h"
#include "Hijacklog.h" //Header file of CHijackLog class
#include "CPUInfo.h"
#include "verInfo.h"
#include "ExportLog.h"
#include "DBPathExpander.h"
#include "FileSig.h"
#include "BalBST.h"
#include "MaxConstant.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CFileSig g_objFileSignature;

/*-------------------------------------------------------------------------------------
Function		: CHijackLog
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
CHijackLog::CHijackLog(void)
{
	m_csUpdateVersion=BLANKSTRING;
	m_csHijackFileName=BLANKSTRING;
	m_csProductVer=BLANKSTRING;
	m_csDatabaseVer=BLANKSTRING;
	m_csComplexSpyVer=BLANKSTRING;
	m_csInformationVer=BLANKSTRING;
	GetEPSignature = NULL;
	m_hInstDLL = NULL;
	m_lpfnSigProc = NULL;
	m_pobjFileSig = NULL;
	m_pobjPEFileSig = NULL;
}

/*-------------------------------------------------------------------------------------
Function		: ~CHijackLog
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
CHijackLog::~CHijackLog(void)
{
	if(m_hInstDLL)
	{
		FreeLibrary(m_hInstDLL);
		m_hInstDLL = NULL;
	}

	if(m_pobjFileSig)
	{
		delete m_pobjFileSig;
		m_pobjFileSig = NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetHijackLog
In Parameters	: -
Out Parameters	: -
Purpose			: Call various function's which scan's registry Keys,Subkeys,Values etc;
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetHijackLog(void)
{
	try
	{
		if(m_objFileOps.OpenLogFile(m_csHijackFileName))//Open the log file
		{
			// Nupur:
			// 11 June 2007, Version 6.0.0.029
			
			GetSD4();				//O4 - Auto loading programs from Registry or Startup group 	//Run
			GetSD20();				//O20 - AppInit_DLLs Registry value auto run
			GetSD24();				//O24 - Uninstall
			GetSD25();				//SD25 - SD25-Running process

			m_objFileOps.WriteLine();
			m_objFileOps.WriteLog(_T("End Registry Info Log\n"));
			m_objFileOps.WriteLine();
			m_objFileOps.CloseLogFile();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetHijackLog"));
	}

}
/*-------------------------------------------------------------------------------------
Function		: GetAllHijackLog
In Parameters	: -
Out Parameters	: -
Purpose			: Call various function's which scan's registry Keys,Subkeys,Values etc;
Author			: Sandip Sanap
Created Date	: 22-12-2007
--------------------------------------------------------------------------------------*/
void CHijackLog::GetAllHijackLog(void)
{
	try
	{
		
		if(m_objFileOps.OpenLogFile(m_csHijackFileName))//Open the log file
		{
			GetHeaderHijackLog();
			GetSD0();				//Internet Explorer Start & Search pages(R0,R1,R2,R3)
			GetSD1();				//Internet Explorer Start & Search pages(R0,R1,R2,R3)
			GetSD3();				//Internet Explorer Start & Search pages(R0,R1,R2,R3)
			GetFD0();				//Auto loading programs from INI files
			GetFD1();				//Auto loading programs from INI files
			GetFD2();				//Auto loading programs from INI files
			GetND14();				//Netscape/Mozilla Start & Search page
			GetOD1();				//O1 - Host file redirections
			GetOD2();				//OD2 - Browser Helper Objects(o2)
			GetOD3();				//OD3 - Internet Explorer toolbars(O3)
			GetSD4();				//O4 - Auto loading programs from Registry or Startup group 	//Run
			GetSD5();				//O5 - Internet Explorer Options not visible in Control Panel
			GetSD6();				//O6 - Internet Explorer Options access restricted by Administrator
			GetSD7();				//O7 - Regedit access restricted by Administrator
			GetSD8();				//O8 - Extra items in IE right-click menu
			GetSD9();				//O9 - Extra buttons on main IE toolbar, or extra items in IE 'Tools' menu
			GetSD10();				//O10 - Winsock hijackers
			GetSD11();				//O11 - Extra group in IE 'Advanced Options' window
			GetSD12();				//O12 - Internet Explorer plugins
			GetSD13();				//O13 - Internet Explorer Default Prefix hijack
			GetSD14();				//O14 - Reset Web Settings' hijack in iereset.inf
			GetSD15();				//O15 - Unwanted sites in Trusted Zone
			GetSD16();				//O16 - ActiveX Objects (Downloaded Program Files)
			GetSD17();				//O17 - Lop.com domain hijacks
			GetSD19();				//O19 - User style sheet
			GetSD20();				//O20 - AppInit_DLLs Registry value auto run
			GetSD21();				//O21 - ShellServiceObjectDelayLoad
			GetSD22();				//O22 - SharedTaskScheduler
			GetSD23();				//O23 - NT Services
			GetSD24();				//O24 - Uninstall
			GetSD25();				//SD25 - SD25-Running process
			GetSD28();				//SD28 - HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Desktop\Components
			GetSD29();				//SD29 - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components
			GetSD30();				//SD30 - NT Drivers
			GetSD31();				//SD31 - program files, program filesx86, program data(Added by Nilkanth 19-nov-2015)

			m_objFileOps.WriteLine();
			m_objFileOps.WriteLog(_T("End Registry Info Log\n"));
			m_objFileOps.WriteLine();
			m_objFileOps.CloseLogFile();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetHijackLog"));
	}

}

/*-------------------------------------------------------------------------------------
Function		: OpenHijackLog()
In Parameters	: -
Out Parameters	: -
Purpose			: Open hijack log file
Author			: Sandip Sanap
Created Date	: 27-09-2006
--------------------------------------------------------------------------------------*/
bool CHijackLog::OpenHijackLog()
{
	try
	{
		//creating file.
		if(m_csHijackFileName != BLANKSTRING)
			return m_objFileOps.OpenLogFile(m_csHijackFileName);
		else
			return false;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::OpenHijackLog"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CloseHijackLog()
In Parameters	: -
Out Parameters	: -
Purpose			: Close hijack log file
Author			: Sandip Sanap
Created Date	: 27-09-2006
--------------------------------------------------------------------------------------*/
bool CHijackLog::CloseHijackLog()
{
	try
	{
		return m_objFileOps.CloseLogFile();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::CloseHijackLog"));
	}
	return false;
}
/*-------------------------------------------------------------------------------------
Function		: SetHijackFileName()
In Parameters	: CString csProdVer;
Out Parameters	: -
Purpose			: Set the HijackFile Name File Nmae;
Author			: Sandip Sanap
Created Date	: 30-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::SetHijackFileName(CString csHijackFileName)
{
	try
	{
		m_csHijackFileName = csHijackFileName;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::SetHijackFileName"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: SetProdVer()
In Parameters	: CString csProdVer;
Out Parameters	: -
Purpose			: Set the values of Product version;
Author			: Sandip Sanap
Created Date	: 27-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::SetProdVer(CString csProdVer)
{
	m_csProductVer=csProdVer; //Set Product Version

}

/*-------------------------------------------------------------------------------------
Function		: SetUpdtVer()
In Parameters	: CString csUpdtVer
Out Parameters	: -
Purpose			: Set the values of update version patch
Author			: anand srivastava
Created Date	: 13-Nov-2011
--------------------------------------------------------------------------------------*/
void CHijackLog::SetUpdtVer(CString csUpdtVer)
{
	m_csUpdateVersion=csUpdtVer; //Set Update Version
}

/*-------------------------------------------------------------------------------------
Function		: SetVerInfo()
In Parameters	: CString csProdVer,CString csDatabaseVer,CString csCompSpyVer,CString csInfoVer;
Out Parameters	: -
Purpose			: Get the value of Database Version;
Author			: Sandip Sanap
Created Date	: 27-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::SetDatabaseVer(CString csDatabaseVer)
{
	m_csDatabaseVer=csDatabaseVer; //Set Database version
}

/*-------------------------------------------------------------------------------------
Function		: SetComplexSpyVer()
In Parameters	: CString csCompSpyVer;
Out Parameters	: -
Purpose			: Set the value of ComplexSpy Version;
Author			: Sandip Sanap
Created Date	: 27-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::SetComplexSpyVer(CString csComplexSpyVer)
{
	m_csComplexSpyVer=csComplexSpyVer; //Set ComplexSpy version
}

/*-------------------------------------------------------------------------------------
Function		: SetInformation()
In Parameters	: CString csInformationVer;
Out Parameters	: -
Purpose			: Set the value Information Version)
Author			: Sandip Sanap
Created Date	: 27-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::SetInformationVer(CString csInformationVer)
{
	m_csInformationVer=csInformationVer; //Set Information Version
}

/*-------------------------------------------------------------------------------------
Function		: SetGenKeylogVer
In Parameters	: CString csGenKeylogVer;
Out Parameters	: -
Purpose			: Set the value Information Version
Author			: Milind Shete
Created Date	: 03-09-2007
--------------------------------------------------------------------------------------*/
void CHijackLog::SetGenKeylogVer(CString csGenKeylogVer)
{
	m_csGenKeylogVer = csGenKeylogVer; //Set Information Version
}

void CHijackLog::SetVirusVer(CString csVirusVer)
{
	m_csVirusVer = csVirusVer; //Set Information Version
}

void CHijackLog::SetFirstPriVer(CString csFirstPriVer)
{
	m_csFirstPriVer = csFirstPriVer; //Set Information Version
}

/*-------------------------------------------------------------------------------------
Function		: SetRootkitRemVer
In Parameters	: CString csRootkitRemVer;
Out Parameters	: -
Purpose			: Set the value Information Version
Author			: Milind Shete
Created Date	: 03-09-2007
--------------------------------------------------------------------------------------*/
void CHijackLog::SetRootkitRemVer(CString csRootkitRemVer)
{
	m_csRootkitremVer = csRootkitRemVer; //Set Information Version
}

/*-------------------------------------------------------------------------------------
Function		: GetSD0
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Internet Explorer Start & Search pages(R0,R1,R2,R3)
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD0()
{
	try
	{
		CString csDataTemp;
		m_objStringArray.RemoveAll(); //Remove all values in the CStringArray
		m_QueryStringArray.RemoveAll(); //Remove all values in the CStringArray

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Main"),_T("Start Page"),m_csData); //Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != _T("about:blank"))
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Internet Explorer\\Main");
			m_csData+=_T(",Start Page");
			m_objStringArray.Add(m_csData); //Add the registry main Key
			m_QueryStringArray.Add(csDataTemp); //Add the Registry value
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Main"),_T("Start Page"),m_csData,HKEY_LOCAL_MACHINE); //Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != _T("about:blank") && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKLM\\Software\\Microsoft\\Internet Explorer\\Main");
			m_csData+=_T(",Start Page");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Main"),_T("Default_Page_URL"),m_csData);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Internet Explorer\\Main");
			m_csData+=_T(",Default_Page_URL");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Main"),_T("Default_Page_URL"),m_csData,HKEY_LOCAL_MACHINE);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKLM\\Software\\Microsoft\\Internet Explorer\\Main");
			m_csData+=_T(",Default_Page_URL");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		// Local Machine entries - search assistant
		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Search"),_T("SearchAssistant"),m_csData,HKEY_LOCAL_MACHINE);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKLM\\Software\\Microsoft\\Internet Explorer\\Search");
			m_csData+=_T(",SearchAssistant");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}
		WriteRegistryLog(_T(" | SD0 | Internet  Explorer :")); //Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD0"));
	}

} //End of Function GetSD0

/*-------------------------------------------------------------------------------------
Function		: GetSD1
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Internet Explorer Start & Search pages(R0,R1,R2,R3)
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
void  CHijackLog::GetSD1()
{
	try
	{
		CString csDataTemp;
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Main"),_T("Search Bar"),m_csData);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Internet Explorer\\Main");
			m_csData+=_T(",Search Bar");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Main"),_T("Search Page"),m_csData);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Internet Explorer\\Main");
			m_csData+=_T(",Search Page");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Main"),_T("Search Page"),m_csData,HKEY_LOCAL_MACHINE);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{

			m_csData=_T("HKLM\\Software\\Microsoft\\Internet Explorer\\Main");
			m_csData+=_T(",Search Page");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Search"),_T("CustomizeSearch"),m_csData,HKEY_LOCAL_MACHINE);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1) ||
			(m_csData.Find(_T("http://ie.search.msn.com")) == -1)
			)
		{
			m_csData=_T("HKLM\\Software\\Microsoft\\Internet Explorer\\Search");
			m_csData+=_T(",CustomizeSearch");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Search"),_T("CustomizeSearch"),m_csData);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Internet Explorer\\Search");
			m_csData+=_T("CustomizeSearch");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\SearchURL"),BLANKSTRING,m_csData);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING)
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Internet Explorer\\SearchURL");
			m_csData+=_T("(,Default)");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Search"),_T("CustomizeSearch"),m_csData);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Internet Explorer\\Search");
			m_csData+=_T(",CustomizeSearch");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),_T("ProxyServer"),m_csData);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
			m_csData+=_T(",ProxyServer");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),_T("ProxyOverride"),m_csData);//Read the Registry data and values using Get()Function
		csDataTemp=m_csData;
		if(m_csData != BLANKSTRING && ((m_csData.Find(_T("http://www.microsoft.com")) == -1) ||
			(m_csData.Find(_T("http://www.google.com")) == -1) ||
			(m_csData.Find(_T("http://www.msn.com")) == -1))
			)
		{
			m_csData=_T("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
			m_csData+=_T(",ProxyOverride");
			m_objStringArray.Add(m_csData);//Add the registry main Key
			m_QueryStringArray.Add (csDataTemp);
		}

		m_csData = BLANKSTRING;
		if(m_objReg.Get(_T("Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel"),BLANKSTRING,m_csData))
		{
			m_csData = _T("Present");
			csDataTemp=m_csData;
		}
		else
		{
			m_csData = _T("Not Present");
			csDataTemp=m_csData;
		}

		m_csData=_T("HKCU\\Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel");
		m_objStringArray.Add(m_csData);//Add the registry main Key
		m_QueryStringArray.Add (csDataTemp);

		WriteRegistryLog(_T(" | SD1 | Internet  Explorer :")); //Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD1"));
	}
} //End of GetSD1 Function

/*-------------------------------------------------------------------------------------
Function		: GetSD3
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Internet Explorer Start & Search pages(R0,R1,R2,R3)
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD3()
{
	try
	{
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		m_csData=BLANKSTRING;

		//Url search hook
		//Check for given key of the registry exist or not

		if(m_objReg.KeyExists(_T("software\\microsoft\\internet explorer\\urlsearchhooks"),HKEY_CURRENT_USER))
			m_objReg.QueryDataValue(_T("software\\microsoft\\internet explorer\\urlsearchhooks"),m_objStringArray,m_QueryStringArray,HKEY_CURRENT_USER); //Get Recursively value and corrsponding data
		WriteRegistryLog(_T(" | SD3 | URL search Hook :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD3"));
	}
} //End of GetSD3 Function

/*-------------------------------------------------------------------------------------
Function		: GetFD0
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Autoloading programs from INI files
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetFD0()
{
	try
	{
		//F0 - Autoloading programs from INI files
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();

		m_csData=BLANKSTRING;
		m_objReg.Get(WINLOGON_REG_KEY,_T("Shell"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != BLANKSTRING  && m_csData.CompareNoCase(_T("Explorer.exe")) != 0)
		{
			m_objStringArray.Add(_T("Shell"));//Add the registry SubKey Name
			m_QueryStringArray.Add (m_csData);
		}
		WriteRegistryLog(_T(" | FD0 | Winlogon :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetFD0"));
	}
} //End of GetFD0 Function

/*-------------------------------------------------------------------------------------
Function		: GetFD1
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Autoloading programs
from INI files
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetFD1()
{
	try
	{
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		TCHAR lzBuffer[MAX_FILE_PATH];
		GetWindowsDirectory(lzBuffer,MAX_FILE_PATH);
		CString csINIPath;
		csINIPath = lzBuffer;
		csINIPath += _T("\\System.ini");
		//Thi GetPrivateProfileString function retrieves a string from the specified section in an initialization file.
		GetPrivateProfileString(_T("boot"),_T("shell"),BLANKSTRING,m_csData.GetBuffer(MAX_PATH),MAX_PATH,csINIPath);
		m_csData.ReleaseBuffer();
		if(m_csData != BLANKSTRING && m_csData.CompareNoCase(_T("Explorer.exe")) != 0)
		{
			m_objStringArray.Add(_T("Shell"));//Add the registry subKey name
			m_QueryStringArray.Add (m_csData);
			WriteRegistryLog(_T(" | FD0 | System.ini :")); //Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetFD1"));
	}
} // End of GetFD1 Function

/*-------------------------------------------------------------------------------------
Function		: GetFD2
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Autoloading programs from INI files
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetFD2()
{
	try
	{
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		TCHAR lzBuffer[MAX_FILE_PATH];
		GetWindowsDirectory(lzBuffer,MAX_FILE_PATH);
		CString csINIPath;
		csINIPath = lzBuffer;
		csINIPath += _T("\\win.ini");
		GetPrivateProfileString(_T("windows"),_T("Run"),BLANKSTRING,m_csData.GetBuffer(MAX_PATH),MAX_PATH,csINIPath);
		m_csData.ReleaseBuffer();
		if(m_csData != BLANKSTRING)
		{
			m_objStringArray.Add(_T("Run"));//Add the registry SubKey name
			m_QueryStringArray.Add (m_csData);
			WriteRegistryLog(_T(" | FD1 | WIN.INI :"));
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(WINLOGON_REG_KEY,_T("Userinit"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != BLANKSTRING)
		{
			m_objStringArray.Add(_T("Userinit"));//Add the registry subKey name
			m_QueryStringArray.Add (m_csData);
		}

		WriteRegistryLog(_T(" | FD2 | Winlogon :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetFD2"));
	}
}
/*-------------------------------------------------------------------------------------
Function		: GetND14
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with N1, N2, N3, N4 - Netscape/Mozilla Start & Search page
Author			: Sandip Sanap
Created Date	: 22-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetND14()
{
	//N1, N2, N3, N4 - Netscape/Mozilla Start & Search page
	try
	{
		TCHAR lzBuffer[MAX_FILE_PATH];
		GetWindowsDirectory(lzBuffer,MAX_FILE_PATH);
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		m_csData=BLANKSTRING;
		CString csAppPath = BLANKSTRING,csCmnStartup = BLANKSTRING, csStartup = BLANKSTRING;
		TCHAR szPath[MAX_FILE_PATH]={0};
		typedef HMODULE  (__stdcall *SHGETFOLDERPATH)(HWND, int, HANDLE, DWORD, LPTSTR);
		HMODULE hModule = LoadLibrary(_T("SHFOLDER.DLL"));
		if(hModule != NULL)
		{
#ifdef _UNICODE
			SHGETFOLDERPATH fnShGetFolderPath = (SHGETFOLDERPATH)GetProcAddress(hModule, "SHGetFolderPathW");
#else
			SHGETFOLDERPATH fnShGetFolderPath = (SHGETFOLDERPATH)GetProcAddress(hModule, "SHGetFolderPathA");
#endif

			if(fnShGetFolderPath != NULL)
			{
				fnShGetFolderPath(0,CSIDL_APPDATA/*_CONST*/,NULL,	0,szPath);
				csAppPath = szPath;
				fnShGetFolderPath(0,CSIDL_COMMON_STARTUP,NULL,	0,szPath);
				csCmnStartup = szPath;
				fnShGetFolderPath(0,CSIDL_STARTUP/*_CONST*/,NULL,	0,szPath);
				csStartup = szPath;
			}
			FreeLibrary(hModule);
			hModule = NULL;
		}
		if(csAppPath != BLANKSTRING)
		{
			CString csPath(szPath);
			csPath += _T("\\Mozilla\\Profiles\\default\\3rbu6w2d.slt\\prefs.js");
			CFileFind objFind;
			if(objFind.FindFile(csPath))
			{
				CFile objFile;
				objFile.Open(static_cast<LPCTSTR>(csPath), CFile::modeRead);
				//to do: change the size of the buffer from 1024 to appropriate value.
				TCHAR lzBufferLocal[1024];
				CString csBuffer;
				while(!objFile.Read(lzBufferLocal, 1024))
				{
					csBuffer = lzBufferLocal;
					if(csBuffer.Find(_T("browser.search.defaultengine")) != -1)
					{
						m_objStringArray.Add(csBuffer);//Add the registry subKey name
						m_QueryStringArray.Add(csPath);//Add Path name
						break;
					}
				}
				objFile.Close();
				WriteRegistryLog(_T(" | ND1 | NetScape :"));//Write all registry information in the Log File
				m_objStringArray.RemoveAll();
				m_QueryStringArray.RemoveAll();
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetND14"));
	}
} //End of GetND14 function
/*-------------------------------------------------------------------------------------
Function		: GetOD1
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O1 - Hostsfile redirections
Author			: Sandip Sanap
Created Date	: 23-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetOD1()
{
	//O1 - Hostsfile redirections
	try
	{
		TCHAR lzBuffer[MAX_FILE_PATH];
		GetWindowsDirectory(lzBuffer,MAX_FILE_PATH);
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		m_csData=BLANKSTRING;
		CFileFind objFind; //Constructs a CFileFind object.
		CString csPath;
		csPath = lzBuffer;
		csPath += _T("\\Help\\Hosts");
		if(objFind.FindFile(csPath))
		{
			m_objStringArray.Add(csPath); //Add the registry Pathname
			m_QueryStringArray.Add(_T("Present")); //Add status
			WriteRegistryLog(_T(" | OD1 | Host :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetOD1"));
	}
} //End of GetOD1 function
/*-------------------------------------------------------------------------------------
Function		: GetOD2
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O2 - Browser Helper Objects
Author			: Sandip Sanap
Created Date	: 23-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetOD2()
{
	try
	{
		CRegistry m_objReg;//Create the object of CREgistry Class
		//O2 - Browser Helper Objects
		m_objStringArray.RemoveAll();
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | OD2 | BHO :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetOD2"));
	}
} //End of GetOD2 function
/*-------------------------------------------------------------------------------------
Function		: GetOD3
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O3 - Internet Exploler toolbars
Author			: Sandip Sanap
Created Date	: 23-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetOD3()
{
	try
	{
		//O3 - IE toolbars
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check the Given Key exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar"),HKEY_LOCAL_MACHINE))
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar"),m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);//Get Recursively value and corrsponding data
		WriteRegistryLog(_T(" | OD3 | ToolBar :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetOD3"));
	}
} //End of GetOD3 Function
/*-------------------------------------------------------------------------------------
Function		: GetSD4
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O4 - Autoloading programs from Registry or Startup group
Author			: Sandip Sanap
Created Date	: 23-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD4()
{
	try
	{
		//O4 - Autoloading programs from Registry or Startup group
		//Run
		CString csCmnStartup = BLANKSTRING, csStartup = BLANKSTRING;
		TCHAR szPath[MAX_FILE_PATH]={0};
		TCHAR lzBuffer[MAX_FILE_PATH]={0};
		GetWindowsDirectory(lzBuffer,MAX_FILE_PATH);
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		m_csData=BLANKSTRING;
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),HKEY_CURRENT_USER))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),m_objStringArray,m_QueryStringArray,HKEY_CURRENT_USER);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKCU-Run :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"),HKEY_CURRENT_USER))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"),m_objStringArray,m_QueryStringArray,HKEY_CURRENT_USER);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKCU-RunServicesOnce :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"),HKEY_CURRENT_USER))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"),m_objStringArray,m_QueryStringArray,HKEY_CURRENT_USER);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKCU-RunServices :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),HKEY_CURRENT_USER))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),m_objStringArray,m_QueryStringArray,HKEY_CURRENT_USER);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKCU-RunOnce :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),HKEY_CURRENT_USER))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),m_objStringArray,m_QueryStringArray,HKEY_CURRENT_USER);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKCU-Policies\\Explorer\\Run :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),HKEY_LOCAL_MACHINE))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKLM-Run :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"),HKEY_LOCAL_MACHINE))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"),m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKLM-RunServicesOnce :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"),HKEY_LOCAL_MACHINE))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"),m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKLM-RunServices :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),HKEY_LOCAL_MACHINE))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKLM-RunOnce :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),HKEY_LOCAL_MACHINE))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKLM-Policies\\Explorer\\Run :"));
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//Check for given key of the registry exist or not
		if(m_objReg.KeyExists(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"),HKEY_LOCAL_MACHINE))
		{
			m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"),m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);//Get Recursively value and corrsponding data
		}
		WriteRegistryLog(_T(" | SD4 | HKLM-RunOnceEx :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();

		if(csCmnStartup != BLANKSTRING)
		{
			this->GetFilesFromFolder(szPath);
			WriteRegistryLog(_T(" | SD4 | Global startup :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}

		if(csStartup != BLANKSTRING)
		{
			this->GetFilesFromFolder(szPath);
			WriteRegistryLog(_T(" | SD4 | Startup :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD4"));
	}
} // End of GetSD4 function
/*-------------------------------------------------------------------------------------
Function		: GetSD5
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O5 - IE Options not visible in Control Panel
Author			: Sandip Sanap
Created Date	: 23-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD5()
{
	try
	{
		TCHAR lzBuffer[MAX_FILE_PATH];
		GetWindowsDirectory(lzBuffer,MAX_FILE_PATH);
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		m_csData=BLANKSTRING;
		//O5 - IE Options not visible in Control Panel
		CString csWinPath;
		csWinPath = lzBuffer;
		csWinPath += _T("control.ini");
		GetPrivateProfileString(_T("don't load"),_T("inetcpl.cpl"),BLANKSTRING,m_csData.GetBuffer(MAX_PATH),MAX_PATH,csWinPath);
		m_csData.ReleaseBuffer();
		if(m_csData != BLANKSTRING)
		{
			m_objStringArray.Add (_T("inetcpl.cpl"));//Add the registry subKey name
			m_QueryStringArray.Add(m_csData); // Add Value
			WriteRegistryLog(_T("| SD5 | control.ini :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD5"));
	}
}// End of GetSD5 function

/*-------------------------------------------------------------------------------------
Function		: GetSD6
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Internet Explorer Options access restricted by Administrator
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD6 ()
{
	try
	{
		CRegistry m_objReg; //Create the object of CREgistry Class
		m_csData = BLANKSTRING;
		if(m_objReg.Get(_T("Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions"),BLANKSTRING,m_csData))
		{
			m_csData = _T("Present");
		}
		else
		{
			m_csData = _T("Not Present");
		}
		m_objStringArray.Add(_T("HKCU\\Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions"));//Add the registry MainKey name
		m_QueryStringArray.Add(m_csData); //Add Value

		WriteRegistryLog(_T(" | SD6 | IE Options Restriction :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD6"));
	}
}// End of GetSD6 function

/*-------------------------------------------------------------------------------------
Function		: GetSD7
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with  Regedit access restricted by Administrator
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD7()
{
	//O7 - Regedit access restricted by Administrator
	try
	{
		CRegistry m_objReg;//Create the object of CREgistry Class
		DWORD dwData;
		m_objReg.Get(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),_T("DisableRegistryTools"),dwData);
		if(dwData == 1)
		{
			m_csData = _T("Disable Regedit");
			m_objStringArray.Add(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"));//Add the registry MainKey name
			m_QueryStringArray.Add(m_csData); //Add Value
			WriteRegistryLog(_T(" | SD7 | Regedit Restiction :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD7"));
	}
} //End of GetSD7 function

/*-------------------------------------------------------------------------------------
Function		: GetSD8
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Extra items in IE right-click menu
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD8()
{
	//O8 - Extra items in IE right-click menu
	try
	{
		m_objReg.EnumSubKeys(_T("Software\\Microsoft\\Internet Explorer\\MenuExt"),m_objStringArray,HKEY_CURRENT_USER);
		WriteRegistryLog(_T(" | SD8 | Extra context menu item :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD8"));
	}
} //End of GetSD8 function

/*-------------------------------------------------------------------------------------
Function		: GetSD9
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Extra buttons on main IE toolbar, or extra items in IE 'Tools' menu
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD9()
{
	//O9 - Extra buttons on main IE toolbar, or extra items in IE 'Tools' menu
	try
	{
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Extensions"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD9 | Extra :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD9"));
	}
} //End of GetSD9 Function

/*-------------------------------------------------------------------------------------
Function		: GetSD10
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O10 - Winsock hijackers
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD10()
{
	//O10 - Winsock hijackers
	try
	{
		m_csData=BLANKSTRING;
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD10 | Winsock :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD10"));
	}
}// End of GetSD10 function

/*-------------------------------------------------------------------------------------
Function		: GetSD11
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O11 - Extra group in IE 'Advanced Options' window
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD11()
{
	//O11 - Extra group in IE 'Advanced Options' window
	try
	{
		m_csData=BLANKSTRING;
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD11 | Advance Option :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD11"));
	}
} //End of GetSD11 Function

/*-------------------------------------------------------------------------------------
Function		: GetSD12
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O12 - IE plugins
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD12()
{
	//O12 - IE plugins
	try
	{
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Plugins\\Extension"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD12 | Plugin :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD12"));
	}
} //End of Get SD12 function

/*-------------------------------------------------------------------------------------
Function		: GetSD13
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Internet Explorer Default Prefix hijack
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD13()
{
	//O13 - IE DefaultPrefix hijack
	try
	{
		CString csTemp;
		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\URL\\DefaultPrefix"),BLANKSTRING,m_csData,HKEY_LOCAL_MACHINE);
		csTemp=m_csData;
		if(m_csData != _T("http://") && m_csData != BLANKSTRING)
		{
			m_objStringArray.Add(_T("Default "));//Add the registry subKey name
			m_QueryStringArray.Add(csTemp); //Add Value
			WriteRegistryLog(_T("| SD13 | Prefix :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\URL\\Prefixes"),_T("www"),m_csData,HKEY_LOCAL_MACHINE);
		csTemp=m_csData;
		if(m_csData != BLANKSTRING && m_csData != _T("http://"))
		{
			m_objStringArray.Add(_T("www"));//Add the registry subKey name
			m_QueryStringArray.Add(csTemp);//Add Value
			WriteRegistryLog(_T(" | SD13 | Prefix :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD13"));
	}
} // End of GetSD13 function

/*-------------------------------------------------------------------------------------
Function		: GetSD14
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with O14 - Reset Web Settings' hijack in iereset.inf
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD14()
{
	//O14 - 'Reset Web Settings' hijack
	try
	{
		CString csWinPath;

		TCHAR lzBuffer[MAX_FILE_PATH];
		GetWindowsDirectory(lzBuffer,MAX_FILE_PATH);
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		m_csData=BLANKSTRING;
		csWinPath = lzBuffer;
		csWinPath += _T("\\inf\\iereset.inf");
		GetPrivateProfileString(_T("Strings"),_T("START_PAGE_URL"),BLANKSTRING,m_csData.GetBuffer(MAX_PATH),MAX_PATH,csWinPath);
		m_csData.ReleaseBuffer();
		m_objStringArray.Add(_T("START_PAGE_URL"));//Add the registry subKey name
		m_QueryStringArray.Add(m_csData);//Add Value
		WriteRegistryLog(_T(" | SD14 | IERESET.INF :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD14"));
	}
}// End of GetSD14 function

/*-------------------------------------------------------------------------------------
Function		: GetSD15
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Unwanted sites in Trusted Zone
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD15()
{
	//O15 - Unwanted sites in Trusted Zone
	try
	{
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains"),m_objStringArray,HKEY_CURRENT_USER);
		WriteRegistryLog(_T(" | SD15 | Trusted Zone :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD15 | Trusted Zone :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges"),m_objStringArray,HKEY_CURRENT_USER);
		WriteRegistryLog(_T(" | SD15 | Trusted Zone :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD15 | Trusted Zone :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD15"));
	}
} // End of GetSD15 function

/*-------------------------------------------------------------------------------------
Function		: GetSD16
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with ActiveX Objects (Downloaded Program Files)
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD16()
{
	//O16 - ActiveX Objects (aka Downloaded Program Files)
	try
	{
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Code Store Database\\Distribution Units"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD16 | Activex :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD16"));
	}
} // End of GetSD16 function

/*-------------------------------------------------------------------------------------
Function		: GetSD17
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Lop.com domain hijacks
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD17()
{
	//O17 - Lop.com domain hijacks
	try
	{
		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"),_T("Domain"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != BLANKSTRING)
		{
			m_objStringArray.Add(_T("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters,Domain"));//Add the registry MainKey name
			m_QueryStringArray.Add(m_csData);//Add Value
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{AEBBD6DC-81E2-4967-B659-611186F03976}"),_T("NameServer"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != BLANKSTRING)
		{
			m_objStringArray.Add(_T("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{AEBBD6DC-81E2-4967-B659-611186F03976},NameServer"));//Add the registry subKey name
			m_QueryStringArray.Add (m_csData); //Add Value
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters"),_T("Domain"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != BLANKSTRING)
		{
			m_objStringArray.Add (_T("HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters,Domain"));//Add the registry mainKey name
			m_QueryStringArray.Add (m_csData);//Add Value
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SYSTEM\\ControlSet002\\Services\\Tcpip\\Parameters"),_T("Domain"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != BLANKSTRING)
		{
			m_objStringArray.Add (_T("HKLM\\SYSTEM\\ControlSet002\\Services\\Tcpip\\Parameters,Domain"));//Add the registry mainKey name
			m_QueryStringArray.Add (m_csData);//Add Value
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP"),_T("Domain"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != BLANKSTRING)
		{
			m_objStringArray.Add(_T("HKLM\\SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP,Domain"));//Add the registry mainKey name
			m_QueryStringArray.Add (m_csData);//add Value
		}

		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SYSTEM\\ControlSet001\\Services\\VxD\\MSTCP"),_T("Domain"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != "")
		{
			m_objStringArray.Add (_T("HKLM\\SYSTEM\\ControlSet001\\Services\\VxD\\MSTCP,Domain"));//Add the registry mainKey name
			m_QueryStringArray.Add (m_csData);//Add Value
		}

		WriteRegistryLog(_T(" | SD17 | TCP-IP :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD17 | TCPIP :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD17"));
	}
} // End of GetSD17 function

/*-------------------------------------------------------------------------------------
Function		: GetSD19
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with User style sheet
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD19()
{
	//O19 - User style sheet hijack
	try
	{
		DWORD dwData;
		m_csData=BLANKSTRING;
		m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Styles"),_T("Use My Stylesheet"),dwData,HKEY_CURRENT_USER);
		if(dwData == 1)
		{
			m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Styles"),_T(" User Stylesheets"),m_csData,HKEY_CURRENT_USER);
			m_objStringArray.Add (_T("present"));//Add the registry SubKey name
			m_QueryStringArray.Add (m_csData);
			WriteRegistryLog(_T(" | SD19 | Use My Stylesheet :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD19"));
	}
} // End of GetSD19 function

/*-------------------------------------------------------------------------------------
Function		: GetSD20
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with AppInit_DLLs Registry value auto run
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD20()
{
	//O20 - AppInit_DLLs Registry value autorun
	try
	{
		m_csData=BLANKSTRING;
		m_objReg.Get(_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),_T("AppInit_DLLs"),m_csData,HKEY_LOCAL_MACHINE);
		if(m_csData != BLANKSTRING)
		{
			int curPos = 0;
			CString csToken = m_csData.Tokenize(_T(","), curPos);
			CString csExpandPath,csExpandPathMain = BLANKSTRING;
			while(csToken != BLANKSTRING)
			{
				if(csExpandPathMain != BLANKSTRING)
					csExpandPathMain += _T(" ");
				GetLongPathName(csToken.GetBuffer(MAX_PATH),csExpandPath.GetBuffer(MAX_FILE_PATH),MAX_FILE_PATH);
				csToken.ReleaseBuffer();
				csExpandPath.ReleaseBuffer();
				csExpandPathMain+=csExpandPath;
				csToken = m_csData.Tokenize(_T(","), curPos);
			}
			m_csData=csExpandPathMain;
			m_objStringArray.Add (m_csData);//Add the registry SubKey name
			m_QueryStringArray.Add (m_csData);//Add the registry SubKey name
			WriteRegistryLog(_T(" | SD20 | AppInit_DLLs :"));//Write all registry information in the Log File
			m_objStringArray.RemoveAll();
			m_QueryStringArray.RemoveAll();
		}
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(NOTIFY_MAIN_KEY,m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD20 | Winlogon :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD20"));
	}

} // End of GetSD20 function

/*-------------------------------------------------------------------------------------
Function		: GetSD21
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with ShellServiceObjectDelayLoad
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD21()
{
	//O21 - ShellServiceObjectDelayLoad
	try
	{
		m_objReg.QueryDataValue(SSODL_PATH,m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);//Get Recursively value and corrsponding data
		WriteRegistryLog(_T(" | SD21 | SSODL :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD21"));
	}
} // End of GetSD21 function

/*-------------------------------------------------------------------------------------
Function		: GetSD22
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with SharedTaskScheduler
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD22()
{
	//O22 - SharedTaskScheduler
	try
	{
		m_objReg.QueryDataValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler"),m_objStringArray,m_QueryStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD22 | SharedTaskScheduler :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD22"));
	}
} // End of GetSD22 function

/*-------------------------------------------------------------------------------------
Function		: GetSD30
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with NT Services
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD30()
{
	//SD30 - NT Drivers
	try
	{
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SYSTEM\\CurrentControlSet\\Services"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD30 | Drivers :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD30"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetSD23
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with NT Services
Author			: Sandip Sanap
Created Date	: 25-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD23()
{
	//O23 - NT Services
	try
	{
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SYSTEM\\CurrentControlSet\\Services"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD23 | Services :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD23"));
	}
}// End of GetSD23 function

/*-------------------------------------------------------------------------------------
Function		: GetSD24
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with Uninstall
Author			: Sandip Sanap
Created Date	: 26-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD24()
{
	//SD24 : uninstall
	try
	{
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD24 | Uninstall :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD24"));
	}
} // End of GetSD24 function

/*-------------------------------------------------------------------------------------
Function		: GetSD28
In Parameters	: -
Out Parameters	: -
Purpose			: Scan and get registry and files related with SD28 - HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Desktop\Components
Author			: Sandip Sanap
Created Date	: 26-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD28()
{
	//SD28 - HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Desktop\Components\0
	try
	{
		//EnumSubkeys()function Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Desktop\\Components"),m_objStringArray,HKEY_CURRENT_USER);
		WriteRegistryLog(_T(" | SD28 | Desktop Components :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD28"));
	}
}// End of GetSD28 function

/*-------------------------------------------------------------------------------------
Function		: GetSD29
In Parameters	: -
Out Parameters	: -
Purpose			: Scan and get registry and files related with SD29 - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components
Author			: Sandip Sanap
Created Date	: 28-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD29()
{
	try
	{
		//EnumSubkeys() ->> Get all subkeys(Name only)
		m_objReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"),m_objStringArray,HKEY_LOCAL_MACHINE);
		WriteRegistryLog(_T(" | SD29 | Installed Components :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD29"));
	}
} //End Of SD29 Function

/*-------------------------------------------------------------------------------------
Function		: GetSD25
In Parameters	: -
Out Parameters	: -
Purpose			: Scan registry and files related with SD25-Running process
Author			: Sandip Sanap
Created Date	: 26-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetSD25()
{
	try
	{
		GetRunningProcess();
		WriteRegistryLog(_T(" | SD25 | Process :"));//Write all registry information in the Log File
		m_objStringArray.RemoveAll();
		m_QueryStringArray.RemoveAll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD25"));
	}
} // End of GetSD25 function

/*-------------------------------------------------------------------------------------
Function		: CALLBACK ProcHandler
In Parameters	: LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum
Out Parameters	: BOOL
Purpose			: Calling convention for callback function
Author			: Sandip Sanap
Created Date	: 26-09-2006
--------------------------------------------------------------------------------------*/
BOOL CALLBACK ProcHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CHijackLog *pSpyUIDlg = (CHijackLog *)pThis; //Create object of the CHijackClass
		CString temp,csTemp;
		temp=szExePath;
		pSpyUIDlg->m_objStringArray.Add(temp);
		csTemp = pSpyUIDlg->GetSignature(szExePath) + L" #@# " + pSpyUIDlg->GetExecSignature(szExePath);
		pSpyUIDlg->m_QueryStringArray.Add(csTemp);
		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::ProcHandler"));
	}
	return FALSE;
}// End of ProcHandler function

/*-------------------------------------------------------------------------------------
Function		: GetRunningProcess
In Parameters	: -
Out Parameters	: -
Purpose			: Scan files related with running process
Author			: Sandip Sanap
Created Date	: 26-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetRunningProcess()
{
	try
	{
		CEnumProcess objEnumProcess;
		objEnumProcess.EnumRunningProcesses((PROCESSHANDLER)ProcHandler, this);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetRunningProcess"));
	}
}//End of GetRunningProcess Function

/*-------------------------------------------------------------------------------------
Function		: WriteRegistryLog()
In Parameters	: CString csType :Passes the different values of registry keys
Out Parameters	: -
Purpose			: Write the all Entries such as registry name,Subkeys,value in the Log file
Author			: Sandip Sanap
Created Date	: 26-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::WriteRegistryLog(CString csType)
{
	try
	{
		CString csFileName,csData1;
		CString temp;
		CString csVal;
		int arrSize = static_cast<int>(m_objStringArray.GetCount());
		for(INT_PTR i = 0; i < arrSize; i++)
		{
			CString m_csData,csName;
			int iFind = csType.Find(_T(" | SD4"));
			if(m_QueryStringArray.GetCount() == m_objStringArray.GetCount())
				m_csData=m_QueryStringArray.GetAt(i);
			csVal=m_objStringArray.GetAt(i);

			if(csType.Find(_T(" | SD31")) != -1)
			{
				m_csData = m_objStringArray.GetAt(i);
			}
			if(iFind != -1)
			{
				CFileFind fFind;
				csFileName = m_csData;
				csFileName.MakeLower();
				iFind = csFileName.Find(EXE_EXTENTION);
				if(iFind != -1)
				{
					csFileName = csFileName.Mid(0,iFind + 4);
					csFileName.Replace(L"\"",L"");
				}
				else
				{
					iFind = csFileName.Find(DLL_EXTENTION);
					if(iFind != -1)
					{
						csFileName = csFileName.Mid(0,iFind + 4);
					}
					iFind = csFileName.Find(_T(' '));

					if(iFind != -1 && fFind.FindFile(csFileName) == FALSE)
					{
						csFileName = csFileName.Mid(iFind + 1,csFileName.GetLength());
					}

				}
				if(fFind.FindFile(csFileName) == FALSE)
				{
					CString csWinDir;
					GetWindowsDirectory(csWinDir.GetBuffer(MAX_FILE_PATH),MAX_FILE_PATH);
					csWinDir.ReleaseBuffer();
					CString csAllPath;
					m_objReg.Get(_T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"),_T("Path"),csAllPath,HKEY_LOCAL_MACHINE);
					int curPos = 0;
					CString sToken = csAllPath.Tokenize(_T(";"), curPos);
					while(sToken != BLANKSTRING)
					{
						sToken.Replace(_T("%SystemRoot%"),csWinDir);
						sToken +=BACK_SLASH;
						sToken += csFileName;
						if(fFind.FindFile(sToken) == TRUE)
						{
							csFileName = sToken;
							break;
						}
						sToken = csAllPath.Tokenize(_T(";"), curPos);
					}
				}
				m_csData = m_csData + _T(" #@# ") + GetSignature(csFileName) + _T(" #@# ") + GetExecSignature(csFileName);
			}
			else if(csType == _T(" | SD23 | Services :"))
			{
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("SYSTEM\\CurrentControlSet\\Services\\") +csVal,_T("ImagePath"),m_csData,HKEY_LOCAL_MACHINE);
				if(m_csData == BLANKSTRING || m_csData.Right(4).MakeLower() == _T(".sys"))
				{
					csVal = BLANKSTRING; // for skipping this entries
					m_csData = BLANKSTRING; // for skipping this entries
				}
				if(m_csData != BLANKSTRING)
				{
					GetLongPathName(m_csData.GetBuffer(MAX_PATH),m_csData.GetBuffer(MAX_FILE_PATH),MAX_FILE_PATH);
					m_csData.ReleaseBuffer();
					CFileVersionInfo objVerInfo;
					bool bVerInfo = false;
					CCPUInfo objSystem;
					m_csData.MakeLower();
					if(m_csData.Left(9).CollateNoCase(L"system32\\") == 0)
						m_csData.Replace(_T("system32"), objSystem.GetSystemDir());
					else if(m_csData.Left(21).CollateNoCase(L"\\systemroot\\system32\\") == 0)
						m_csData.Replace(_T("\\systemroot\\system32"), objSystem.GetSystemDir());
					else
					{
						m_csData.Replace(_T("%systemroot%"), objSystem.GetWindowsDir());
						m_csData.Replace(_T("%windir%"),objSystem.GetWindowsDir());
					}
					bVerInfo = objVerInfo.DoTheVersionJob(m_csData,false);
					m_csData = m_csData + _T(" #@# ") + GetSignature(m_csData) + _T(" #@# ") + GetExecSignature(m_csData);
					if(bVerInfo)
						m_csData = m_csData + _T(" #@# true");
					else
						m_csData = m_csData + _T(" #@# false");

				}
			}
			else if(csType == _T(" | SD30 | Drivers :"))
			{
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("SYSTEM\\CurrentControlSet\\Services\\") +csVal,_T("ImagePath"),m_csData,HKEY_LOCAL_MACHINE);
				if(m_csData == BLANKSTRING || m_csData.Right(4).MakeLower() != _T(".sys"))
				{
					csVal = BLANKSTRING; // for skipping this entries
					m_csData = BLANKSTRING; // for skipping this entries
				}
				if(m_csData != BLANKSTRING)
				{
					GetLongPathName(m_csData.GetBuffer(MAX_PATH),m_csData.GetBuffer(MAX_FILE_PATH),MAX_FILE_PATH);
					m_csData.ReleaseBuffer();
					CFileVersionInfo objVerInfo;
					bool bVerInfo = false;
					CCPUInfo objSystem;
					m_csData.MakeLower();
					if(m_csData.Left(9).CollateNoCase(L"system32\\") == 0)
						m_csData.Replace(_T("system32"), objSystem.GetSystemDir());
					else if(m_csData.Left(21).CollateNoCase(L"\\systemroot\\system32\\") == 0)
						m_csData.Replace(_T("\\systemroot\\system32"), objSystem.GetSystemDir());
					else
					{
						m_csData.Replace(_T("%systemroot%"), objSystem.GetWindowsDir());
						m_csData.Replace(_T("%windir%"),objSystem.GetWindowsDir());
					}
					bVerInfo = objVerInfo.DoTheVersionJob(m_csData,false);
					m_csData = m_csData + _T(" #@# ") + GetSignature(m_csData) + _T(" #@# ") + GetExecSignature(m_csData);
					if(bVerInfo)
						m_csData = m_csData + _T(" #@# true");
					else
						m_csData = m_csData + _T(" #@# false");

				}
			}
			else if(csType == _T(" | SD11 | Advance Option :"))
			{
				m_csData=BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\") +csVal,_T("Text"),m_csData,HKEY_LOCAL_MACHINE);
			}
			else if(csType == _T(" | SD24 | Uninstall :"))
			{
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\") +csVal,_T("DisplayName"),m_csData,HKEY_LOCAL_MACHINE);
				if(m_csData == BLANKSTRING)
					csVal = BLANKSTRING; // for skipping this entries
				else
				{
					csName = BLANKSTRING;
					m_objReg.Get(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\") +csVal,_T("UninstallString"),csName,HKEY_LOCAL_MACHINE);
					if(csName != BLANKSTRING)
					{
						GetLongPathName(csName.GetBuffer(MAX_PATH),csName.GetBuffer(MAX_PATH),MAX_PATH);
						csName.ReleaseBuffer();
						m_csData = m_csData + _T(" #@# ") + csName + _T(" #@# ") + GetSignature(csName) + _T(" #@# ") + GetExecSignature(csName);
					}

				}

			}
			else if(csType == _T(" | SD28 | Desktop Components :"))
			{
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\Desktop\\Components\\") +csVal,_T("Source"),m_csData,HKEY_CURRENT_USER);

			}
			else if(csType == _T(" | SD20 | Winlogon :"))
			{
				m_csData = BLANKSTRING;
				m_objReg.Get(REG_NOTIFY_ENTRY + csVal,_T("DllName"),m_csData,HKEY_LOCAL_MACHINE);
			}
			else if(csType == _T(" | OD2 | BHO :") || csType == _T(" | OD3 | ToolBar :")
				|| csType == _T(" | SD3 | URL search Hook :") || csType == _T(" | SD21 | SSODL :")
				|| csType == _T(" | SD22 | SharedTaskScheduler :"))
			{
				if(csType == _T(" | SD21 | SSODL :"))
				{
					csName = csVal;
					csVal = m_csData;
				}
				else if(csType == _T(" | SD22 | SharedTaskScheduler :"))
				{
					csName = m_csData;
				}
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Classes\\CLSID\\") +csVal+_T("\\InprocServer32"),BLANKSTRING,m_csData,HKEY_LOCAL_MACHINE);
				if(m_csData == BLANKSTRING)
					m_csData = _T("(No File)");
				else
				{
					CFileFind fFile;
					if(fFile.FindFile(m_csData) == TRUE)
					{
						fFile.FindNextFile();
						m_csData = fFile.GetFilePath();
						m_csData = m_csData + _T(" #@# ") + GetSignature(m_csData) + _T(" #@# ") + GetExecSignature(m_csData);
					}
					else
						m_csData = m_csData + _T(" #@# (File not found)");
				}
				if(csType == _T(" | SD3 | URL search Hook :"))
				{
					if(csVal.Find(_T("_")) == -1)

					{
						csVal = BLANKSTRING;
					}
					else
					{
						CString csName = BLANKSTRING;
						m_objReg.Get(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved"),csVal,csName,HKEY_LOCAL_MACHINE);
						if(csName == BLANKSTRING)
						{
							csName = _T("(No Name)");
						}
						csVal = csName + _T(" #@# ") + csVal;
					}
				}
				if(csType == _T(" | SD21 | SSODL :"))
				{
					m_csData = csName + _T(" #@# ") + m_csData;
				}
				if(csType == _T(" | SD22 | SharedTaskScheduler :"))
				{
					csVal =  csName + _T(" #@# ") + csVal;
				}
			}
			else if(csType == _T(" | SD9 | Extra :") || csType == _T(" | SD9 | Extra Button :") || csType == _T(" | SD9 | Extra Menu :"))
			{
				CString csName = BLANKSTRING;
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\") +csVal,_T("ButtonText"),m_csData,HKEY_LOCAL_MACHINE);
				if(m_objReg.Get(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\") +csVal,_T("Exec"),csName,HKEY_LOCAL_MACHINE))
				{
					if(csName != BLANKSTRING)
						m_csData = m_csData + _T(" #@# ") + csName;
				}
				else
				{
					m_objReg.Get(_T("SOFTWARE\\Classes\\CLSID\\") +csVal+_T("\\InprocServer32"),BLANKSTRING,csName,HKEY_LOCAL_MACHINE);
					if(csName != BLANKSTRING)
					{
						GetLongPathName(csName.GetBuffer(MAX_FILE_PATH),csName.GetBuffer(MAX_FILE_PATH),MAX_FILE_PATH);
						csName.ReleaseBuffer();
						m_csData = m_csData + _T(" #@# ") + csName;
					}
				}
				if(m_csData != BLANKSTRING)
				{
					m_objFileOps.WriteLog (_T("\n"));
					csType = _T(" | SD9 | Extra Button :");
					CString csStr = csVal + _T(" #@# ") +  m_csData;

					csData1 = csType + _T(" ->> ") + csStr;
					m_objFileOps.WriteLog (csData1);
				}

				m_csData = BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\") +csVal,_T("Menutext"),m_csData,HKEY_LOCAL_MACHINE);
				if(m_objReg.Get(_T("SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\") +csVal,_T("Exec"),csName,HKEY_LOCAL_MACHINE))
				{
					if(csName != BLANKSTRING)
						m_csData = m_csData + _T(" #@# ") + csName;
				}
				else
				{
					m_objReg.Get(_T("SOFTWARE\\Classes\\CLSID\\") +csVal+_T("\\InprocServer32"),BLANKSTRING,csName,HKEY_LOCAL_MACHINE);
					if(csName != "")
					{
						GetLongPathName(csName.GetBuffer(MAX_FILE_PATH),csName.GetBuffer(MAX_FILE_PATH),MAX_FILE_PATH);
						csName.ReleaseBuffer();
						m_csData = m_csData + _T(" #@# ") + csName;
					}
				}
				if(m_csData != BLANKSTRING)
				{
					csType = _T(" | SD9 | Extra Menu :");

				}
				else
				{
					csVal = BLANKSTRING;
				}

			}
			else if(csType == _T(" | SD16 | Activex :"))
			{
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Microsoft\\Code Store Database\\Distribution Units\\") +csVal+_T("\\DownloadInformation"),_T("CODEBASE"),m_csData,HKEY_LOCAL_MACHINE);
				if(m_csData == BLANKSTRING)
				{
					m_csData = _T("Unknown");
				}
				CString csFileName = BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Classes\\CLSID\\") +csVal+_T("\\InprocServer32"),BLANKSTRING,csFileName,HKEY_LOCAL_MACHINE);
				if(csFileName != BLANKSTRING)
				{
					GetLongPathName(csFileName.GetBuffer(MAX_FILE_PATH),csFileName.GetBuffer(MAX_FILE_PATH),MAX_FILE_PATH);
					csFileName.ReleaseBuffer();
					m_csData = csFileName + _T(" #@# ") + m_csData;
				}

				CString csName = BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Classes\\CLSID\\") +csVal,BLANKSTRING,csName,HKEY_LOCAL_MACHINE);
				if(csName != BLANKSTRING)
				{
					csVal = csName + _T(" #@# ") + csVal;
				}
				if(csName == "")
				{
					csVal = csName + _T(" #@# ") + csVal;
				}
			}
			else if(csType == _T(" | SD8 | Extra context menu item :"))
			{
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("Software\\Microsoft\\Internet Explorer\\MenuExt\\") +csVal,BLANKSTRING,m_csData,HKEY_CURRENT_USER);
			}
			else if(csType == _T(" | SD29 | Installed Components :"))
			{
				m_csData=BLANKSTRING;
				m_objReg.Get(_T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\") +csVal,_T("StubPath"),m_csData,HKEY_LOCAL_MACHINE);
				if(m_csData == BLANKSTRING)
					csVal = BLANKSTRING;
			}
			else if(csType == _T(" | SD10 | Winsock :"))
			{
				m_csData = BLANKSTRING;
				m_objReg.Get(_T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\") +csVal,_T("LibraryPath"),m_csData,HKEY_LOCAL_MACHINE);
			}

			else if(csType == _T(" | SD15 | Trusted Zone :"))
			{
				m_csData = _T("*");
				DWORD dwData;
				m_objReg.Get(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\") +csVal,_T("http"),dwData);
				if(dwData == 2)
				{
					CString csStr = csVal + _T(" #@# ") +  m_csData;
					m_csData = csType + _T(" ->> ") + csStr;
					m_csData +=_T("\n");
				}
				dwData = 0;
				m_csData = _T("Related");
				m_objReg.Get(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\") +csVal+_T("\\related"),_T("http"),dwData);
				if(dwData != 2)
				{
					csVal = BLANKSTRING;
				}

			}
			else if(csType == _T(" | SD17 | TCPIP :"))
			{
				m_csData=BLANKSTRING;
				m_objReg.Get(_T("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\") +csVal,_T("NameServer"),m_csData,HKEY_LOCAL_MACHINE);
				if(m_csData == BLANKSTRING)
				{
					csVal = BLANKSTRING;
				}
				else
				{
					m_csData = _T("NameServer ") + m_csData;
				}
			}
			else if(csType == _T(" | SD4 | Global startup :") || csType == _T(" | SD4 | Startup :"))
			{
				m_csData = GetShortcutTarget(csVal);
				m_csData = m_csData + _T(" #@# ") + GetSignature(m_csData) + _T(" #@# ") + GetExecSignature(m_csData);
			}
			else if(csType == _T(" | SD31 | Program Files :") || csType == _T(" | SD31 | Program Data :") || csType == _T(" | SD31 | Program Filesx86 :"))
			{
				m_csData = GetSignature(m_csData) + _T(" #@# ") + GetExecSignature(m_csData);
			}

			if(csVal!=BLANKSTRING)
			{
				csData1 =csVal;// m_objStringArray.GetAt(i);
				csData1 +=_T(" #@# ");
				csData1 = _T("\n") + csType + _T(" ->> ") + csData1;
				csData1 +=m_csData;
				m_objFileOps.WriteLog (csData1); //Write in the log file
			}

			INT_PTR iC=m_objStringArray.GetCount();
			if(i == (iC-1) && csVal!=BLANKSTRING)
				m_objFileOps.WriteLog (_T("\n")); //Go to next line in  the log file

			if(i == (iC-1) &&(csType == _T(" | SD23 | Services :") || csType == _T(" | SD30 | Drivers :") ||csType == _T(" | SD29 | Installed Components :")))
				m_objFileOps.WriteLog (_T("\n")); //Go to next line in  the log file

		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::WriteRegistryLog"));
	}
}//End of WriteRegistryLog Function()

/*-------------------------------------------------------------------------------------
Function		: GetShortcutTarget()
In Parameters	: const CString LinkFileName
Out Parameters	: CString-return source file name
Purpose			: get source filename of the target(.lnk,.pif)filename
Author			: Sandip Sanap
Created Date	: 23-09-2006
--------------------------------------------------------------------------------------*/
CString CHijackLog::GetShortcutTarget(const CString LinkFileName)
{
	// get source filename of the target(.lnk,.pif)filename
	try
	{
		HRESULT hres;
		CString Link, Temp = LinkFileName;
		Temp.MakeLower();
		if(Temp.Find(_T(".lnk")) == -1 && Temp.Find(_T(".pif")) == -1)//Check if the name ends with.lnk
			Link = LinkFileName + _T(".lnk"); //if not, append it
		else
			Link = LinkFileName;

		CString Info;
		Info.Empty();

		IShellLink* ipShellLink;
		//Create the ShellLink object
		hres = CoInitialize(NULL);
		COINITIALIZE_OUTPUTDEBUGSTRING(hres);
		hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&ipShellLink);
		COCREATE_OUTPUTDEBUGSTRING(hres);
		if(SUCCEEDED(hres))
		{
			IPersistFile* ipPersistFile;
			//Bind the ShellLink object to the Persistent File
			hres = ipShellLink->QueryInterface(IID_IPersistFile, (LPVOID *)&ipPersistFile);
			if(SUCCEEDED(hres))
			{
				//Read the link into the persistent file
				hres = ipPersistFile->Load((LPCOLESTR)Link, 0);
				if(SUCCEEDED(hres))
				{
					// Try to find the target of a shortcut,
					// even if it has been moved or renamed
					//SLR_UPDATE |
					hres = ipShellLink->Resolve(NULL, SLR_NO_UI |SLR_NOUPDATE |SLR_NOSEARCH);
					if(SUCCEEDED(hres))
					{
						// Get the path to the shortcut target
						hres = ipShellLink->GetPath(Temp.GetBuffer(1024), 1024, NULL, SLGP_UNCPRIORITY);
						if(FAILED(hres))
						{
							CoUninitialize();
							return BLANKSTRING;
						}
					}
					Temp.ReleaseBuffer();
					Info = Temp;
				}
			}
		}
		ipShellLink->Release();
		//Return the Target and the Argument as a CString
		CoUninitialize();
		return Info;
	}
	catch(...)
	{
	}
	return BLANKSTRING;
} //End of GetShortcutTerget()Function

void CHijackLog::PreparePESignature(WCHAR *wcsPESig, LPBYTE lpSignature)
{
	swprintf_s(wcsPESig, 20, L"%02x%02x%02x%02x%02x%02x%02x%02x", 
		lpSignature[0], lpSignature[1], lpSignature[2], lpSignature[3],
		lpSignature[4], lpSignature[5], lpSignature[6], lpSignature[7]);
}

void CHijackLog::PrepareFileSigForLog(WCHAR *wcsFileSig, int iLenOfbuffer, LPCWSTR filePath)
{
	DTL_FINFO FileInfo = {0};

	if(!m_pobjFileSig)
	{
		m_pobjFileSig = new CFileSig;
		if(!m_pobjFileSig)
		{
			return;
		}
	}

	if(SIG_STATUS_PE_SUCCESS != m_pobjFileSig->CreateSignature(filePath, FileInfo))
	{
		return;
	}

	memset(wcsFileSig, 0, sizeof(WCHAR) * iLenOfbuffer);
	swprintf_s(wcsFileSig, iLenOfbuffer, L"MD5: %S, 15MBMD5CRC: %016I64x, Sig: %016I64x", 
		FileInfo.szMD5, FileInfo.ul15MBFileMD5, FileInfo.ulSignature);
}

/*-------------------------------------------------------------------------------------
Function		: GetSignature()
In Parameters	: CString csFilePath
Out Parameters	: CString
Purpose			: get  filepath of the target filename
Author			: Sandip Sanap
Created Date	: 23-09-2006
--------------------------------------------------------------------------------------*/
CString CHijackLog::GetSignature(CString csFilePath)
{
	try
	{
		WCHAR szSignatureString[MAX_PATH] = {0};
		CDBPathExpander objPathExp;
		CString csReturn = BLANKSTRING, csResolvedPath;

		csFilePath.MakeLower();
		if((BLANKSTRING == csFilePath) || (-1 != csFilePath.Find(L"rundll32")))
		{
			return BLANKSTRING;
		}

		// resolve the path name from registry
		csFilePath = objPathExp.ExpandSystemPath(csFilePath, true);
		m_objRegPathExp.DoesFileExist(csFilePath);
		csResolvedPath = m_objRegPathExp.m_csFileFound;

		PrepareFileSigForLog(szSignatureString, _countof(szSignatureString), csResolvedPath);
		csReturn = szSignatureString;
		return csReturn;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSignature"));
	}

	return BLANKSTRING;
}	//End of GetSignature function

/*-------------------------------------------------------------------------------------
Function		: LoadSignatureDll()
In Parameters	:
Out Parameters	: bool
Purpose			: load signaturescanner.dll
Author			: Dipali Pawar
Created Date	: 12-May-2008
--------------------------------------------------------------------------------------*/
bool CHijackLog::LoadSignatureDll()
{
	m_hSigScanDLL =  ::LoadLibrary(L"SignatureScanner.dll");
	if(!m_hSigScanDLL)
	{
		AddLogEntry(L"SignatureScanner.dll Load fail in CHijackLog::GetEPSignature");
		return false;
	}
	GetEPSignature = (EPSIGPROC)GetProcAddress(m_hSigScanDLL, "GetEPSignature");
	if(!GetEPSignature)
	{
		::FreeLibrary(m_hSigScanDLL);
		m_hSigScanDLL = NULL;
		return false;
	}
	LoadExecInfoDb = (LOADDB)GetProcAddress(m_hSigScanDLL, "LoadExecInfoDb");
	if(!LoadExecInfoDb)
	{
		::FreeLibrary(m_hSigScanDLL);
		m_hSigScanDLL = NULL;
		return false;
	}
	UnloadExecInfoDb = (UNLOADDB)GetProcAddress(m_hSigScanDLL, "UnloadExecInfoDb");
	if(!UnloadExecInfoDb)
	{
		::FreeLibrary(m_hSigScanDLL);
		m_hSigScanDLL = NULL;
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: UnloadSignatureDll()
In Parameters	: -
Out Parameters	: -
Purpose			: Unload SignatureScanner.Dll
Author			: Dipali Pawar
Created Date	: 12-May-2008
--------------------------------------------------------------------------------------*/
void CHijackLog::UnloadSignatureDll()
{
	UnloadExecInfoDb();
	if(m_hSigScanDLL)
	{
		::FreeLibrary(m_hSigScanDLL);
		m_hSigScanDLL = NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetEPSignature()
In Parameters	: CString csFilePath
Out Parameters	: CString
Purpose			: get  filepath of the target filename
Author			: Dipali Pawar
Created Date	: 12-May-2008
--------------------------------------------------------------------------------------*/
CString CHijackLog::GetExecSignature(CString csFilePath)
{
	// all the code from this function is moved to 'GetSignature'
	// so that we get all the info by opening the file once only
	return BLANKSTRING;

}//End of GetSignature function

/*-------------------------------------------------------------------------------------
Function		: GetFilesFromFolder
In Parameters	: CString csFolderPath
Out Parameters	: -
Purpose			: Get files from given passing Folder path
Author			: Sandip Sanap
Created Date	: 23-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog::GetFilesFromFolder(CString csFolderPath)
{
	try
	{
		csFolderPath.TrimLeft(); csFolderPath.TrimRight();
		if(csFolderPath.GetLength() == 0)
			return;
		csFolderPath += _T("\\*.*");
		CFileFind finder;
		if(!finder.FindFile(csFolderPath.GetBuffer(csFolderPath.GetLength())))
		{
			//Added By Nilesh Dorge Bec.Of Memory Leak On 5th Aug.
			finder.Close();
			return;
		}
		csFolderPath.ReleaseBuffer();

		BOOL bRet = TRUE;
		while(bRet)
		{
			bRet = finder.FindNextFile();
			if(finder.IsDots())
				continue;

			if(finder.IsDirectory())// if it's a directory, recursively search it
			{
				this->GetFilesFromFolder(finder.GetFilePath());
			}
			else
			{
				CString csPath = finder.GetFilePath();
				m_objStringArray.Add (csPath  + _T(" #@# "));
			}
		}
		//Added By Nilesh Dorge Bec.Of Memory Leak
		finder.Close();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetFilesFromFolder"));
	}
} //End of GetFilesFromFolder()Function

/*-------------------------------------------------------------------------------------
Function		: GetHeaderHijackLog()
In Parameters	: -
Out Parameters	: -
Purpose			: Make the header of Log file by geting various System value like
Date,Pc Name,Os Versioncs,ProductVer,DatabaseVer,ComplexSpyVer,InformationVer etc;
Author			: Sandip Sanap
Created Date	: 27-09-2006
--------------------------------------------------------------------------------------*/
void CHijackLog ::GetHeaderHijackLog()
{
	CString csTemp;
	//Check Product Version Not Empty
	m_objFileOps.WriteLine();
	if(m_csProductVer!=_T(""))
	{	
		csTemp+=_T("\nProduct Version           :	");
		csTemp+=m_csProductVer;
	}
	//Check Database Version Not Empty
	if(m_csDatabaseVer!=_T(""))
	{
		csTemp+=_T("\nDatabase Version	  :	");
		csTemp+=m_csDatabaseVer;
	}
	//Check ComplexSpy Version not Empty
	if(m_csComplexSpyVer!=_T(""))
	{
		csTemp+=_T("\nComplexSpy Version	  :	");
		csTemp+=m_csComplexSpyVer;
	}
	//Check Information Version Not Empty
	if(m_csInformationVer!=_T(""))
	{
		csTemp+=_T("\nInformation Version	  :	");
		csTemp+=m_csInformationVer;
	}
	//Check Generic Keylogger Version Not Empty
	if(m_csGenKeylogVer !=_T(""))
	{
		csTemp+=_T("\nGeneric Keylogger Version :	");
		csTemp+=m_csGenKeylogVer;
	}
	if(m_csVirusVer !=_T(""))
	{
		csTemp+=_T("\nVirus Version :	");
		csTemp+=m_csVirusVer;
	}
	if(m_csFirstPriVer !=_T(""))
	{
		csTemp+=_T("\nFirst Priority Version :	");
		csTemp+=m_csFirstPriVer;
	}
	//Check Generic Keylogger Version Not Empty
	if(m_csRootkitremVer !=_T(""))
	{
		csTemp+=_T("\nRootkit Remover Version	  :	");
		csTemp+=m_csRootkitremVer;
		csTemp+=_T("\n");
	}
	if(m_csUpdateVersion != _T(""))
	{
		csTemp+=_T("\nUpdate Version	  :	");
		csTemp+=m_csUpdateVersion;
		csTemp+=_T("\n");
	}
	m_objFileOps.WriteLog(csTemp); //Write information like Date,Pc Name, Os Version,Database Version Etc in HijackLog File
	m_objFileOps.WriteLine();
}

void CHijackLog ::GetSD31()
{
	try
	{
		CRegistry objReg;

		m_csData = BLANKSTRING;
		CCPUInfo objInfo;
		CString csProgramFilePath = _T("");
		csProgramFilePath = objInfo.GetProgramFilesDir();
		this->GetFilesFromProgramFilesFolder(csProgramFilePath);
		WriteRegistryLog(_T(" | SD31 | Program Files :"));//Write program files information in the Log File
		m_objStringArray.RemoveAll();

		m_csData = BLANKSTRING;
		CString csAppDataPath = _T("");
		CString csPath = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders");
		CString csAppData = _T("Common AppData");
		if(!objReg.Get(csPath, csAppData, csAppDataPath, HKEY_LOCAL_MACHINE))
		{
			AddLogEntry(_T("Path not found"));
		}
		this->GetFilesFromProgramFilesFolder(csAppDataPath);
		WriteRegistryLog(_T(" | SD31 | Program Data :"));
		m_objStringArray.RemoveAll();

		m_csData = BLANKSTRING;
		CString szPath(_T("C:\\Program Files (x86)"));
		this->GetFilesFromProgramFilesFolder(szPath);
		WriteRegistryLog(_T(" | SD31 | Program Filesx86 :"));//Write program files information in the Log File
		m_objStringArray.RemoveAll();
		

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetSD31"));
	}
}

void CHijackLog ::GetFilesFromProgramFilesFolder(CString csFolderPath)
{
	try
	{
		
		csFolderPath.TrimLeft(); csFolderPath.TrimRight();
		if(csFolderPath.GetLength() == 0)
			return;
		csFolderPath += _T("\\*.*");
		CFileFind finder;
		if(!finder.FindFile(csFolderPath.GetBuffer(csFolderPath.GetLength())))
		{
			//Added By Nilesh Dorge Bec.Of Memory Leak On 5th Aug.
			csFolderPath.ReleaseBuffer();
			finder.Close();
			return;
		}
		csFolderPath.ReleaseBuffer();

		BOOL bRet = TRUE;
		while(bRet)
		{
			bRet = finder.FindNextFile();
			if(finder.IsDots())
				continue;

			if(finder.IsDirectory())// if it's a directory, recursively search it
			{
				if(CheckDirectory(finder.GetFilePath()) == true)
				{
					this->GetFilesFromProgramFilesFolder(finder.GetFilePath());
				}
			}
			else
			{
				CString csPath = finder.GetFilePath();
				if(!CheckValidCompanyName(csPath))
				{
					m_objStringArray.Add (csPath /* + _T(" #@# ")*/);
				}
			}
		}
		//Added By Nilesh Dorge Bec.Of Memory Leak
		finder.Close();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetFilesFromFolder"));
	}
} //End ofGetFilesFromProgramFilesFolder()Function

bool CHijackLog ::CheckDirectory(CString csFolderPath)
{
	try
	{
		int iDirectoryCount = 0;
		int iFilesCount = 0;
		csFolderPath.TrimLeft(); csFolderPath.TrimRight();
		if(csFolderPath.GetLength() == 0)
			return false;
		csFolderPath += _T("\\*.*");
		CFileFind finder;
		if(!finder.FindFile(csFolderPath.GetBuffer(csFolderPath.GetLength())))
		{
			//Added By Nilesh Dorge Bec.Of Memory Leak On 5th Aug.
			csFolderPath.ReleaseBuffer();
			finder.Close();
			return false;
		}
		csFolderPath.ReleaseBuffer();

		BOOL bRet = TRUE;
		while(bRet)
		{
			bRet = finder.FindNextFile();
			if(finder.IsDots())
				continue;

			if(finder.IsDirectory())// if it's a directory, recursively search it
			{
				iDirectoryCount++;
			}
			else
			{
				iFilesCount++;
			}
			if(iDirectoryCount >= 2 || iFilesCount > 6)
			{
				finder.Close();
				return false;
			}
		}

		//Added By Nilesh Dorge Bec.Of Memory Leak
		finder.Close();
		if(iDirectoryCount < 2 || iFilesCount <= 6)
		{
			return true;
		}
		
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHijackLog::GetFilesFromFolder"));
	}
	return false;
}

bool CHijackLog ::CheckValidCompanyName(CString csPath)
{
	CFileVersionInfo objFileInfo;
	LPCTSTR szFilePath;
	TCHAR szCompanyName[MAX_PATH] = {0};
	szFilePath = (LPCTSTR)csPath;

	if(!objFileInfo.GetCompanyName(szFilePath, szCompanyName))
	{
		return false;
	}

	_tcslwr_s(szCompanyName, _countof(szCompanyName));
	if(!_tcsstr(szCompanyName, _T("microsoft")))
	{
		return false;
	}

	return true;
}



