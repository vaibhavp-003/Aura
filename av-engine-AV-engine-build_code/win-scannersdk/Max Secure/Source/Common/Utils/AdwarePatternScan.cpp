/*======================================================================================
   FILE				: AdwarePatternScan.cpp
   ABSTRACT			: Model responsible for Adware scanning 
   DOCUMENTS		: 
   AUTHOR			: Tushar Kadam
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 22 Jul 2010
   NOTES			: This module searches and detects Adwares using Pattern and Rules
   VERSION HISTORY	: 
=====================================================================================*/
#pragma once
#include "pch.h"
#include "AdwarePatternScan.h"
#include "VerInfo.h"
#include <fstream>
#include <string>
#include <iostream>
#include <shlwapi.h>
#include "EnumProcess.h"
#include "DirectoryManager.h"


using namespace std;
///array for names after removing more then one continious occurences of alpabets,vowels and numbers
//Note:Use when many folders present which have  pattern like (PRiceeLesse/ Priceless/PriiceLess)or (9wdsmanpro9/bwdsmanprob/fwdsmanprof)

TCHAR	szBlackList[][40] = {
	_T("\\dsrchlnk"),
	_T("\\cthprc"), 
	_T("\\prcls"),
	_T("\\cnmplscv"), 
	_T("\\grtsvu"), 
	_T("\\nyprtctx"),
	_T("\\hpysv"), 
	_T("\\gmsdjp"), 
	_T("\\grtsv"), 
	_T("\\mnmprc"), 
	_T("\\nzbrws"), 
	_T("\\pgptp"), 
	_T("\\slpls"), 
	_T("\\svlt"), 
	_T("\\svrxtnsn"),
	_T("\\gmsdn"), 
	_T("\\ctvdlscpntm"), 
	_T("\\gmrsdsktp"),
	_T("\\jncpn"),
	_T("\\cnmplsvbrwsrxtnsnstl"),
	_T("\\nrmsls"),
	_T("\\syscpn"),
	_T("\\bstdblckr"),
	_T("\\cplsvbrwsrxtns"),
	_T("\\ldysl"),		
	_T("\\cnmpls"),
	_T("\\hlthlrt"),
	_T("wdsmnpr"),
	_T("\\dblckr"),
	_T("\\brkngnwslrt"),
	_T("\\brwsrdfndr"),
	_T("\\hlthlrt"),
	_T("\\hprtctpdt"),
	_T("\\lhpmpfcjpfjhjcdkpcmpflmpn"),
	_T("\\gmsdsktp"),
	_T("\\rgclnpr"),
	_T("\\spdbtvdwnldr"),
	_T("\\wntrntn"),
	_T("\\mysrch"),
	_T("\\ntngn"),
	_T("\\spdbt"),
	_T("\\trmnstlr"),
	_T("\\txmpc"),
	_T("\\wndwsmngrprtct"),
	_T("\\wndwsprtctmngr"),
	_T("\\ylwdblckr"),
	//_T("\\ytdvdwnldr"),
	_T("\\btsvr"),
	_T("\\spcsndpr"),
	_T("\\spcsndprv"),
	_T("\\plshdpv"),
	_T("\\plshd"),
	_T("\\hpysv"),
	_T("\\cpxtnsn"),
	_T("\\rlrcstrprk"),
	_T("\\svps"),
	_T("\\svsns"),
	_T("\\dgcpn"),
	_T("\\dscvrtrsr"),
	_T("\\dnsnlckr"),
	_T("\\lxtch"),
	_T("\\fdntfr"),
	_T("\\glblpdt"),
	_T("\\skprtnrntwrk"),
	_T("\\vgsfgrdtlbr"),
	_T("\\vgscrsrch"),
	_T("\\grntrplctns"),
	_T("\\gplyr"),
	_T("\\jgtmp"),
	_T("\\mgclfnd"),
	_T("\\mtcrwlr"),
	_T("\\mnmmprc"),
	_T("\\myscrpnk"),
	_T("\\pybyds"),
	_T("\\rydld"),
	_T("\\srchprdct"),
	_T("\\shpndsvp"),
	_T("\\shprpr"),
	_T("\\shprz"),
	_T("\\snctrn"),
	_T("\\spdbtvdwnldr"),
	_T("\\thmsngjsnnspctr"),
	_T("\\wntrntn"),
	_T("\\wndwssrchqtlbr"),
	_T("\\brkngnwslrt"),
	_T("\\lpkhkcgmgkdglfnfnfhflk"),
	_T("\\hlthlrt"),
	_T("\\mlwrprtctnlv"),
	_T("\\spdbrwsr"),
	_T("\\mtcrwlr"),
	_T("\\prcgng"),
	_T("\\smrtwb"),
	_T("\\spdbt"),
	_T("\\wbprtctr"),
	_T("\\nyprtctx"),
	_T("\\lxtch"),
	_T("\\mtcrwlr"),
	_T("\\mystrtsrch"),
	_T("\\pncndy"),
	_T("\\rsrfng"),
	_T("\\pcxvwr"),
	_T("\\shrtctstr"),
	_T("\\systwk"),
	_T("\\wbxtnd"),
	_T("\\wbsrchs"),
	_T("\\pncndy"),
	_T("\\skprtnrntwrk"),
	_T("\\srchprtct"),
	_T("\\smplfls"),
	_T("\\shprpr"),
	_T("\\spdbt"),
	_T("\\bnsrchltd"),
	_T("\\nyprtctx"),
	_T("\\jgtmp"),
	_T("\\prcmtér"),
	_T("\\svsns"),
	_T("\\spcsndpr"),
	_T("\\vpckg"),
	_T("\\mystrtsrch"),
	_T("\\pncndy"),
	_T("\\slvsft"),
	_T("\\vpckg"),
	_T("\\brwsrhlpr"),
	_T("\\smrtwb"),
	_T("\\systbyhtwhl"),
	_T("\\smrtwb"),
	_T("\\qyvd"),
	_T("\\jgtmp"),
	_T("\\mystrtsrch"),
	_T("\\trvlchp"),
	_T("\\rvlchp"),
	_T("\\mybrwsrv")
};

//array for hardcoded paths
TCHAR	szBlackListHardcodedPath[][80] = {

	_T("c:\\breakingnewsalert"),
	_T("c:\\conduit"),
	_T("c:\\healthalert"),
	_T("c:\\iqiyi video"),
	_T("c:\\searchprotect"),
	_T("c:\\programdata\\apn"),
	_T("c:\\programdata\\~0"),
	_T("c:\\users\\public\\public documents\\shopperpro"),
	_T("c:\\users\\public\\public documents\\speedbit"),
	_T("c:\\programdata\\browser"),
	_T("c:\\documents and settings\\all users\\application data\\browser"),
	_T("c:\\programdata\\esafe"),
	_T("c:\\programdata\\df4f3a237ae8fe3f"),
	_T("c:\\programdata\\microsoft\\windows\\start menu\\programs\\uc"),
	_T("c:\\windows\\system32\\tasks\\asp"),
	_T("c:\\windows\\system32\\tasks\\metacrawler"),
	_T("c:\\users\\public\\documents\\shopperpro"),
	_T("c:\\users\\public\\documents\\speedbit"),
	_T("c:\\windows\\system32\\tasks\\netengine"),
	_T("c:\\windows\\assembly\\gac_msil\\quickstorestoolbar"),
	_T("c:\\windows\\installer\\{86d4b82a-abed-442a-be86-96357b70f4fe}"),
	_T("c:\\windows\\sysnative\\tasks\\dsite"),
	_T("c:\\windows\\sysnative\\tasks\\searchya"),
	_T("c:\\ods.exe.config"),
	_T("c:\\ods.exe"),
	_T("c:\\windows\\system32\\tasks\\wintaske"),
	_T("c:\\windows\\sysnative\\drivers\\bsdriver.sys"),
	_T("c:\\windows\\sysnative\\drivers\\bsdriver.sys"),
	_T("c:\\windows\\sysnative\\drivers\\cherimoya.sys"),
	_T("c:\\windows\\system32\\config\\systemprofile\\appdata\\roaming\\tencent"),
	_T("c:\\windows\\system32\\tasks\\wintaske"),
	_T("c:\\windows\\system32\\tasks\\regclean pro"),
	_T("c:\\windows\\system32\\config\\systemprofile\\appdata\\local\\speed browser"),
	_T("c:\\windows\\system32\\tasks\\regclean pro"),
	_T("c:\\windows\\system32\\tasks\\hnaluefnowu"),
	_T("c:\\windows\\syswow64\\config\\systemprofile\\appdata\\local\\ysearchutil"),
	_T("c:\\windows\\system32\\config\\systemprofile\\appdata\\local\\speed browser"),
	_T("c:\\windows\\system32\\config\\systemprofile\\appdata\\local\\askpartnernetwork")



};

TCHAR	szBlackListFolderName[][50] = {
	_T("\\{01c47a4a 1064 0}"),
	_T("\\{0a954ecd 7190 1}"),
	_T("\\{211f7dd3 7961 4deb 211f f7dd3796f74d}"),
	_T("\\{262e20b8 6e20 4cef b1fd d022ab1085f5}.dat"),
	_T("\\{3620b9a0 4064 1}"),
	_T("\\{366e26bc 5190 0}"),
	_T("\\{86d4b82a abed 442a be86 96357b70f4fe}"),
	_T("\\{d2020d47 707d 4e26 b4d9 739c4f4c2e9a}"),
	_T("\\{f200cbb7 b502 567f f200 0cbb7b502ede}"),
	_T("\\03000200 1455632996 0500 0006 000700080009"),
	_T("\\03000200 1455652950 0500 0006 000700080009"),
	_T("\\19a87fa1ec024bbcbb41931263354405"),
	_T("\\1clickdownload"),
	_T("\\4999579983011370290"),
	_T("\\4f596ec3 77fb 4fc3 82cb 691c42c71d77"),
	_T("\\681537d6 1455018014 11e4 98aa 38c7cc922f00"),
	_T("\\681537d6 1455283229 11e4 98aa 38c7cc922f00"),
	_T("\\681537d6 1455620807 11e4 98aa 38c7cc922f00"),
	_T("\\681537d6 1455721745 11e4 98aa 38c7cc922f00"),
	_T("\\681537d6 1455728260 11e4 98aa 38c7cc922f00"),
	_T("\\681537d6 1455790192 11e4 98aa 38c7cc922f00"),
	_T("\\681537d6 1455793781 11e4 98aa 38c7cc922f00"),
	_T("\\681537d6 1455880185 11e4 98aa 38c7cc922f00"),
	_T("\\681537d6 1455893000 11e4 98aa 38c7cc922f00"),
	_T("\\7b0626f7 1455099372 7245 760e 382c4ab6a487"),
	_T("\\8wdm8"),
	_T("\\9a4b8b26 f4e0 4529 a5b4 93ec828f7e42"),
	_T("\\ads remover"),
	_T("\\alfasistem memory"),
	_T("\\apn"),
	_T("\\appverifier"),
	_T("\\ask.com"),
	_T("\\asktoolbar"),
	_T("\\aspackage"),
	_T("\\audiotoaudio_8i"),
	_T("\\b56dff5a df23 4e43 acde a4f08b8dcffb"),
	_T("\\babylon"),
	_T("\\babylontoolbar"),
	_T("\\browser"),
	_T("\\browserair"),
	_T("\\browserhelper"),
	_T("\\c432d246 1452855294 e511 8b16 9457a5041507"),
	_T("\\concom"),
	_T("\\conduit"),
	_T("\\cpuminer"),
	_T("\\crossbrowse"),
	_T("\\crsoft"),
	_T("\\csdimedia"),
	_T("\\date today"),
	_T("\\deletead"),
	//_T("\\delta"),
	_T("\\desktop search"),
	_T("\\digitalsites"),
	_T("\\discover treasure"),
	_T("\\dns unlocker"),
	_T("\\drivertoolkit"),
	_T("\\dsite"),
	_T("\\easyfileopener"),
	_T("\\exploretech"),
	_T("\\exttag"),
	_T("\\exttags"),
	_T("\\fcfenmboojpjinhpgggodefccipikbpd"),
	_T("\\free youtube downloader"),
	_T("\\games desktop"),
	_T("\\gamesdesktop"),
	_T("\\genienext"),
	_T("\\ghjilkklhblehddahbcmeffecdjimkke"),
	_T("\\gmsd_in_005010233"),
	_T("\\gmsd_in_005010239"),
	_T("\\gnibgjlfebpplfgjlppkofepkkcpcgec"),
	_T("\\gohd"),
	_T("\\gophoto.it"),
	//_T("\\greentree applications"),
	_T("\\healthalert"),
	_T("\\hnaluefnowu"),
	_T("\\igfx32"),
	_T("\\ilividbandoomoviestoolbar"),
	_T("\\inbox toolbar"),
	_T("\\inbox.com"),
	_T("\\inetstat"),
	_T("\\install_13182"),
	_T("\\install_27277"),
	_T("\\internet quick access"),
	_T("\\ironsource"),
	_T("\\istartpageing"),
	_T("\\istartsurf"),
	_T("\\jbbnalpbmhligpjbjhccgoenambiljfj"),
	_T("\\mallpejgeafdahhflmliiahjdpgbegpk_dis"),
	_T("\\malwareprotectionlive"),
	_T("\\max driver updater"),
	_T("\\maxdrivrupdater"),
	_T("\\mipony"),
	_T("\\miuitab"),
	_T("\\mobogenie"),
	_T("\\mpc adcleaner"),
	_T("\\mpc cleaner"),
	_T("\\mybrowser"),
	_T("\\mysites123"),
	_T("\\netservice"),
	_T("\\nixsrv"),
	_T("\\onlinevault"),
	_T("\\opencandy"),
	_T("\\ortmp"),
	_T("\\pdf to word converter"),
	_T("\\picexa"),
	_T("\\ppt"),
	_T("\\pragmaedit"),
	_T("\\predm"),
	_T("\\pricefountain"),
	_T("\\quickstorestoolbar"),
	_T("\\raydld"),
	_T("\\rcp"),
	_T("\\reachit"),
	_T("\\rebateinformer"),
	_T("\\rec_en_77"),
	_T("\\rec_in_200"),
	_T("\\regclean pro"),
	_T("\\rheng"),
	_T("\\roaming\aspackage"),
	_T("\\roaming\rpeng"),
	_T("\\rpeng"),
	_T("\\rundir"),
	_T("\\savee eoon"),
	_T("\\search know"),
	_T("\\searchestoyesbnd"),
	_T("\\searchmodule"),
	_T("\\searchya!"),
	_T("\\searchya"),
	_T("\\service1104"),
	_T("\\sfk"),
	_T("\\shopperpro3"),
	_T("\\shopperz150220161452"),
	_T("\\shopperz170220161850"),
	_T("\\shortcutstore"),
	_T("\\showmypcservice"),
	_T("\\simplitec"),
	_T("\\sound+"),
	_T("\\spacesoundpro"),
	_T("\\speed browser"),
	_T("\\speedbit video downloader"),
	_T("\\speedbit"),
	_T("\\super optimizer"),
	_T("\\sw-booster"),
	_T("\\systweak"),
	_T("\\tdatadld"),
	_T("\\tencent"),
	_T("\\thinkupwp"),
	_T("\\tomorrowgames"),
	_T("\\toolbar4"),
	_T("\\toolgets"),
	_T("\\tsearch"),
	_T("\\txqmpc"),
	_T("\\unisalesu"),
	_T("\\vnt"),
	_T("\\vopackage"),
	_T("\\webextend"),
	_T("\\wincert"),
	_T("\\winsere"),
	_T("\\wintaske"),
	_T("\\yellow adblocker"),
	_T("\\yoursearching"),
	_T("\\ysearchutil"),
	//_T("\\ytd video downloader"),
	_T("\\ywdmy")
};

/*-------------------------------------------------------------------------------------
	Function		: CAdwarePatternScan
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CAdwarePatternScan::CAdwarePatternScan(void)
{

}
/*-------------------------------------------------------------------------------------
	Function		: ~CAdwarePatternScan
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detector
--------------------------------------------------------------------------------------*/
CAdwarePatternScan::~CAdwarePatternScan(void)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ScanAdwarePattern
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scans file for all subsequent possible adware pattern
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ScanAdwarePattern(LPCTSTR szFilePath)
{
	bool bInfected = false;

	if(Scan4AdwAmonetizeFolder(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKADWFOLDAMONETIZE: %s", szFilePath);
		return bInfected;

	}

	//Comment Due To False+ Reported BY Dheeraj
	/*
	if(Scan4ExeConfigPattern(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKADWFOLDEXECONFIGPATTERN: %s", szFilePath);
		return bInfected;
	}
	*/

	if(ScanForMegaSearchExtension(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKADWMEGASEARCHPATTERN: %s", szFilePath);
		return bInfected;
	}

	if(ScanForWebSearch(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKADWWEBSEARCHPATTERN: %s", szFilePath);
		return bInfected;
	}
	
	if(ScanAndParseCommon(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKADWMEGASEARCHPATTERNFROMCOMMONSCAN: %s", szFilePath);
		return bInfected;
	}
	//if(Scan4UpdEngine(szFilePath))
	//{
	//	bInfected = true;
	//	AddLogEntry(L"####BLACKADWUPDENGINE: %s", szFilePath);
	//	return bInfected;

	//}

	/*
    if(Scan4FolderPattern(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLACKADWFOLDERPATTERN: %s", szFilePath);
		return bInfected;
	}
	*/

	if (Scan4FOLDEREXENamePattern(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKADWFOLDEXENAMEPATTERN: %s", szFilePath);
		return bInfected;
	}

	/*
	//Commeneted : False +ve Adobe Temp files
	if(Scan4ISTempAndTempPattern(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKADWMISTEMPANDTEMP: %s", szFilePath);
		return bInfected;
	}
	*/
	if(ThreeFilePtrn(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKTHREEFL: %s", szFilePath);
		return bInfected;
	}

	if(CloudNetPtrn(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKCLDNET: %s", szFilePath);
		return bInfected;
	}

	if(GoogleChromePtrn(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKGGLCRMA3X: %s", szFilePath);
		return bInfected;
	}

	return bInfected;

}

/*-------------------------------------------------------------------------------------
	Function		: Scan4AdwAmonetizeFolder
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detection for Amonetize Adware Family
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::Scan4AdwAmonetizeFolder(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR	*pTemp = NULL;


	if (_tcslen(szFilePath) <= 22)
	{
		return bRetStatus;
	}

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr(szDummyFilePath);

	pTemp = _tcsrchr(szDummyFilePath,_T('.'));
	if (pTemp == NULL)
	{
		return bRetStatus;
	}

	if (_tcslen(pTemp) > 0x4 || _tcsstr(pTemp,_T(".exe")) == NULL)
	{
		return bRetStatus;
	}

	*pTemp = '\0';
	pTemp = NULL;

	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szParentFolderName[MAX_PATH] = {0x00};

	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}
	if (! (_tcscmp(szParentFolderName, _T("5vmekbltva6")) || _tcslen(pTemp) != 0xA || _tcslen(pTemp) != 0xB)) // added
	{
		return bRetStatus;
	}
	else 
	{

		_stprintf(szConfigFilePath,L"%s.config",szFilePath);
		if (PathFileExists(szConfigFilePath) == FALSE)
		{
			return bRetStatus;
		}

		pTemp++;
		_tcscpy_s(szFileNameOnly,MAX_PATH,pTemp);
		pTemp--;

		*pTemp = '\0';
		pTemp = nullptr;

		//Folder Path
		pTemp = _tcsrchr(szDummyFilePath,_T('\\'));
		if (pTemp == NULL)
		{
			return bRetStatus;
		}


		pTemp++;
		_tcscpy_s(szParentFolderName,MAX_PATH,pTemp);
		pTemp--;

		int iFileCnt = GetFolderDetails(szDummyFilePath);

		if (iFileCnt == 0x05)
		{
		

			_stprintf(szConfigFilePath,L"%s\\uninstaller.exe",szDummyFilePath);
			if (PathFileExists(szConfigFilePath) == FALSE)
			{
				return bRetStatus;
			}

			_stprintf(szConfigFilePath,L"%s\\uninstaller.exe.config",szDummyFilePath);
			if (PathFileExists(szConfigFilePath) == FALSE)
			{
				return bRetStatus;
			}	


			_stprintf(szConfigFilePath,L"%s.config",szFilePath);
			DeleteFile(szConfigFilePath);

			_stprintf(szConfigFilePath,L"%s\\uninstaller.exe",szDummyFilePath);
			DeleteFile(szConfigFilePath);

			_stprintf(szConfigFilePath,L"%s\\uninstaller.exe.config",szDummyFilePath);
			DeleteFile(szConfigFilePath);

			_stprintf(szConfigFilePath,L"%s\\cast.config",szDummyFilePath);
			DeleteFile(szConfigFilePath);

			MoveFileEx(szDummyFilePath,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);

			bRetStatus = TRUE;
		}

		if (iFileCnt== 0x06)
		{
		

			_stprintf(szConfigFilePath,L"%s\\EN1W8.exe",szDummyFilePath);
			_stprintf(szConfigFilePath,L"%s\\QBGSX0EWQX2P5G7.exe",szDummyFilePath);

			if (PathFileExists(szConfigFilePath) == FALSE)
			{
				return bRetStatus;
			}	


			_stprintf(szConfigFilePath,L"%s\\EN1W8.exe.config",szDummyFilePath);
			_stprintf(szConfigFilePath,L"%s\\QBGSX0EWQX2P5G7.exe.config",szDummyFilePath);
			if (PathFileExists(szConfigFilePath) == FALSE)
			{
				return bRetStatus;
			}	

			_stprintf(szConfigFilePath,L"%s.config",szFilePath);
			DeleteFile(szConfigFilePath);


			_stprintf(szConfigFilePath,L"%s\\EN1W8.exe",szDummyFilePath);
			DeleteFile(szConfigFilePath);

			_stprintf(szConfigFilePath,L"%s\\QBGSX0EWQX2P5G7.exe",szDummyFilePath);
			DeleteFile(szConfigFilePath);

			_stprintf(szConfigFilePath,L"%s\\EN1W8.exe.config",szDummyFilePath);
			DeleteFile(szConfigFilePath);

			_stprintf(szConfigFilePath,L"%s\\QBGSX0EWQX2P5G7.exe.config",szDummyFilePath);
			DeleteFile(szConfigFilePath);

			_stprintf(szConfigFilePath,L"%s\\cast.config",szDummyFilePath);
			DeleteFile(szConfigFilePath);

			MoveFileEx(szDummyFilePath,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);

			bRetStatus = TRUE;

		}

		return bRetStatus;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: GetFolderDetails
	In Parameters	: LPCTSTR szFolPath
	Out Parameters	: 
	Purpose			: Internal Function
	Author			: Tushar Kadam
	Description		: Collects the information for Parent directory of file being scanned
--------------------------------------------------------------------------------------*/
int	CAdwarePatternScan::GetFolderDetails(LPCTSTR szFolPath)
{
	int			iRetValue = 0x00;
	CFileFind	objFileFinder;
	BOOL		bSuccess = FALSE;
	TCHAR		szEnunPath[MAX_PATH] = {0x00};

	_stprintf(szEnunPath,L"%s\\*.*",szFolPath);
	
	bSuccess = objFileFinder.FindFile(szEnunPath);
	while(bSuccess)
	{
		bSuccess = objFileFinder.FindNextFileW();
		if (objFileFinder.IsDots() == FALSE)
		{
			iRetValue++;
		}
	}
	objFileFinder.Close();

	return iRetValue;
}


/*--------------------------------------------------------------------------------------------------
Function	:	ScanPriceLess
Author		:	Ramandeep (Virus Team)
Desription	:	Fnction handles the Throjan which on installation creates folders in <%PROGDIR%>
with random names with following pattern
1 : PRiceeLesse		2 : Priceless		3 : PriiceLess
4 : CitThoePrice	
--------------------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ScanPriceLess(LPCTSTR szFilePath)
{
	TCHAR	szFilePathTemp[MAX_PATH] = {0};
	TCHAR	szParentFolderName[MAX_PATH] = {0};

	TCHAR	*pTemp = NULL;


	_tcscpy_s(szFilePathTemp, MAX_PATH,szFilePath);
	_tcslwr(szFilePathTemp);

	//if((_tcsstr(szFilePathTemp,_T(":\\program files")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\appdata\\local")) == NULL)&&(_tcsstr(szFilePathTemp,_T(":\\programdata")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\application data")) == NULL))
	if((_tcsstr(szFilePathTemp,_T(":\\program files")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\appdata\\local")) == NULL)&&(_tcsstr(szFilePathTemp,_T(":\\programdata")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\application data")) == NULL) && ( _tcsstr(szFilePathTemp,_T(":\\documents and settings\\all users\\application data")) == NULL)&& (_tcsstr(szFilePathTemp,_T("\\appdata\\roaming\\")) == NULL))
	{
		return false;
	}

	pTemp = _tcsrchr(szFilePathTemp, _T('\\'));
	if (pTemp == NULL)
	{
		return false;
	}

	*pTemp = '\0';
	pTemp = NULL;


	pTemp = _tcsrchr(szFilePathTemp, _T('\\'));
	if (pTemp == nullptr)
	{
		return false;
	}

	_tcscpy_s(szParentFolderName, MAX_PATH,pTemp);
	
	TCHAR	szVowelList[MAX_PATH] = {0x00};
	TCHAR	szNormalisedNm[MAX_PATH] = {0x00};
	int		iLen = 0x00, kCnt = 0x00;


	pTemp = nullptr;
	_tcscpy_s(szVowelList, MAX_PATH,_T("aeiou"));
	iLen = _tcslen(szParentFolderName);

	for (int i = 0x00;  i < iLen; i++)
	{
		if(!((szParentFolderName[i] >= 0x61 && szParentFolderName[i] < 0x7B) || szParentFolderName[i] == 0x5C))
		{
			continue;
		}
		pTemp = _tcsrchr(szVowelList,szParentFolderName[i]);
		if (pTemp != nullptr)
		{
			pTemp = nullptr;
			continue;
		}
		if(kCnt > 0x00)
		{
			if (szNormalisedNm[kCnt - 0x01] == szParentFolderName[i])
			{
				continue;
			}
		}
		szNormalisedNm[kCnt] = szParentFolderName[i];
		kCnt++;
	}

	if (szNormalisedNm[0x00] == 0x00)
	{
		return false;
	}

	int iLent=0x00;
	iLent = _countof(szBlackList);
	for(int j = 0x00; j < iLent; j++)
	{
		if (_tcsstr( szNormalisedNm,szBlackList[j]) != nullptr)
		{
			return true;
		}
	}

	return false;

}


/*--------------------------------------------------------------------------------------------------
Function	:	ScanHardcodedPathAndFolderName
Author		:	Ramandeep (Virus Team)
Desription	:	Hardcoded malicious paths and folders scan.
--------------------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ScanHardcodedPathAndFolderName(LPCTSTR szFilePath)
{
	TCHAR	szFilePathTemp[MAX_PATH] = {0};
	TCHAR	szParentFolderPath[MAX_PATH] = {0};
	TCHAR	*pTemp = NULL;
	int     iLent=0x00;
	int     iRet=0x0;
	TCHAR*  szParentFolderName;


	szParentFolderName= new TCHAR[MAX_PATH];
	_tcscpy_s(szParentFolderName, MAX_PATH,_T("0"));

	_tcscpy_s(szFilePathTemp, MAX_PATH,szFilePath);
	_tcslwr(szFilePathTemp);
	_tcscpy_s(szParentFolderPath, MAX_PATH,szFilePathTemp); 
	pTemp = _tcsrchr(szFilePathTemp, _T('\\'));
	if (pTemp == NULL)
	{
		return false;
	}

	*pTemp = '\0';
	pTemp = NULL;  


	//first hardcoded path check
	iLent = _countof(szBlackListHardcodedPath);
	for(int j = 0x00; j < iLent; j++)
	{
		if (_tcsstr( szFilePathTemp,szBlackListHardcodedPath[j]) != NULL)
		{
			//iRet=DeleteBadFolder(szFilePathTemp);
			return true;
		}

	}

	iLent =0x0;
	//second arrays check for hardcoded malicious  folder names
	if((_tcsstr(szFilePathTemp,_T(":\\program files")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\appdata\\local")) == NULL)&&(_tcsstr(szFilePathTemp,_T(":\\programdata")) == NULL) && ( _tcsstr(szFilePathTemp,_T(":\\documents and settings\\all users\\application data")) == NULL)&& (_tcsstr(szFilePathTemp,_T("\\appdata\\roaming\\")) == NULL) && (_tcsstr(szFilePathTemp,_T("\\start menu\\programs\\")) == NULL))
	{
		return false;
	}


	if(!((_tcsstr(szFilePathTemp,_T(":\\program files")) == NULL) &&(_tcsstr(szFilePathTemp,_T(":\\programdata")) == NULL)))
	{
		if((_tcsstr(szFilePathTemp,_T("\\start menu\\programs\\")) == NULL ))
		{
			ParseFilePath(szParentFolderPath,szParentFolderName,1); 
		}
	}

	if(!((_tcsstr(szFilePathTemp,_T("\\local")) == NULL) &&(_tcsstr(szFilePathTemp,_T("\\locallow")) == NULL)&&(_tcsstr(szFilePathTemp,_T("\\roaming")) == NULL) ))
	{
		if((_tcsstr(szFilePathTemp,_T("\\start menu\\programs\\")) == NULL ))
		{
			ParseFilePath(szParentFolderPath,szParentFolderName,4); 
		}
	}

	if(!(_tcsstr(szFilePathTemp,_T("\\application data")) == NULL) )
	{

		ParseFilePath(szParentFolderPath,szParentFolderName,3); 
	}

	//code for coverage of  start menu 
	if(!(_tcsstr(szFilePathTemp,_T("\\start menu\\programs\\")) == NULL ))
	{
		if(!(_tcsstr(szFilePathTemp,_T(":\\programdata\\microsoft\\windows\\start menu\\programs\\")) == NULL) )
		{
			ParseFilePath(szParentFolderPath,szParentFolderName,5); 
		}
		else if(!(_tcsstr(szFilePathTemp,_T("\\microsoft\\windows\\start menu\\programs\\")) == NULL) )
		{
			if(!(_tcsstr(szFilePathTemp,_T("c:\\users\\")) == NULL) )
		 {
			 ParseFilePath(szParentFolderPath,szParentFolderName,8); 
		 }
		}
		else if (!(_tcsstr(szFilePathTemp,_T("c:\\documents and settings\\")) == NULL))
		{
			ParseFilePath(szParentFolderPath,szParentFolderName,4); 
		}
	}




	if ( szParentFolderName[0] == _T('0'))
	{
		delete szParentFolderName;
		return false;
	}

	iLent = _countof(szBlackListFolderName);
	for(int j = 0x00; j < iLent; j++)
	{
		if (_tcsstr( szParentFolderName,szBlackListFolderName[j]) != NULL)
		{
			// iRet=DeleteBadFolder(szFilePathTemp);
			delete szParentFolderName;
			return true;
		}
	}
    delete szParentFolderName;
	return false;

}

/*--------------------------------------------------------------------------------------------------
Function	:	ParseFilepath
Author		:	Ramandeep (Virus Team)
Desription	:	To find a specific member of a file path hierachy.
--------------------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ParseFilePath(LPCTSTR szFilePath,LPTSTR szParentFolderName,int iDepth)
{   
	TCHAR	szFilePathTemp[MAX_PATH] = {0};
	TCHAR	*pTemp1 = NULL;
	_tcscpy_s(szFilePathTemp, MAX_PATH,szFilePath);

	for(int i=0;i<=iDepth;i++)
	{
		if(i==0)
		{
			pTemp1 = _tcschr(szFilePathTemp, _T('\\'));
			*pTemp1++;
		}
		else if((i >0) && (i <= (iDepth-1)))
		{
			pTemp1 = _tcschr(pTemp1, _T('\\'));
			*pTemp1++;
		}
		else
		{
			pTemp1 = _tcschr(pTemp1, _T('\\'));
		}
		if (pTemp1 == NULL)
		{
			return false;
		}

	}
	*pTemp1++;
	pTemp1 = _tcschr(pTemp1, _T('\\'));
	if (pTemp1 == NULL)
	{
		return false;
	}
	*pTemp1 = 0;

	pTemp1 = _tcsrchr(szFilePathTemp, _T('\\'));
	if (pTemp1 == NULL)
	{
		return false;
	}

	_tcscpy_s(szParentFolderName, MAX_PATH,  pTemp1);

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: Scan4AdwMultiplugbei
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detection for Multiplug Adware Family
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::Scan4AdwMultiplugbei(LPCTSTR szFilePath)
{
	bool	bRetVal = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR   szParentFolderPath[1024] = {0x00};
	TCHAR   szFileName[MAX_PATH] = {0x00};
	TCHAR	*pTemp = nullptr;

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr_s(szDummyFilePath,1024);
	
	pTemp = _tcsrchr(szDummyFilePath, _T('.'));

	if(pTemp == nullptr)
	{
		return bRetVal;
	}
	
	if((_tcsstr(pTemp, _T(".dat")) == nullptr) && (_tcsstr(pTemp, _T(".dll")) == nullptr) && (_tcsstr(pTemp, _T(".tlb")) == nullptr))
	{
		return bRetVal;
	}

	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));
	if (pTemp == nullptr)
	{
		return bRetVal;
	}

	pTemp++;
	_tcscpy_s(szFileName,MAX_PATH ,pTemp);
	pTemp--;

	*pTemp = '\0';
	 pTemp = nullptr;
	
	 _tcscpy_s(szParentFolderPath,(1024 * sizeof(TCHAR)), szDummyFilePath);

	 int iFileCnt = GetFolderDetails(szParentFolderPath);
	 
	 if((iFileCnt != 2) && (iFileCnt != 4) && (iFileCnt != 6) && (iFileCnt != 8) && (iFileCnt != 10) && (iFileCnt != 12) && (iFileCnt != 16))
	 {
		return bRetVal;
	 }

	 pTemp = _tcsrchr(szFileName, _T('.'));

	 if(pTemp == nullptr)
	 {
		return bRetVal;
	 }
		
	 *pTemp = '\0';
	 pTemp = nullptr;
		
	 if(CheckForFiles(szParentFolderPath, szFileName))
	 {
		bRetVal = true;
	 }

	 return bRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForFiles
	In Parameters	: LPCTSTR szFolPath, LPCTSTR szFileName
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Supportive function for Scan4AdwMultiplugbei (Detection for Multiplug Adware Family)
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::CheckForFiles(LPCTSTR szFolPath, LPCTSTR szFileName)
{
	CFileFind	objFileFinder;
	BOOL		bSuccess = FALSE;
	BOOL        bOtherFile = TRUE;
	TCHAR		szEnunPath[MAX_PATH] = {0x00};
	TCHAR       szFile[MAX_PATH] = {0x00};
	TCHAR       szFilePath[MAX_PATH] = {0x00};
	TCHAR	    csFileName[MAX_PATH] = {0x00};
	int         iDatFileCount = 0x00;
	int         iDllFileCount = 0x00;
	int         itlbFileCount = 0x00;
	int         iexeFileCount = 0x00;

	_stprintf(szEnunPath,L"%s\\*.*",szFolPath);
	_tcscpy_s(szFile,MAX_PATH, szFileName);
	
	bSuccess = objFileFinder.FindFile(szEnunPath);
	while(bSuccess)
	{
		bSuccess = objFileFinder.FindNextFileW();
		bOtherFile = TRUE;
		if(bSuccess)
		{
			_tcscpy_s(csFileName,MAX_PATH,objFileFinder.GetFileName());
			_tcslwr(csFileName);

			if(_tcsstr(csFileName, szFile) != nullptr)
			{
				if((_tcsstr(csFileName,L".dat") == nullptr) && (_tcsstr(csFileName,L".dll") == nullptr)
					&& (_tcsstr(csFileName,L".tlb") == nullptr) && (_tcsstr(csFileName,L".exe") == nullptr))
				{
					objFileFinder.Close();
					return false;	
				}
				if(_tcsstr(csFileName,L".dat") != nullptr)
				{
					bOtherFile = FALSE;
					iDatFileCount++;
				}
				if(_tcsstr(csFileName,L".dll") != nullptr)
				{
					bOtherFile = FALSE;
					iDllFileCount++;
				}
				if(_tcsstr(csFileName,L".tlb") != nullptr)
				{
					bOtherFile = FALSE;
					itlbFileCount++;
				}
				if(_tcsstr(csFileName,L".exe") != nullptr)
				{
					bOtherFile = FALSE;
					iexeFileCount++;
				}
				if(bOtherFile)
				{
					return false;
				}
			}
		}
		else
		{
			_tcscpy_s(csFileName,MAX_PATH,objFileFinder.GetFileName());
			_tcslwr(csFileName);

			if(_tcsstr(csFileName,szFile) != nullptr)
			{
				if((_tcsstr(csFileName,L".dll") == nullptr) && (_tcsstr(csFileName,L".exe") == nullptr))
				{
					objFileFinder.Close();
					return false;
				}
				if(_tcsstr(csFileName,L".dll") != nullptr)
				{
					bOtherFile = FALSE;
					iDllFileCount++;
				}
				if(_tcsstr(csFileName,L".exe") != nullptr)
				{
					bOtherFile = FALSE;
					iexeFileCount++;
				}
				if(bOtherFile)
				{
					return false;
				}
			}
		}

	}
	objFileFinder.Close();

	if(((iDatFileCount == 0) || (iDllFileCount == 0) || (itlbFileCount == 0)) && ((iDatFileCount == 0) || (iexeFileCount == 0)))
	{
		return false;
	}

	if((iDllFileCount == iDatFileCount*2) && (iDllFileCount == itlbFileCount*2))
	{
		return true;
	}
	if((iDatFileCount == iexeFileCount))
	{
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForFiles
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Alisha Kadam
	Description		: Adware Folder contains only 2 files (a) XXXXXXXX.exe (b) XXXXXXXX.exe.config
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::Scan4ExeConfigPattern(LPCTSTR szFilePath)
{

	bool	bRetStatus = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR	*pTemp = NULL;

	if (_tcslen(szFilePath) <= 22)
	{
		return bRetStatus;
	}

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr(szDummyFilePath);

	if ((_tcsstr(szDummyFilePath,L"\\windows\\") != nullptr) || (_tcsstr(szDummyFilePath,L"\\microsoft") != nullptr) || (_tcsstr(szDummyFilePath,L"\\program files (x86)") == nullptr))
	{
		return bRetStatus;
	}

	if ((_tcsstr(szDummyFilePath,L"\\program files") == nullptr) && (_tcsstr(szDummyFilePath,L"\\appdata\\") == nullptr))
	{
		return bRetStatus;
	}

	pTemp = _tcsrchr(szDummyFilePath,_T('.'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}

	if (_tcslen(pTemp) > 0x4)
	{
		return bRetStatus;
	}


	if (!(_tcscmp(pTemp, _T(".exe")) || _tcscmp(pTemp,_T(".config"))))
	{
	   return bRetStatus;
	}


	*pTemp = '\0';
	pTemp = nullptr;

	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));

	if (pTemp == nullptr)
	{
		return bRetStatus;
	}
	if ((_tcslen(pTemp) <= 2) || (_tcslen(pTemp) > 12))
	{
		return bRetStatus;
	}
    
	*pTemp = '\0';
	pTemp = nullptr;


	int iFileCnt = GetFolderDetails(szDummyFilePath);
	if (iFileCnt < 0x07) //added
	{

		_stprintf(szConfigFilePath,L"%s.config",szFilePath);
		if (PathFileExists(szConfigFilePath) == FALSE)
		{
			_stprintf(szConfigFilePath,L"%s.config",szConfigFilePath);
			if (PathFileExists(szConfigFilePath) == FALSE)
				return bRetStatus;
		}
		else
		{
			DeleteFile(szConfigFilePath);  // Delete Config File
			bRetStatus = true;
		}
	}
	

	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: Scan4FolderPattern
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Check for Adware Folder with Folder Patern Rule
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::Scan4FolderPattern(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR	*pTemp = NULL;

	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szFolderPath[MAX_PATH] = {0x00};
	TCHAR szFName[MAX_PATH] = {0};

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr(szDummyFilePath);

	pTemp = _tcsrchr(szDummyFilePath,_T('.'));
	if (pTemp == NULL)
	{
		return bRetStatus;
	}

	if (_tcslen(pTemp) > 0x4 || _tcsstr(pTemp,_T(".exe")) || _tcsstr(pTemp,_T(".dll")) == NULL)
	{
		return bRetStatus;
	}

	_tcscpy_s(szFolderPath, _countof(szFolderPath), szFilePath);
	LPTSTR szSlash = 0;
	szSlash = _tcsrchr(szFolderPath, _T('\\'));
	if(!szSlash)
	{
		return false;
	}

	*szSlash = 0;
	if(_tsplitpath_s(szFilePath, 0, 0, 0, 0, szFName, _countof(szFName), 0, 0))
	{
		return false;
	}

	if(0 == szFName[0])
	{
		return false;
	}

	TrimString(szFName);
	if(_tcslen(szFolderPath) + _tcslen(szFName) + 1 >= _countof(szFolderPath))
	{
		return false;
	}

	int iFileCnt = GetFolderDetails(szFolderPath);

	if(iFileCnt <= 5)
	{
		TCHAR szCompanyName[MAX_PATH] = {0};
		CFileVersionInfo objVerInfo;
		if(objVerInfo.GetCompanyName(szFilePath, szCompanyName))
		{
			return false;
		}
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: TrimString
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: Internal Function
	Author			: Tushar Kadam
	Description		: 
--------------------------------------------------------------------------------------*/
void CAdwarePatternScan::TrimString(LPTSTR szString)
{
	int i = 0, iLen = 0;
	LPTSTR pBegin = 0, pFinish = 0;

	iLen = _tcslen(szString);
	for(i = 0; i < iLen; i++)
	{
		if(0 != _istprint(szString[i]) && szString[i] != 32 && szString[i] != 160)
		{
			pBegin = szString + i;
			break;
		}
	}

	if(!pBegin)
	{
		*szString = 0;
		return;
	}

	for(i = iLen; i >= 0; i--)
	{
		if(0 != _istprint(szString[i]) && szString[i] != 32 && szString[i] != 160)
		{
			pFinish = szString + i;
			break;
		}
	}

	if(pBegin >= pFinish)
	{
		return;
	}

	while(pBegin <= pFinish)
	{
		*szString++ = *pBegin++;
	}

	*szString = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: Scan4UpdEngine
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detection for Update Engine Adware
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::Scan4UpdEngine(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR	*pTemp = NULL;
	LPTSTR szSlash = 0;

	if (_tcsstr(szFilePath,L"\\program files") == NULL)
	{
		return bRetStatus;
	}

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr(szDummyFilePath);

	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szFolderPath[MAX_PATH] = {0x00};
	TCHAR szFName[MAX_PATH] = {0};

	_tcscpy_s(szFolderPath, _countof(szFolderPath), szFilePath);

	szSlash = _tcsrchr(szFolderPath, _T('\\'));
	if(!szSlash)
	{
		return false;
	}

	*szSlash = 0;
	if(_tsplitpath_s(szFilePath, 0, 0, 0, 0, szFName, _countof(szFName), 0, 0))
	{
		return false;
	}

	if(0 == szFName[0])
	{
		return false;
	}

	TrimString(szFName);
	if(_tcslen(szFolderPath) + _tcslen(szFName) + 1 >= _countof(szFolderPath))
	{
		return false;
	}
	//TCHAR t1[0x100] = {0};
	int iFileCnt = GetFolderDetails(szFolderPath);
	//_stprintf(t1,L"%d",iFileCnt);
	//AddLogEntry(L"File count %s",t1);
	if (iFileCnt == 8)
	{
		_stprintf(szConfigFilePath,L"%s\\updengine.exe",szFolderPath);
		if (PathFileExists(szConfigFilePath) == FALSE)
		{
			return bRetStatus;
		}
		_stprintf(szConfigFilePath,L"%s\\kl.dll",szFolderPath);
		if (PathFileExists(szConfigFilePath) == FALSE)
		{
			return bRetStatus;
		}
		_stprintf(szConfigFilePath,L"%s\\uninstall.exe",szFolderPath);
		if (PathFileExists(szConfigFilePath) == FALSE)
		{
			return bRetStatus;
		}

		_stprintf(szConfigFilePath,L"%s\\updengine.exe",szFolderPath);
		DeleteFile(szConfigFilePath);
		_stprintf(szConfigFilePath,L"%s\\kl.dll",szFolderPath);
		DeleteFile(szConfigFilePath);
		_stprintf(szConfigFilePath,L"%s\\uninstall.exe",szFolderPath);
		DeleteFile(szConfigFilePath);

		return true;
	}

	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: Scan4FOLDEREXENamePattern
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Sneha Kurade
	Description		: Detection for Adware using Folder and Executable Name Pattern
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::Scan4FOLDEREXENamePattern(LPCTSTR szFilePath)
{

	bool	bRetStatus = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR* pTemp = nullptr;


	if (_tcslen(szFilePath) <= 22)
	{
		return bRetStatus;
	}

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr(szDummyFilePath);

	pTemp = _tcsrchr(szDummyFilePath,_T('.'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}

	if (_tcslen(pTemp) > 0x4 || _tcsstr(pTemp,_T(".exe")) == nullptr)
	{
		return bRetStatus;
	}

	*pTemp = '\0';
	pTemp = nullptr;

	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szParentFolderName[MAX_PATH] = {0x00};

	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}

	if (_tcslen(pTemp) != 0xA)
	{
		return bRetStatus;
	}

	_stprintf(szConfigFilePath,L"%s",szFilePath);
	if (PathFileExists(szConfigFilePath) == FALSE)
	{
		return bRetStatus;
	}

	pTemp++;
	_tcscpy_s(szFileNameOnly,MAX_PATH,pTemp);
	pTemp--;

	*pTemp = '\0';
	pTemp = nullptr;

	//Folder Path
	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));

	if (pTemp == nullptr)
	{
		return bRetStatus;
	}
	if (_tcslen(pTemp) != 0xB)
	{
		return bRetStatus;
	}

	pTemp++;
	_tcscpy_s(szParentFolderName,MAX_PATH,pTemp);
	pTemp--;

	int iFileCnt = GetFolderDetails(szDummyFilePath);

	if (iFileCnt < 0x03)
	{
		if (_tcsstr(szParentFolderName,szFileNameOnly) != nullptr)
		{
			return true;
		}
	}
	if (iFileCnt == 1)
	{

		TCHAR szGetFileInternalName[MAX_PATH] = {0};

		CFileVersionInfo objVerInfo;
		if(objVerInfo.GetFileInternalName(szFilePath, szGetFileInternalName))
		{
			if (!(_tcsstr(szGetFileInternalName,_T("SourceEXE.exe"))== NULL))
			{
				delete szParentFolderName;
				return true;
			}
			else if(!(_tcsstr(szGetFileInternalName,_T("PokerFace.exe"))== NULL))
			{
				delete szParentFolderName;
				return true;
			}
			else if(!(_tcsstr(szGetFileInternalName,_T("HtagFRA.exe"))== NULL))
			{
				delete szParentFolderName;
				return true;
			}
		}

		return bRetStatus;
	}
	return bRetStatus;

}

/*-------------------------------------------------------------------------------------
	Function		: ScanForMegaSearchExtension
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if extenssion found else false
	Purpose			: 
	Author			: Nilkanth Jagtap + Virus Analysis Team
	Description		: Detection for Adware MegaSearch using Script Parsing
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ScanForMegaSearchExtension(LPCTSTR szFilePath)
{

	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR	*pTemp = NULL;
	LPTSTR szSlash = 0;

	if((_tcsstr(szFilePath, _T("user data\\default\\extensions")) == NULL))
	{
		return false;
	}

	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szFolderPath[MAX_PATH] = {0x00};
	TCHAR szFName[MAX_PATH] = {0};

	_tcscpy_s(szFolderPath, _countof(szFolderPath), szFilePath);
	szSlash = _tcsrchr(szFolderPath, _T('\\'));
	if(!szSlash)
	{
		return false;
	}

	*szSlash = 0;
	if(_tsplitpath_s(szFilePath, 0, 0, 0, 0, szFName, _countof(szFName), 0, 0))
	{
		return false;
	}

	if(0 == szFName[0])
	{
		return false;
	}

	TrimString(szFName);
	if(_tcslen(szFolderPath) + _tcslen(szFName) + 1 >= _countof(szFolderPath))
	{
		return false;
	}

	int iFileCnt = GetFolderDetails(szFolderPath);

	if(_tcsstr(szFName, _T("background")) != NULL)
	{
		TCHAR *pszFileName = new TCHAR[MAX_PATH];
		memset(pszFileName,0x00, sizeof(MAX_PATH));

		if(ParseFile(szFilePath, pszFileName))
		{
			if(CheckForMegaSearchFiles(szFolderPath, pszFileName))
			{
				delete pszFileName;
				return true;
			}
		}

		delete pszFileName;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ParseFile
	In Parameters	: LPCTSTR szFilePath, TCHAR * szFileName (Return file Name of Adware)
	Out Parameters	: true if extenssion found else false
	Purpose			: 
	Author			: Nilkanth Jagtap + Virus Analysis Team
	Description		: This function is supportive function for Detection of Adware MegaSearch
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ParseFile(LPCTSTR szFilePath, TCHAR * szFileName)
{
	bool bRetVal = false;

	TCHAR szFullFilePath[MAX_PATH] = {0x00};
	WCHAR *pszLine = nullptr;
	LPTSTR szStart = 0;
	LPTSTR szEnd = 0;

	_tcscpy_s(szFullFilePath,MAX_PATH,szFilePath);

	ifstream fFile(szFullFilePath, ios_base::in);

	string strLine;

	if(fFile.is_open())
	{
		while(!fFile.eof())
		{
			getline(fFile, strLine);

			DWORD dw = GetLastError();
			TCHAR szTempName[100] = {0x00};

			const WCHAR *pwcsName;
			// required size
			int nChars = MultiByteToWideChar(CP_ACP, 0, strLine.c_str(), -1, nullptr, 0);
			// allocate it
			pwcsName = new WCHAR[nChars];
			MultiByteToWideChar(CP_ACP, 0, strLine.c_str(), -1, (LPWSTR)pwcsName, nChars);

			pszLine = new WCHAR[nChars];
			memset(pszLine, 0x00, sizeof(WCHAR)*nChars);

			_tcscpy_s(pszLine, nChars, pwcsName);

			if(_tcsstr(pszLine,_T("<!doctype html>")) != NULL)
			{
				if(_tcsstr(pszLine, _T("lsdb.js")) != NULL)
				{
					bRetVal = true; 
					szStart = _tcsstr(pszLine, _T("="));
					szEnd   = _tcsstr(pszLine, _T(".js"));

					szStart+= 2;
					szEnd+= 3;

					int iCount = 0;

					TCHAR ch = szStart[0];
					szTempName[iCount] = ch;
					while(true)
					{
						iCount++;
						szStart++;
						ch = szStart[0];
						szTempName[iCount] = ch;

						if(_tcscmp(szStart, szEnd) == 0)
						{
							break;
						}
					}
					szTempName[iCount] = '\0';

				}
			}

			delete pwcsName;
			delete pszLine;
			//_tcscpy_s(szFileName,_tcslen(szFileName), szTempName);
			if (szFileName)
			{
				_tcscpy(szFileName, szTempName);
			}
			break;
		}
	}
	fFile.close();

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForMegaSearchFiles
	In Parameters	: LPCTSTR szFolderPath, LPCTSTR szFileNameToSearch
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Nilkanth Jagtap + Virus Analysis Team
	Description		: This function is supportive function for Detection of Adware MegaSearch
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::CheckForMegaSearchFiles(LPCTSTR szFolderPath, LPCTSTR szFileNameToSearch)
{
	bool		bRetValue = false;
	int         iMatchCount = 0x00;
	CFileFind	objFileFinder;
	BOOL		bSuccess = FALSE;
	TCHAR		szEnunPath[MAX_PATH] = {0x00};
	TCHAR       szFileName[MAX_PATH] = {0x00};

	_stprintf(szEnunPath,L"%s\\*.*",szFolderPath);

	bSuccess = objFileFinder.FindFile(szEnunPath);
	while(bSuccess)
	{
		bSuccess = objFileFinder.FindNextFileW();

		_tcscpy_s(szFileName,MAX_PATH, objFileFinder.GetFileName());

		if((_tcscmp(szFileName, szFileNameToSearch) == 0) || (_tcscmp(szFileName, _T("lsdb.js")) == 0) || (_tcscmp(szFileName, _T("background.html")) == 0) || (_tcscmp(szFileName, _T("content.js")) == 0))
		{
			iMatchCount++;
		}
	}
	objFileFinder.Close();

	if(iMatchCount == 4)
	{
		bRetValue = true;
	}

	return bRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanForWebSearch
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Nilkanth Jagtap + Gaurav Pakhale + Virus Analysis Team
	Description		: Detection of Adware WebSearch Extenssion
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ScanForWebSearch(LPCTSTR szFilePath)
{
	LPTSTR szSlash = 0;
	LPTSTR szFolNameSlash = 0;

	if((_tcsstr(szFilePath, _T("user data\\default\\extensions")) == NULL))
	{
		return false;
	}

	TCHAR	szFolderPath[MAX_PATH] = {0x00};

	_tcscpy_s(szFolderPath, _countof(szFolderPath), szFilePath);
	szSlash = _tcsrchr(szFolderPath, _T('\\'));
	if(!szSlash)
	{
		return false;
	}

	*szSlash = 0;

	szFolNameSlash = _tcsrchr(szFolderPath, _T('\\'));

	if(!szFolNameSlash)
	{
		return false;
	}

	szFolNameSlash++;

	if(_tcscmp(szFolNameSlash, _T("js")) == 0)
	{
		if(CheckForWebSearchFiles(szFolderPath))
		{
			return true;
		}
	}

	return false;
}


/*-------------------------------------------------------------------------------------
	Function		: CheckForWebSearchFiles
	In Parameters	: LPCTSTR szFolderPath
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Nilkanth Jagtap + Gaurav Pakhale + Virus Analysis Team
	Description		: This function is supportive function for Detection of Adware WebSearch Extenssion
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::CheckForWebSearchFiles(LPCTSTR szFolderPath)
{
	bool		bRetValue = false;
	int         iMatchCount = 0x00;
	CFileFind	objFileFinder;
	BOOL		bSuccess = FALSE;
	TCHAR		szEnunPath[MAX_PATH] = {0x00};
	TCHAR       szFileName[MAX_PATH] = {0x00};

	_stprintf(szEnunPath,L"%s\\*.*",szFolderPath);

	bSuccess = objFileFinder.FindFile(szEnunPath);
	DWORD dw = GetLastError();
	while(bSuccess)
	{
		bSuccess = objFileFinder.FindNextFileW();

		_tcscpy_s(szFileName,MAX_PATH, objFileFinder.GetFileName());

		if((_tcscmp(szFileName, _T("extension_detect.js")) == 0) || (_tcscmp(szFileName, _T("urlFragmentActions.js")) == 0) || (_tcscmp(szFileName, _T("background.js")) == 0) || (_tcscmp(szFileName, _T("content_script.js")) == 0) || (_tcscmp(szFileName, _T("index.js")) == 0) || (_tcscmp(szFileName, _T("dlp.js")) == 0) || (_tcscmp(szFileName, _T("logger.js")) == 0) || (_tcscmp(szFileName, _T("ul.js")) == 0) || (_tcscmp(szFileName, _T("urlUtils.js")) == 0) || (_tcscmp(szFileName, _T("util.js")) == 0))
		{
			iMatchCount++;
		}
	}
	objFileFinder.Close();

	if(iMatchCount == 10)
	{
		bRetValue = true;
	}

	return bRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanCommonExtJS
	In Parameters	: LPCTSTR szFolderPath
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Nilkanth Jagtap + Gaurav Pakhale + Virus Analysis Team
	Description		: Common function to parse .js or .html files and check for malicious website or not.
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ScanCommonExtJS(LPCTSTR szFilePath,LPCTSTR szFileName,LPCTSTR szIllegalWebsite)
{
	
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR	*pTemp = nullptr;
	LPTSTR szSlash = 0;

	if((_tcsstr(szFilePath, _T("user data\\default\\extensions")) == nullptr) && (_tcsstr(szFilePath, _T("AppData\\Roaming\\Mozilla\\Firefox\\Profiles")) == nullptr))
	{
		return false;
	}

	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szFolderPath[MAX_PATH] = {0x00};
	TCHAR szFName[MAX_PATH] = {0};

	_tcscpy_s(szFolderPath, _countof(szFolderPath), szFilePath);
	szSlash = _tcsrchr(szFolderPath, _T('\\'));
	if(!szSlash)
	{
		return false;
	}

	*szSlash = 0;
	if(_tsplitpath_s(szFilePath, 0, 0, 0, 0, szFName, _countof(szFName), 0, 0))
	{
		return false;
	}

	if(0 == szFName[0])
	{
		return false;
	}

	TrimString(szFName);
	if(_tcslen(szFolderPath) + _tcslen(szFName) + 1 >= _countof(szFolderPath))
	{
		return false;
	}

	int iFileCnt = GetFolderDetails(szFolderPath);

	if(_tcsstr(szFName,szFileName) != NULL )
	{
		TCHAR *pszFileName = new TCHAR[MAX_PATH];
		memset(pszFileName,0x00, sizeof(MAX_PATH));



		if(ParseFileCommonJS(szFilePath,szIllegalWebsite))
		{
			delete pszFileName;
			return true;
		}


		delete pszFileName;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ParseFileCommonJS
	In Parameters	: LPCTSTR szFilePath,LPCTSTR szIllegalWebsite
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Nilkanth Jagtap + Gaurav Pakhale + Virus Analysis Team
	Description		: Common function to parse .js or .html files and check for malicious website or not.
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ParseFileCommonJS(LPCTSTR szFilePath,LPCTSTR szIllegalWebsite)
{
	bool bRetVal = false;

	TCHAR szFullFilePath[MAX_PATH] = {0x00};
	WCHAR *pszLine = nullptr;
	LPTSTR szStart = 0;
	LPTSTR szEnd = 0;

	_tcscpy_s(szFullFilePath,MAX_PATH,szFilePath);

	ifstream fFile(szFullFilePath, ios_base::in);

	string strLine;
	if(fFile.is_open())
	{
		while(!fFile.eof())
		{

			getline(fFile, strLine);
			DWORD dw = GetLastError();
			TCHAR szTempName[100] = {0x00};

			const WCHAR *pwcsName;
			// required size
			int nChars = MultiByteToWideChar(CP_ACP, 0, strLine.c_str(), -1, NULL, 0);
			// allocate it
			pwcsName = new WCHAR[nChars];
			MultiByteToWideChar(CP_ACP, 0, strLine.c_str(), -1, (LPWSTR)pwcsName, nChars);

			pszLine = new WCHAR[nChars];
			memset(pszLine, 0x00, sizeof(WCHAR)*nChars);

			_tcscpy_s(pszLine, nChars, pwcsName);
			if(_tcsstr(pszLine,szIllegalWebsite) != nullptr)
			{
				
				bRetVal = true; 
				break;

			}


			free((void *)pwcsName);	
		}
	}


	fFile.close();

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanAndParseCommon
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Nilkanth Jagtap + Gaurav Pakhale + Virus Analysis Team
	Description		: Common function for detection of Adware Extenssions and 
				      to parse .js or .html files and check for malicious website or not.
--------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ScanAndParseCommon(LPCTSTR szFilePath)
{
	bool bRetVal = false;

	//Gaurav

	if(ScanCommonExtJS(szFilePath,_T("metrics"),_T("http://go.mail.ru")))
	{
		return true;//mail RU
	}

	if(ScanCommonExtJS(szFilePath,_T("background"),_T("http://personal-browser.com")) || ScanCommonExtJS(szFilePath,_T("redirect"),_T("http://personal-browser.com")))
	{
		return true;//personal browser extension 
	}
	if(ScanCommonExtJS(szFilePath,_T("app.bundle"),_T("http://e.mail.ru")))
	{
		return true; //tuTube
	}
	if(ScanCommonExtJS(szFilePath,_T("background"),_T("http://rutube.ru")))
	{
		return true;//One more Ru
	}
	if(ScanCommonExtJS(szFilePath,_T("background"),_T("http://chrome.dealply.com")))
	{
		return true;//Dealply
	}

	if(ScanCommonExtJS(szFilePath,_T("storage"),_T("http://storage.ape.yandex.net")))
	{
		return true;//Yandex
	}

	//Aniket

	if(ScanCommonExtJS(szFilePath,_T("nigel"),_T("nigel.js")) && ScanCommonExtJS(szFilePath,_T("nigel"),_T("http://i.imgur.com")))
	{
		return true;//nigel
	}

	if(ScanCommonExtJS(szFilePath,_T("background"),_T("http://portal.utilitooltech.com")))
	{
		return true;//Utilitool
	}

	if(ScanCommonExtJS(szFilePath,_T("manifest"),_T("https://feed.utilitooltech.com")))
	{
		return true;//Utilitool
	}

	return bRetVal;
}


bool CAdwarePatternScan::Scan4ISTempAndTempPattern(LPCTSTR szFilePath)
{

	bool	bRetStatus = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR	*pTemp = nullptr;

	if (_tcslen(szFilePath) <= 22)
	{
		return bRetStatus;
	}

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr(szDummyFilePath);

	if(_tcsstr(szDummyFilePath, _T("appdata\\local\\temp")) == nullptr)
	{
		return bRetStatus;
	}

	pTemp = _tcsrchr(szDummyFilePath,_T('.'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}

	if (_tcslen(pTemp) > 0x4 || _tcsstr(pTemp,_T(".tmp")) == nullptr)
	{
		return bRetStatus;
	}

	*pTemp = '\0';
	pTemp = nullptr;

	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szParentFolderName[MAX_PATH] = {0x00};

	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}

	if (_tcslen(pTemp) != 0xC)
	{
		return bRetStatus;
	}

	_stprintf(szConfigFilePath,L"%s",szFilePath);
	if (PathFileExists(szConfigFilePath) == FALSE)
	{
		return bRetStatus;
	}

	pTemp++;
	_tcscpy_s(szFileNameOnly,MAX_PATH,pTemp);
	pTemp--;

	*pTemp = '\0';
	pTemp = nullptr;

	//Folder Path
	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));

	if (pTemp == nullptr)
	{
		return bRetStatus;
	}
	
	pTemp++;
	_tcscpy_s(szParentFolderName,MAX_PATH,pTemp);
	pTemp--;

	if(_tcsstr(szParentFolderName,_T(".tmp")) != NULL && _tcsstr(szParentFolderName,_T("is-")) != NULL && _tcslen(szParentFolderName) == 0xC);
	{
		if (_tcslen(szFileNameOnly) == 0xB)
		{
			bRetStatus = true;

		}


	}
	

	return bRetStatus;

}

/*---------------------------------------------------------------------------------------------------------------
	Function		: ThreeFilePtrn
	In Parameters		: LPCTSTR szFilePath
	Out Parameters		: 
	Purpose			: 
	Description		: Detection for Adware using Folder Name, Executable Name And Config File Name Pattern
----------------------------------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::ThreeFilePtrn(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szConfigFilePath[1024] = {0x00};
	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szParentFolderName[MAX_PATH] = {0x00};
	TCHAR	*pTemp = nullptr;

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr(szDummyFilePath);
	pTemp = _tcsrchr(szDummyFilePath,_T('.'));

	if (_tcslen(szFilePath) <= 22)
	{
		return bRetStatus;
	}

	if (_tcsstr(szFilePath,L"\\program files") == NULL)
	{
		return bRetStatus;
	}

	if (pTemp == NULL)
	{
		return bRetStatus;
	}
	if (_tcsstr(pTemp,_T(".config")) == NULL)
	{
		return bRetStatus;
	}

	*pTemp = '\0';
	pTemp = nullptr;
	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));

	if (pTemp == nullptr)
	{
		return bRetStatus;
	}
	if (_tcslen(pTemp) != 0xE)
	{
		return bRetStatus;
	}
	_stprintf(szConfigFilePath,L"%s",szFilePath);
	if (PathFileExists(szConfigFilePath) == FALSE)
	{
		return bRetStatus;
	}
	pTemp++;
	_tcscpy_s(szFileNameOnly,MAX_PATH,pTemp);
	pTemp--;

	*pTemp = '\0';
	pTemp = nullptr;

	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}
	if (_tcslen(pTemp) != 0xB)
	{
		return bRetStatus;
	}
	pTemp++;
	_tcscpy_s(szParentFolderName,MAX_PATH,pTemp);
	pTemp--;

	int		iFileCnt = GetFolderDetails(szDummyFilePath);
	int		i = 0;
	int		iLen = 0;
	iLen = _tcslen(szParentFolderName);
	bool	bMatch = false;
	for (int i = 0x00;  i < (iLen-1); i++)
	{
		if(szParentFolderName[i] == szFileNameOnly[i])
		{
			bMatch = true;
			continue;
		}
		else
		{
			bMatch = false;
			break;
		}
	}

	if(bMatch == false)
	{
		return bRetStatus;
	}
	if (iFileCnt == 0x03)
	{
		_stprintf(szConfigFilePath,L"%s\\uninstaller.exe",szDummyFilePath);
		DeleteFile(szConfigFilePath);

		_stprintf(szConfigFilePath,L"%s\\uninstaller.exe.config",szDummyFilePath);
		DeleteFile(szConfigFilePath);
		return true;
	}
	return bRetStatus;
}

/*-----------------------------------------------------------------------------------------------------------------
	Function		: CloudNet
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Swapnil + Virus Analysis Team
	Description		: Detection for malicious cloudnet.exe and csrss.exe
-------------------------------------------------------------------------------------------------------------------*/
bool CAdwarePatternScan::CloudNetPtrn(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	TCHAR	szDummyFilePath[1024] = {0x00};
	TCHAR	szCloudNetFilePath[1024] = {0x00};
	TCHAR	szFileNameOnly[MAX_PATH] = {0x00};
	TCHAR	szParentFolderName[MAX_PATH] = {0x00};
	TCHAR	*pTemp = nullptr;

	_tcscpy_s(szDummyFilePath,1024, szFilePath);
	_tcslwr(szDummyFilePath);
	pTemp = _tcsrchr(szDummyFilePath,_T('.'));

	if (_tcslen(szFilePath) <= 22)
	{
		return bRetStatus;
	}
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}
	if ((_tcsstr(szDummyFilePath,L"\\appdata\\roaming\\epicnet inc\\cloudnet\\") == nullptr) && (_tcsstr(szDummyFilePath,L"\\appdata\\local\\temp\\csrss\\") == nullptr))
	{
		return bRetStatus;
	}

	*pTemp = '\0';
	pTemp = nullptr;
	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}
	if (_tcslen(pTemp) != 0x9 && _tcslen(pTemp) != 0x6)
	{
		return bRetStatus;
	}

	_stprintf(szCloudNetFilePath,L"%s",szFilePath);
	if (PathFileExists(szCloudNetFilePath) == FALSE)
	{
		return bRetStatus;
	}
	pTemp++;
	_tcscpy_s(szFileNameOnly,MAX_PATH,pTemp);
	pTemp--;

	*pTemp = '\0';
	pTemp = nullptr;

	pTemp = _tcsrchr(szDummyFilePath,_T('\\'));
	if (pTemp == nullptr)
	{
		return bRetStatus;
	}

	pTemp++;
	_tcscpy_s(szParentFolderName,MAX_PATH,pTemp);
	pTemp--;

	int iFileCnt = GetFolderDetails(szDummyFilePath);
	if (iFileCnt == 0x01)
	{
		if(_tcscmp(szFileNameOnly, _T("Cloudnet")))
		{
			_stprintf(szCloudNetFilePath,L"%s\\cloudnet.exe",szDummyFilePath);
			DeleteFile(szCloudNetFilePath);
			return true;
		}
		if(_tcscmp(szFileNameOnly, _T("csrss")))
		{
			_stprintf(szCloudNetFilePath,L"%s\\csrss.exe",szDummyFilePath);
			DeleteFile(szCloudNetFilePath);
			return true;
		}
	}

	return bRetStatus;
}

bool CAdwarePatternScan::GoogleChromePtrn(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	TCHAR	szFilePath2Check[1024] = {0x00};
	TCHAR	szParentDirectory[1024] = {0x00};

	if (szFilePath == nullptr)
	{
		return bRetStatus;
	}

	if (_tcslen(szFilePath) <= 10)
	{
		return bRetStatus;
	}

	_tcscpy_s(szFilePath2Check,1024,szFilePath);
	_tcslwr(szFilePath2Check);

	_tcscpy_s(szParentDirectory,1024,szFilePath2Check);
	TCHAR	*pTemp = nullptr;

	pTemp = _tcsrchr(szParentDirectory,L'\\');
	if (pTemp)
	{
		*pTemp = '\0';
		pTemp = nullptr;
	}

	if (_tcsstr(szFilePath2Check,L".a3x") != nullptr)
	{
		if (_tcsstr(szFilePath2Check,L":\\googlechrome\\") != nullptr || _tcsstr(szFilePath2Check,L":\\mozillafirefox\\") != nullptr)
		{
			bRetStatus = true;
			CEnumProcess	objEnumProcess;

			objEnumProcess.IsProcessRunning(L"0googlechrome.exe",true,false,true);
		
			if (_tcslen(szParentDirectory) > 0x4 && _tcsstr(szParentDirectory,L".") == nullptr)
			{
				CDirectoryManager	objDirManager;
				objDirManager.MaxDeleteDirectory(szParentDirectory,true);
			}
		}
	}
	
	return bRetStatus;
}