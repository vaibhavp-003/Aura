/*======================================================================================
   FILE				: ResourceManager.cpp
   ABSTRACT			: class which manages loading the strings from ini file 
   DOCUMENTS		: 
   AUTHOR			: Avinash Bhardwaj
   COMPANY			: Aura 
   COPYRIGHT NOTICE :
						(C)Aura
						Created as an unpublished copyright work.  All rights reserved.
						This document and the information it contains is confidential and
						proprietary to Aura.  Hence, it may not be 
						used, copied, reproduced, transmitted, or stored in any form or by any 
						means, electronic, recording, photocopying, mechanical or otherwise, 
						without the prior written permission of Aura
   CREATION DATE	: 12/01/2007
   NOTE				:
   VERSION HISTORY	: 
						Resource: Avinash Bhardwaj
						Description: Added a new function which checks whether the required 
						resource file for current set language exists or not if it does not
						then it sets the default language as english.
						Date: 9 Apr 2008
						Resource: Sunil Apte 
						Description: Code review changes

						Version: 19.0.0.73
						Date: 4-Feb-2009
						Resource: Ashwinee Jagtap
						Description: Modification in code for MultiLanguage Support.
=======================================================================================*/
#include "pch.h"
#include "ResourceManager.h"
#include "ProductInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CResourceManager
In Parameters	:
Out Parameters	:
Purpose			: constructor
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
CResourceManager::CResourceManager(void)
{
	//preparing the list of languages.
	m_nCurrentLanguageCode = 0;
	//Loading Default (English_String.ini)INI file.
	SetFileName(_T(""));
	SetCurrentLanguageSetting();


}

/*-------------------------------------------------------------------------------------
Function		: CResourceManager
In Parameters	: CString : Module name to appende to file eg: "Voucher_" for Voucher_English_String.ini
Out Parameters	:
Purpose			: To Set different String file
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
void CResourceManager::SetFileName(const CString &csFileName)
{
	m_listOfResourceFilePaths.RemoveAll();

	//filling the list of language resource files.
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("English_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("German_Strings.ini")));
	// Languages added for Multilanguage support.Ashwinee Jagtap.
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("French_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Spanish_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Russian_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Japanese_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Hindi_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Marathi_Strings.ini")));
	
	//New
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Gujrati_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Telugu_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Tamil_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Kannada_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Bengali_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("ChineseS_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("ChineseT_Strings.ini")));
	m_listOfResourceFilePaths.Add(GetAppFolder() + SETTING_FOLDER + csFileName + CString(_T("Greek_Strings.ini")));
}

/*-------------------------------------------------------------------------------------
Function		: ~CResourceManager
In Parameters	:
Out Parameters	:
Purpose			: destructor
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
CResourceManager::~CResourceManager(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: SetLanguage
In Parameters	: int iLanguageCode : language code (Codes : 0 = English, 1 = German.......)
Out Parameters	:
Purpose			: This function has been kept just to make the earlier code run...it does nothing.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CResourceManager::SetLanguage(int iLanguageCode)
{
}

/*-------------------------------------------------------------------------------------
Function		: GetString
In Parameters	: CString csResourceId : Resource id
Out Parameters	: CString : the string corresponding to the input resource id.
Purpose			: returns the string reading it from language ini file.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
CString CResourceManager::GetString(const CString &csResourceId)
{
	WCHAR buffer[1200];
	GetPrivateProfileString(SECTION_NAME, csResourceId, _T(""), buffer, 1200,
		m_listOfResourceFilePaths[m_nCurrentLanguageCode]);
	CString csOutput(buffer);
	FormatStringForDisplay(csOutput);
	return csOutput;
}

/*-------------------------------------------------------------------------------------
Function		: FormatStringForDisplay
In Parameters	: CString &csFormatStr: input string
Out Parameters	:
Purpose			: Removes string terminator char (~)
Checks for "\n" in input string and replaces it with \n escape sequence
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CResourceManager::FormatStringForDisplay(CString &csFormatStr)
{

	//removing the string terminator character (ascii code = 247)
	csFormatStr.Replace(_T("≈"),_T(""));

	//now converting all "\n" to new line charachters.
	int iPos = csFormatStr.Find(_T("\\"));
	CString csStr,csMsg;
	while(iPos != -1)
	{
		csStr = csFormatStr.Left(iPos);
		csMsg = csMsg + csStr + _T("\n");
		csFormatStr = csFormatStr.Mid(iPos+2);
		iPos = csFormatStr.Find(_T("\\"));
	}

	csFormatStr = csMsg + csFormatStr;
}

/*-------------------------------------------------------------------------------------
Function		: SetCurrentLanguageSetting
In Parameters	:
Out Parameters	:
Purpose			: checks for the currentsetting.ini file and reads the current language
and if not found then create a new file and writes the local langugage code into it.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CResourceManager::SetCurrentLanguageSetting()
{
	CString csIniPath = GetSettingFilePath();
	//check for the existence of the file.
	WCHAR buffer[5];
	if(!_waccess(csIniPath,0))
	{
		//read current language setting from the file.
		if(GetPrivateProfileString(LANGUAGE, CURRENT_LANGUAGE,_T(""),buffer,5,csIniPath))
		{
			m_nCurrentLanguageCode = _wtoi(buffer);
			return;
		}
	}

	//get the locale language.
	m_nCurrentLanguageCode = GetLocalLanguageCode();

	//create the file.also in case if the file does not contain anything clear the content.
	HANDLE hFile = CreateFile(csIniPath,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile)
		CloseHandle(hFile);
	CheckExistenceOfIniFileReq();
	WriteCurrentSettings(m_nCurrentLanguageCode);

}

/*-------------------------------------------------------------------------------------
Function		: GetLocalLanguageCode
In Parameters	:
Out Parameters	: returs code for the locale's language.
Purpose			: retrieves the locale's language and returns the correspondign code.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
int CResourceManager::GetLocalLanguageCode()
{
	DWORD dwLanguageCode = 0;
	TCHAR strLocale[MAX_PATH] = {0};
	if(GetLocaleInfo(GetSystemDefaultLCID(), LOCALE_SLANGUAGE, strLocale, MAX_PATH) == 0)
	{
		return dwLanguageCode; //GetLocaleInfo failed!
	}
	CString csLangugage;
	csLangugage.Format(_T("%s"),strLocale);

	if(csLangugage.Find(_T("English")) != -1)
	{
		dwLanguageCode = 0;

	}
	else if(csLangugage.Find(_T("Deutsch")) != -1)
	{
		dwLanguageCode = 1;

	}
	//Note: For other upcoming language we need to to find out what text GetLocaleInfo()
	//		method returns and add the respective else if case.
	return dwLanguageCode;
}

/*-------------------------------------------------------------------------------------
Function		: GetSettingFilePath
In Parameters	:
Out Parameters	: CString : path of the currentsettings.ini.
Purpose			: returns the path of the currentsettings.ini file.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
CString CResourceManager::GetSettingFilePath()
{
	CString csIniPath = GetAppFolder() + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	return csIniPath;
}

/*-------------------------------------------------------------------------------------
Function		: WriteCurrentSettings
In Parameters	: int iLanguageCode : language code
Out Parameters	:
Purpose			: writes the language code to the currentsettings.ini
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CResourceManager::WriteCurrentSettings(int iLanguageCode)
{
	m_nCurrentLanguageCode = iLanguageCode;
	CString csIniPath = GetSettingFilePath();
	CString csLang;
	csLang.Format(_T("%d"),m_nCurrentLanguageCode);
	//write the setting in the file.
	WritePrivateProfileString(LANGUAGE,CURRENT_LANGUAGE,csLang,csIniPath);
}

/*-------------------------------------------------------------------------------------
Function		: GetAppFolder
In Parameters	:
Out Parameters	: CString: current folder path
Purpose			: returns the current folder's path.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
CString CResourceManager::GetAppFolder()
{
	CString csCurrDir;
	CProductInfo oProductInfo;
	ENUM_PRODUCT_TYPE eProductType = oProductInfo.GetProductType();
	csCurrDir = oProductInfo.GetProductAppFolderPath(eProductType);
	if(_waccess(csCurrDir, 0) == -1)
	{
		WCHAR* pwchBuffer = NULL;
		pwchBuffer = new WCHAR[MAX_FILE_PATH];

		if(pwchBuffer)
		{
			SecureZeroMemory(pwchBuffer, MAX_FILE_PATH*sizeof(TCHAR));

			GetModuleFileName(NULL, pwchBuffer, MAX_FILE_PATH);

			csCurrDir = pwchBuffer;

			int iFind;
			iFind = csCurrDir.ReverseFind(_T('\\'));
			csCurrDir = csCurrDir.Mid(0, iFind + 1);

			if(pwchBuffer)
			{
				delete[] pwchBuffer;
				pwchBuffer = NULL;
			}
		}
	}
	return csCurrDir;
}

/*-------------------------------------------------------------------------------------
Function		: CheckExistenceOfIniFileReq
In Parameters	:
Out Parameters	:
Purpose			: checks whether the ini file required for current languade code exists or not
if it does not then make english as default.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CResourceManager::CheckExistenceOfIniFileReq()
{
	if(_waccess(m_listOfResourceFilePaths[m_nCurrentLanguageCode],0))
		m_nCurrentLanguageCode = 0;
}

/*-------------------------------------------------------------------------------------
Function		: UpdateCurrentLanguage
In Parameters	: int iLangCode : language code to be used for retrieving current language.
Out Parameters	:
Purpose			: updates the current language.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CResourceManager::UpdateCurrentLanguage(int iLangCode)
{
	m_nCurrentLanguageCode = iLangCode;
	CheckExistenceOfIniFileReq();
}