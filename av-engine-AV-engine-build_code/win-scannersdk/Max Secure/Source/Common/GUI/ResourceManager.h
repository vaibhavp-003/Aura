/*======================================================================================
   FILE				: ResourceManager.h
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
   VERSION HISTORY	: 9Apr2008 : Sunil Apte : Code review changes
=======================================================================================*/
#pragma once

class CResourceManager
{
public:
	CResourceManager(void);
	virtual ~CResourceManager(void);

	CString GetString(const CString &csResourceId);
	void	SetLanguage(int iLanguageCode);
	void	WriteCurrentSettings(int iLanguageCode);
	void	SetFileName(const CString &csFileName);
	void    UpdateCurrentLanguage(int iLangCode);
	void	SetResourceHandle(HANDLE hResHandle);
	int		GetLanguageCode(){return m_nCurrentLanguageCode;}

private:
	void	FormatStringForDisplay(CString &csFormatStr);
	void	SetCurrentLanguageSetting();
	int		GetLocalLanguageCode();
	CString GetSettingFilePath();
	CString GetAppFolder();
	void CheckExistenceOfIniFileReq();

	int		m_nCurrentLanguageCode;
	CStringArray m_listOfResourceFilePaths;
};
