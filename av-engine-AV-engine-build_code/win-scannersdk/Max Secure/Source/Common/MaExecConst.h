/*======================================================================================
FILE             : MaExecConst.h
ABSTRACT         :
DOCUMENTS	     :
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE):
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be
				  used, copied, reproduced, transmitted, or stored in any form or by any
				  means, electronic, recording, photocopying, mechanical or otherwise,
				  without the prior written permission of Aura.

CREATION DATE    : 10/07/09
NOTES		     : Consts File
VERSION HISTORY  :
======================================================================================*/
#pragma once
#include "stdafx.h"
#include <string>
#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

const TCHAR MAXVMCOMMLOGPATH[]    =			_T("C:\\Automation\\Log");
const TCHAR MAXAUTOMATIONOUTPUTPATH[]    =			_T("C:\\Output");
const TCHAR REGSHOT_LOG_FOLDER[]     =      _T("C:\\Regshot\\LOG");
const TCHAR MANUAL_INPUT_FILE_PATH[]     =  _T("C:\\Regshot\\LOG\\Manual_Input.txt");
const TCHAR INPUT_SEARCH_PATH[]    =		_T("C:\\input\\*.*");
const TCHAR DETAILS_FILE_PATH[]    =        _T("C:\\input\\Details.txt");
const TCHAR SPYWAREDETECORPARAM1[]    =		 _T("/S /K /D /DRIVES:C:");
const TCHAR SPYWAREDETECORPARAM2[]    =		_T(" /S /K /D /V /DRIVES:C:");
const TCHAR SPYWAREDETECORPARAM3[]    =		_T(" /S /DRIVES:C:");
const TCHAR SPYWAREDETECORPARAM4[]    =		_T("/Q");
const TCHAR SPYWAREDETECORPARAM5[]    =		_T("/D /DRIVES:C:");


const TCHAR AUTOMATION_SIGNGEN_PATH[]	=		_T("C:\\Regshot\\SigGen.exe");
const TCHAR AUTOMATION_SYSTEMSNAP_PATH[]	=		_T("C:\\Regshot\\System Snap.exe");
const TCHAR AUTOMATION_AUTOPARAM1[]	=		_T("FIRSTSHOT");
const TCHAR AUTOMATION_AUTOPARAM2[]	=		_T("AUTOTEMP");
const TCHAR AUTOMATION_AUTOPARAM3[]	=		_T("AUTOFINAL");

const TCHAR REGSHOT_STEXT_LOG[]     =      _T("C:\\Regshot\\LOG\\StaticText.log");

const TCHAR AUTOMATION_INI[]        =       _T("AutoConfiguration.ini");
const TCHAR REGSHOT_INI[]           =       _T("RegShot.ini");
const TCHAR MANUALINPUT_INI[]        =       _T("Manual_Input.ini");
const TCHAR AUTOMATION_PATCH[]      =       _T("AutomationPatch.exe");
const TCHAR DEBUG_TESTING[]         =       _T("/DEBUG");       

const TCHAR REGSHOT_OUTPUT_FOLDER[]     =      _T("C:\\Regshot\\LOG\\");
const TCHAR REGSHOT_FOLDER_PATH[]     =      _T("C:\\Regshot\\");

const TCHAR REGSHOT_OUTPUT_FILE[]     =      _T("C:\\Regshot\\LOG\\Done.txt");
const TCHAR REGSHOT_FAILED_FILE[]     =       _T("C:\\Output\\Failed.txt");
const TCHAR REGSHOT_MODIFIED_FILE[]	=      _T("C:\\Output\\Modified.txt");
const TCHAR REGSHOT_VIRUS_FILE[]	=      _T("C:\\Output\\Virus.txt");
const TCHAR REGSHOT_LOGFAILED_FILE[]	=      _T("C:\\Output\\LogFailed.txt");

const TCHAR  AUTOMATION_AUTOCONFIGINIUPDATEPATH[]        =       _T("C:\\Automation\\AutoConfiguration.ini");
const TCHAR  AUTOMATION_REGSHOTINIUPDATEPATH[]        =       _T("C:\\Automation\\RegShot.ini");

const TCHAR  AUTOMATION_INPUTDATAPATH[]        =       _T("C:\\Input");
const TCHAR  AUTOMATION_INPUTDATAFOLDERPASSWORD[]        =       _T("virus007");

const TCHAR  AUTOMATION_TEMP_INSTALLPATCH[]     =       _T("C:\\Automation\\Temp\\AutomationPatch.exe");
const TCHAR  AUTOMATION_TEMP_INSTALLPATCH_PARAM[]     =       _T("/VERYSILENT");

const int MAX_IMAGE_QUALITY = 90;        
const int MAX_SNAP_WIDTH = 425;  



const int MAX_SCRRENSHOT_COUNT				= 3;
const TCHAR CONST_SCREENSHOT_FOLDER_PATH[]	= _T("C:\\Regshot\\LOG\\ScreenShots");
const TCHAR SPYLAUNCHER_EXE_PATH[]			= _T("C:\\Automation\\SpyLauncher.exe");
const TCHAR FILESADDED_DB_PATH[]			=_T("C:\\Regshot\\LOG\\FilesAdded.DB");
const TCHAR BINARY_COLLECTION_PATH[]		= _T("BinaryCollection");
const TCHAR INPUT_BINARY_COLLECTION_PATH[]    = _T("C:\\Regshot\\BinaryCollection\\Input");
const TCHAR BINARY_COLLECTION_ZIP_PATH[]    = _T("C:\\Regshot\\LOG\\BinaryCollection.zip");
const TCHAR BINARY_COLLECTION_FULLPATH[]    = _T("C:\\Regshot\\BinaryCollection");
const TCHAR AI_BUTTONCAPTION_SECTION[]		= _T("ButtonCaption");
const TCHAR AI_WINDOWTITLE_SECTION[]		= _T("WindowTitle");
const TCHAR AI_SITES_SECTION[]				= _T("BrowseSites");
const TCHAR AI_BUTTONCLASS_SECTION[]		= _T("ButtonClass");
const TCHAR AI_EXEPATH_SECTION[]			= _T("ExePath");
const TCHAR AI_RADIOIGNORE_SECTION[]		= _T("RadioIgnoreList");
const TCHAR AI_CHECKBOXIGNORE_SECTION[]		= _T("CheckboxIgnoreList");

const TCHAR SYSTEM32_PATH[]		= _T("C:\\WINDOWS\\SYSTEM32\\");
const TCHAR DLLCATCHE_PATH[]	= _T("C:\\WINDOWS\\SYSTEM32\\DLLCACHE\\");
const TCHAR WINDOWS_PATH[]		= _T("C:\\WINDOWS\\");
const TCHAR SPYLAUNCHER_INI_PATH[]			= _T("C:\\Automation\\FileList.ini");

typedef enum ENUM_SECTION_TYPE
{
	eButtonCaption,
	eWindowTitle,
	eBrowseSites,
	eButtonClass,
	eExecutablePath,
	eRadioIgnoreCaption,
	eCheckBoxIgnoreCaption,
};


