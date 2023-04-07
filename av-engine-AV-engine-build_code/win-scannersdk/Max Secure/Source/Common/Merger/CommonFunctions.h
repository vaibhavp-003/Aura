/*=============================================================================
   FILE		           : CommonFunctions.h 
   ABSTRACT		       : 
   DOCUMENTS	       : Refer The Live Update Design.doc, Live Update Requirement Document.doc
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C) Aura
						 Created as an unpublished copyright work.  All rights reserved.
						 This document and the information it contains is confidential and
						 proprietary to Aura.  Hence, it may not be 
						 used, copied, reproduced, transmitted, or stored in any form or by any 
						 means, electronic, recording, photocopying, mechanical or otherwise, 
						 without the prior written permission of Aura.	
   CREATION DATE      : 2/3/2005
   NOTES		      :  header file for class which containts commaon functions needed for live update.
   VERSION HISTORY    : 
				
=============================================================================*/
#pragma once

class CCommonFunctions
{
public:
	CString GetFileName(CString sSectionName, CString csVersionINI);
	CString GetSectionName(CString csSection);
	BOOL CopyFolder(CString csDestination, CString csSource, CStringArray* pcsarrSkipFileList = NULL, CStringArray* pcsarrAllowedFileList = NULL);
	BOOL MoveFolder(CString csDestination, CString csSource, CStringArray* pcsarrSkipFileList = NULL, CStringArray* pcsarrAllowedFileList = NULL);
	BOOL CheckInternet();
	BOOL DeleteDirectory(CString csPathName);
	BOOL ReCreateDirectory(CString csPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL);
	BOOL GetServerVersionRegSectionForPatch(CString csPatchFile, CString csINIFile, CString& csSectionName, CString& csServerVersion);
	BOOL GetAllSectionsInINI(CString csINIFile, CStringArray &objarrSections);
	BOOL IsLocalVersionLowerThanServer(CString csServerVersion, CString csLocalVersion);
};
