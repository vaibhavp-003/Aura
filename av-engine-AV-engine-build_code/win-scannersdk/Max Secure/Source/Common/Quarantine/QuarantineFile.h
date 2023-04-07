/*======================================================================================
   FILE				: QuarantineFile.h
   ABSTRACT			: Header File of CQuarantineFile Class
   DOCUMENTS		: 
   AUTHOR			:  Dipali Pawar
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 12-12-2007
   NOTE				: 
   VERSION HISTORY	: 
=======================================================================================*/

#pragma once

class CQuarantineFile
{
private:
	static CStdioFile objFileRemove;
	static CStdioFile objFileDelete;

public:
	static CString GetFileName(CString csFileName);
	
	//Remove DB related functions
	static bool OpenRemDBFile(CString csFileName = REMOVE_SPYDB_FILE_NAME_NEW);
	static bool CloseRemDBFile();
	static void AddEntryInRemoveDB(ULONG ulSpyName, CString csWormType, CString csWorm, CString csNewFileName);
	static CStringArray m_csRemovedEntryArr;

	//Delete DB related functions
	static bool OpenDelDBFile();
	static bool CloseDelDBFile();
	static void AddEntryInDeleteDB(CString csSpyName, CString csWormType, CString csWorm);
	static bool AddInRestartDeleteIni(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID,LPCTSTR szValue);
	static void CreateWormstoDeleteINI(CString strINIPath);
											

	//Block BHO related functions
	static bool OpenBlockBHOFile();
	static void AddEntryInBlockBHO(CString csBHOID,CString csClassName,CString csFilePath);
	static bool CloseBlockBHOFile();

	static bool AddInRestartDeleteList(CString csWormInfo, CString csWormType, bool bDeleteWorm = false);
	//static bool AddInHookList(CString csEntry,CString csWormType);

	//Special Spyware handling
	static void AddWormEntry(CString csEntry, CString csWormType);
};

