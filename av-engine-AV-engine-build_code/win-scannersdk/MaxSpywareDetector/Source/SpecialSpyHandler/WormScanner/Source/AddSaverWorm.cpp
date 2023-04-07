 /*====================================================================================
   FILE				: AddSaverWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Add Saver
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/

#include "pch.h"
#include <fcntl.h>
#include <sys\stat.h>
#include "addsaverworm.h"
#include "StringFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForTargetSaver
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove target saver
	Author			: Sudeep
	Description		: This function checks for the TargetSaver random folders
					  There are Random folders created inside Common Files
					  These folders contain files and folders with same four alphabets as the folder
					  Check and delete EG. rrgs\\rrgst\rrgstl.lck
--------------------------------------------------------------------------------------*/
bool CAddSaverWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		if ( !bToDelete )
		{
			CFileFind objFile;
			BOOL bFileFlag = FALSE ;

			CString csSearchString;
			int iSlashPosition = 0;
			CStringArray csScanLocation ;

			csScanLocation.Add ( m_objSysInfo.m_strProgramFilesDir ) ;
			if ( m_bScanOtherLocations )
				csScanLocation.Add ( m_csOtherPFDir ) ;

			for ( int i = 0 ; i < (int)csScanLocation.GetCount() ; i++ )
			{
				CString csSearchPath = csScanLocation [ i ] + _T("\\Common Files\\*") ;
				bFileFlag = objFile.FindFile(csSearchPath);

				while ( bFileFlag )
				{
					if(IsStopScanningSignaled())
					{
						objFile.Close();
						return false ;
					}

					bFileFlag = objFile.FindNextFile() ;
					if(objFile.IsDots() || ! objFile . IsDirectory ( ))
						continue ;

					//Check the folder is of TargetSaver or Not
					if ( IsFolderOfTargetSaver ( objFile.GetFilePath( ) , objFile.GetFileName()))
					{
						RemoveFolders ( objFile . GetFilePath () , m_ulSpyName , false ) ;
					}

					csSearchString.Empty ( );
				}

				objFile.Close();
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;

	}

	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CAddSaverWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;

}//End of function to check for TargetSaver

/*-------------------------------------------------------------------------------------
	Function		: IsFolderOfTargetSaver
	In Parameters	: CString , CString 
	Out Parameters	: 
	Purpose			: Check CommonFiles folder
	Author			: Sudeep
	Description		: This function enumerates the sub folder in Common files and gives call
					  for function to check for target saver files
--------------------------------------------------------------------------------------*/
bool CAddSaverWorm :: IsFolderOfTargetSaver ( CString csFolderPath , CString csFolderName )
{
	
	BOOL bFileFlag = FALSE ;
	CFileFind cFileFind;	
	CString csSearchPath ( csFolderPath + BACK_SLASH + _T("*") ) ;
	CString csFilepath ;

	bFileFlag = cFileFind . FindFile ( csSearchPath ) ;

	while ( bFileFlag )
	{
		if(IsStopScanningSignaled())
		{
			cFileFind . Close();
			return false ;
		}

		bFileFlag = cFileFind . FindNextFile () ;
		if ( cFileFind . IsDots () || !cFileFind . IsDirectory () )
			continue ;

		if ( -1 != cFileFind . GetFileName() . Find ( csFolderName ) )
		{
			if ( LookForTargetSaverFiles ( cFileFind . GetFilePath() ) )
			{
				cFileFind . Close() ;
				return ( true ) ;
			}
		}
	}//end of while loop to check for all folders containing vcab and class barrel files

	cFileFind . Close() ;
	return ( false ) ;
}//End of function to enumerate the folder in common files program files

/*-------------------------------------------------------------------------------------
	Function		: CheckIfTargetSaverFile
	In Parameters	: CString 
	Out Parameters	: 
	Purpose			: check if it is a target saver file
	Author			: Sudeep
	Description		: This function reads the file and checks wether a set of strings are 
					  present in the file to search for TargetSaver Folder
--------------------------------------------------------------------------------------*/
bool CAddSaverWorm :: CheckIfTargetSaverFile ( CString csFileName )
{
	//Version: 19.0.0.039
	//Resource:Avinash
	//getPattern-***commented string search and call isspywarefile function of dll 
	//***changed again to normal string search as function is called in quick scan 
	//vocabulary File
	char * Strings1 [] =
	{
		"analsex",
		"lolitasex",
		"retrosex",
		"bisexuals",
		"sexuality",
		"transsexuals",
		"sexxx",
		"groupsex",
		"sexiest",
		"cybersex",
		"oralsex",
		"gaysinglesonline",
		"ladyboys",
		"homosexuality",
		"sexplosion",
		"phonesex",
		"middlesex",
		"geosex",
		"unisex",
		"sexpictures",
		"saddam",
		"beckham",
		"britney",
		"spears",
		"jessica",
		"simpson",
		NULL
	} ;

	//class-barrel File
	char * Strings2 [] =
	{
		"Adult_Amatuer",
		"Adult_Anal",
		"Adult_Asian",
		"Adult_Bisexual",
		"Adult_WebHosting",
		"Adult_Webmasters",
		"Antiques_and_Collectibles",
		"Antiques_and_Collectibles_Baseball_Cards",
		"Antiques_and_Collectibles_Cars",
		"Antiques_and_Collectibles_Coins",
		NULL
	} ;

	DWORD i = 0 ;
	int RetValue = 0 ;
	int hFile = -1 ;
	BOOL bReadFile = FALSE;
	DWORD dwBytesRead = 0 ;
	bool bTargetSaverFile = false ;

	RetValue = _tsopen_s ( &hFile , csFileName , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
	if ( 0 != RetValue )
		return ( false );

	for (i = 0; Strings1[i]; i++)
	{
		bTargetSaverFile = false ;
		if (!SearchString(hFile ,Strings1[i] ,&bTargetSaverFile) )
		{
			_close ( hFile ) ;
			return(false) ;
		}

		if ( false == bTargetSaverFile )
			break ;

		if(IsStopScanningSignaled())
            return false ;
		
	}//End of for loop to search the first set of strings to determine the file for 
	//Target Saver

	if ( bTargetSaverFile )
	{
		_close ( hFile ) ;
		return ( true ) ;
	}

	for (i = 0; Strings2 [ i ]; i++ )
	{
		bTargetSaverFile = false ;
		if ( !SearchString ( hFile , Strings2 [ i ] , &bTargetSaverFile ) )
		{
			_close ( hFile ) ;
			return ( false ) ;
		}

		if ( false == bTargetSaverFile )
			break ;

		if(IsStopScanningSignaled())
			return false ;
	}//End of for loop to check for the strings in the file

	_close ( hFile ) ;
	return ( bTargetSaverFile ) ;

}//End Of function check hsa file

/*-------------------------------------------------------------------------------------
	Function		: LookForTargetSaverFiles
	In Parameters	: CString 
	Out Parameters	: 
	Purpose			: determine target saver file
	Author			: Sudeep
	Description		: This function checks for wether the files present in the folder
					  are of TargetSaver or not
--------------------------------------------------------------------------------------*/
bool CAddSaverWorm :: LookForTargetSaverFiles ( CString csPath )
{
	BOOL bFileFlag = FALSE ;
	CFileFind cFileFind ;
	CString csSearchPath ( csPath + BACK_SLASH + _T("*")  );
	bFileFlag = ( BOOL ) cFileFind . FindFile ( csSearchPath ) ;
	while ( bFileFlag )
	{
		if(IsStopScanningSignaled())
		{
			cFileFind . Close();
			return false ;
		}

		bFileFlag = cFileFind . FindNextFile ( );
		if ( cFileFind . IsDots ( ) || cFileFind . IsDirectory ( ) )
			continue ;

		if ( CheckIfTargetSaverFile ( cFileFind .GetFilePath (  ) ) )
		{
			cFileFind . Close();
			return ( true ) ;
		}//End of if to check for target saver files
	}//end of while loop to check for all folders containing vcab and class barrel files

	cFileFind . Close() ;
	return ( false ) ;
}
