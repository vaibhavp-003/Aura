
/*======================================================================================
FILE             : MaxConstantSDK.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : RAVI
COMPANY		     : Aura 
CREATION DATE    : 12/11/18
NOTES		     : Declaring Global constants
VERSION HISTORY  : 
======================================================================================*/
#pragma once

//#ifndef  CURRENT_MAX_DB_VAL
//	#define CURRENT_MAX_DB_VAL			_T("CurrentMDB")
//#endif
//#ifndef  DATABASEVERSION
//	#define DATABASEVERSION				_T("DatabaseVersion")
//#endif
//#ifndef  SDKVERSION
//	#define	SDKVERSION					_T("SDKVersion")
//#endif
//#ifndef  PRODUCT_SETTINGS
//	#define PRODUCT_SETTINGS			_T("ProductSetting")
//#endif

#ifndef MAX_SCANNER_SDK_CONSTANT
//Structure for live update
#pragma pack(1)

//typedef struct				//8 bit
//{
//	unsigned char Internet    : 1;
//	unsigned char Intranet    : 1;
//	unsigned char LocalServer : 1;
//	unsigned char Allversions : 1;
//	unsigned char Reserve1	  : 1;
//	unsigned char Reserve2	  : 1;
//	unsigned char Reserve3	  : 1;
//	unsigned char Reserve4    : 1;
//}UPDATE_OPTIONS, *LPUPDATE_OPTIONS;

typedef struct				
{
	int Internet;
	
}UPDATE_OPTIONS, * LPUPDATE_OPTIONS;

#pragma pack()

#pragma pack(1)

typedef struct
{
	int	  iUpdateStatus;
	int iPercentage;
	int iTotalPercentage;
	int iSuccessErr;
	TCHAR szFiles[MAX_PATH];
	TCHAR szStatus[MAX_PATH];
	TCHAR szTimeRemaining[10];
	
}UPDATE_STATUS, *LPUPDATE_STATUS;

#pragma pack()

#endif
// Exported Function
//To initialize scanner
//For Registration
typedef bool (*REGISTERATIONPROCESS)(LPVOID *pParam);
typedef bool (*RENEWPROCESS)(LPVOID *pParam);
typedef bool (*VOUCHERPROCESS)();
typedef bool (*GETNOOFUSEDLEFT)(int *iNoofUsedLeft);
typedef int  (*GETNOOFDAYSLEFT)();
typedef bool (*GETTOTALREGDAYS)(int* TotalRegDays, CString &strRegDates);
typedef bool (*GETEXPIREDATE)(CString &strEndDate);
typedef bool (*SETNOOFUSEDLEFT)(int iNoofUsedLeft);
//typedef void (CALLBACK *SENDSDKLVMESSAGEUI)(LPUPDATE_STATUS pUpdateStatus);
typedef void (CALLBACK *SENDSDKLVMESSAGEUI)(UPDATE_STATUS objUpdateStatus);
//For liveupdate
typedef int (*LPUPDATE)(SENDSDKLVMESSAGEUI pSendSDKMessageToUI, int iUpdateOption);
typedef bool (*LPSTOPUPDATE)();

//For ThreatCommunity
//typedef BOOL (CALLBACK *SENDSDKLVMESSAGEUI)(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData);
