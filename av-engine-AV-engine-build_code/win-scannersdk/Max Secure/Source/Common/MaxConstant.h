/*======================================================================================
FILE             : MaxConstant.h
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

CREATION DATE    : 5/12/09
NOTES		     : Declaring Global constants
VERSION HISTORY  :
======================================================================================*/
#pragma once

#ifndef COCREATE_OUTPUTDEBUGSTRING
#define WIDEN2(x) L ## x  
#define WIDEN(x) WIDEN2(x)  
#define __WFILE__ WIDEN(__FILE__)
#define COCREATE_OUTPUTDEBUGSTRING(hr)	if(hr!=S_OK){TCHAR szData[1000]={0};swprintf_s(szData, 1000, L"******Failed to create instance in %d : %s", __LINE__, __WFILE__);OutputDebugString(szData);}
#define COINITIALIZE_OUTPUTDEBUGSTRING(hr)	if((hr!=S_OK)&&(hr!=S_FALSE)){TCHAR szData[1000]={0};swprintf_s(szData, 1000, L"******Failed to CoInitialize in %d : %s", __LINE__, __WFILE__);OutputDebugString(szData);}
#endif

const int MAX_PIPE_LENGTH = 8192;
const int MAX_PIPE_RETRY_TIMEOUT  = 1000;
const int MAX_PIPE_RETRY_COUNT  = 3;

const int SD_Message_Info_TYPE_FILE					= 0;
const int SD_Message_Info_TYPE_REG					= 100;
const int SD_Message_Info_TYPE_INFO					= 200;
const int SD_Message_Info_TYPE_ADMIN				= 300;
const int SD_Message_Info_TYPE_CUSTOM				= 400;
const int SD_Message_Info_TYPE_MTS					= 500;
const int SD_Message_Info_TYPE_RO					= 600;
const int SD_Message_Info_TYPE_IO					= 700;
const int SD_Message_Info_TYPE_PCP					= 800;
const int SD_Message_Info_TYPE_RC					= 900;
const int SD_Message_Info_TYPE_RC_DEFRAG			= 1000;
const int SD_Message_Info_TYPE_RC_Ignore			= 2000;
const int SD_Message_Info_TYPE_DBCache				= 3000;
const int SD_Message_Info_TYPE_Scanner				= 4000;

const int FIX_TYPE_NONE						= 0;	       
const int FIX_TYPE_ONLY_IF_SPY_FOUND		= 1;	          
const int FIX_TYPE_ALWAYS_FIX				= 2;	    
const int FIX_TYPE_IF_DEFAULT_NOT_FOUND		= 3;	        

const int FIX_ACTION_NONE					= 0;	       
const int FIX_ACTION_ADD					= 1;	      
const int FIX_ACTION_RESTORE				= 2;	     
const int FIX_ACTION_REMOVE_DATA			= 3;	    

#define MAX_IO_SETTINGS			10

#define NET_DEV_MAX        10
#pragma pack(1)
struct REG_FIX_OPTIONS
{
	unsigned char FIX_TYPE		: 4;	       
	unsigned char FIX_ACTION	: 4;	      
};
#pragma pack()

enum SD_Message_Info
{
	Process						= SD_Message_Info_TYPE_FILE,
	Process_Report,
	Cookie,
	Cookie_Report,
	Folder,
	Folder_Report,
	File,
	File_Report,
	MD5,
	MD5_Report,
	ExecPath,
	ExecPath_Report,
	GenPEScan,
	GenPEScan_Report,
	Rootkit_Process,
	Rootkit_Process_Report,
	Rootkit_File,
	Rootkit_File_Report,
	Rootkit_Folder,
	Rootkit_Folder_Report,
	Special_Process,
	Special_Process_Report,
	Special_File,
	Special_File_Report,
	Special_Folder,
	Special_Folder_Report,
	KeyLogger_Process,
	KeyLogger_Process_Report,
	KeyLogger_File,
	KeyLogger_File_Report,
	KeyLogger_Folder,
	KeyLogger_Folder_Report,
	FilePath,
	FilePath_Report,
	SplSpy,
	SplSpy_Report,
	System_File_Replace,
	System_File_Replace_Report,
	Recursive_Quarantine,
	Recursive_Quarantine_Report,
	Pattern_File,
	Pattern_File_Report,
	Status_Bar_File,
	Status_Bar_File_Report,

	BHO							= SD_Message_Info_TYPE_REG,
	BHO_Report,
	ActiveX,
	ActiveX_Report,
	MenuExt_Key,
	MenuExt_Key_Report,
	MenuExt_Value,
	MenuExt_Value_Report,
	Run1,
	Run1_Report,
	Toolbar,
	Toolbar_Report,
	RegKey,
	RegKey_Report,
	Service,
	Service_Report,
	SSODL,
	SSODL_Report,
	SharedTask,
	SharedTask_Report,
	SharedDlls,
	SharedDlls_Report,
	ShellExecuteHooks,
	ShellExecuteHooks_Report,
	Notify,
	Notify_Report,
	RegValue,
	RegValue_Report,
	RegData,
	RegData_Report,
	RegFix,
	RegFix_Report,
	Rootkit_RegKey,
	Rootkit_RegKey_Report,
	Rootkit_RegVal,
	Rootkit_RegVal_Report,
	Virus_Process,
	Virus_Process_Report,
	Virus_File,
	Virus_File_Report,
	Virus_File_Repair,
	Virus_File_Repair_Report,
	Virus_RegKey,
	Virus_RegKey_Report,
	Virus_RegVal,
	Virus_RegVal_Report,
	Special_RegKey,
	Special_RegKey_Report,
	Special_RegVal,
	Special_RegVal_Report,
	Special_RegFix,
	Special_RegFix_Report,
	Module,
	Module_Report,
	AppInit,
	AppInit_Report,
	Network,
	Network_Report,
	Cookie_New,

	Starting_Process_Scanner		= SD_Message_Info_TYPE_INFO,
	Starting_Cookie_Scanner,
	Starting_Folder_Scanner,
	Starting_File_Scanner,
	Starting_AppInit_DLL_Scanner,
	Starting_BHO_Scanner,
	Starting_ActiveX_Scanner,
	Starting_MenuExt_Key_Scanner,
	Starting_MenuExt_Value_Scanner,
	Starting_RunEntry_Scanner,
	Starting_Toolbar_Scanner,
	Starting_Services_Scanner,
	Starting_SSODL_Scanner,
	Starting_SharedTask_Scanner,
	Starting_SharedDlls_Scanner,
	Starting_ShellExecuteHooks_Scanner,
	Starting_Notify_Scanner,
	Starting_RegKey_Scanner,
	Starting_RegVal_Scanner,
	Starting_RegFix_Scanner,
	Starting_Signature_Scanner,
	Starting_Rootkit_Process_Scanner,
	Starting_Rootkit_FileSystem_Scanner,
	Starting_Rootkit_Registry_Scanner,
	Starting_Signature_And_Virus_Scanner,
	Starting_SpecialSpy_Scanner,
	Starting_KeyLogger_Scanner,
	Starting_Heuristic_Scanner,
	Starting_Network_Scanner,
	Starting_Startup_Scanner,
	Finished_Scanning,

	Stop_Scanning				= SD_Message_Info_TYPE_ADMIN,
	Perform_SplQuarantine,
	Finished_Quarantine,
	Perform_Restore,
	Finished_Recovery,
	Restart_Required,
    Total_DB_Count,
	Report_Scanner_Failure,
	Pause_Scanning,
	Resume_Scanning,
	Scanner_Paused,
	Scanner_NotRunning,
	GamingMode,
	SetProxySetting,
	SetNativeScanSetting,
	SetCopyPasteSetting,
	IsScanner_Ready,
	ScanSingleFile,						       
	Quarantine_MailDB_Entry,
	Enable_Replication,

	WD_StartingApp,
	WD_StoppingApp,
	WD_AppCrashed,
	Exit_Scanner,
	Stop_Exit_Scanner,
    Enable_Stop_WD,
	Register_WD_PID,
    Start_LiveUpdate_process,
	WD_ShutdownSD,
    WD_RestartAfterShutdown,
	WD_StartSD,
	AM_Notification,
	Quarantine_DB_Entry,
    TerminateCMDScanner,
	DiskFullMessage,
	Exit_MaxSDTray,
	Finished_Saving_DB,
	TimeRemainingMsg,
	LockWorkstationMsg,
	TextToSpeech,
	NetworkEnableDisable,
	SD_ScanFile,							       

	Custom_Field1	= SD_Message_Info_TYPE_CUSTOM,
	Install_Firewall,
	Install_Firewall_MSI,
	Show_AUSuccessDlg,
	Delete_TempFile,
	LaunchAppAs_USER,
	Manage_SystemRestore,
	Fix_LSP,
	SendGuid,
	ValidateAdmin,
	RestorePolicySetting,
	EmailReloadDataBase,
	ReloadDataBase,
	LaunchAppAsSystem,
	Scanner_Is_Ready,
	Set_RegistrySetting,
	SetNativeScanSettingEnterprise,	

	MTS_Options = SD_Message_Info_TYPE_MTS,

	RO_StartScan = SD_Message_Info_TYPE_RO,

	IO_StartOpimize = SD_Message_Info_TYPE_IO,
	IO_StartRollBack,
	IO_Finish_Optimize,
	IO_Finish_Rollback,
	
	PCP_StartScan = SD_Message_Info_TYPE_PCP,

	RC_StartScan = SD_Message_Info_TYPE_RC,
	RC_StopScan,
	RC_ScanStatus,
	RC_Quarantine,
	RC_Recover,
	RC_Ignore_Entries,
	RC_FinishedScan,
	RC_Analyze = SD_Message_Info_TYPE_RC_DEFRAG,
	RC_Defrag,
	RC_StopDefrag,
	RC_Finished_Analyze,
	RC_Finished_Defrag,
	RC_Finished_Rollback,
	RC_Finished_Stopping,
	RC_UpdateRecover,
	RC_StartIgnoring = SD_Message_Info_TYPE_RC_Ignore,
	RC_Ignoring,
	RC_Ignore_Recover,
	RC_FinishedIgnoring,

	Finished_LiveUpdate,
	Perform_Quarentine,
	Perform_Recover,
	RegisterPlugin,

	DBC_FinalConstruct = SD_Message_Info_TYPE_DBCache,
	DBC_FinalRelease,
	DBC_ReloadAllDB,
	DBC_IsExcluded,
	DBC_Exclude,
	DBC_Recover,
	DBC_GetThreatInfo,
	DBC_GetRemoveDBData,
	DBC_AddToRemoveDB,
	DBC_AddFileToRescannedDB,
	DBC_SetGamingMode,
	DBC_GetScanStatus,
	DBC_SetScanStatus,
	DBC_ReloadRemoveDB,
	DBC_AddMailToRemoveDB,
	DBC_GetMailRemoveDBData,
	DBC_ReloadMailRemoveDB,
	DBC_IsServerReady,
	DBC_ServerReady,
	DBC_UnSupportedCall,

	SCANNER_FinalConstruct = SD_Message_Info_TYPE_Scanner,
	SCANNER_FinalRelease,
	SCANNER_ReloadScanner,
	SCANNER_SetAutomationLabStatus,
	SCANNER_ReloadInstantINI,
	SCANNER_ReloadMailScannerDB,
	SCANNER_UnloadScanner,
	SCANNER_IsScannerReady,
	SCANNER_ScannerReady,
	SCANNER_ScanFile,
	SCANNER_ScanADS,
	SCANNER_ExitScanner,
	SCANNER_UnSupportedCall,


	Install_Firewall_Setup,
	RestartFirewallMonitor,
	StopFirewallMonitor,
	EnableDisablePlugin,       
	Skip_Folder,
	DeleteLocalDB,
	FSMonitorRestart,
	ChangeFilesLocalDBValue,
	Uninstall_Firewall_Setup,
	Enable_Stop_WD_PPL,
	UnRegister_WD_PPL,
	ResetProToIS,
	Reserve_1,
	Reserve_2,
	Reserve_3,
	Reserve_4,

	Max_Scan_Type,
	
};

enum E_TRUSTPID
{
	eActMon=0,
	eTrayID,
	eMaxSDUI,
	eWD,
	eScanner1,
	eScanner2,
	eScanner3,
	eHeuristic,
	eUSBScanner,
	eOutlookPlugin,
	eMaxDBServer,
	eMailProxy
};

#define MAX_SCANNER _T("AuScanner.exe")

#define SD_DB_FOLDER			_T("SD1.DB")
#define SD_DB_FILE				_T("SD2.DB")
#define SD_DB_EP				_T("SD3.DB")
#define SD_DB_MD5				_T("SD4.DB")
#define SD_DB_LOCAL_SIGNATURE	_T("AuSignature.txt")
#define SD_DB_BHO				_T("SD5.DB")
#define SD_DB_ACTIVEX			_T("SD6.DB")
#define SD_DB_MENUEXT			_T("SD7.DB")
#define SD_DB_RUN				_T("SD8.DB")
#define SD_DB_TOOLBAR			_T("SD9.DB")
#define SD_DB_REGKEY			_T("SD10.DB")
#define SD_DB_REGVAL			_T("SD11.DB")
#define SD_DB_SPYNAME_			_T("SD12.DB")
#define SD_DB_NAMEDB      		_T("SD13.db")
#define SD_DB_COOKIES			_T("SD14.DB")
#define SD_DB_APPINIT_DLL		_T("SD15.DB")
#define SD_DB_SERVICES			_T("SD16.DB")
#define SD_DB_SHARED_TASK		_T("SD17.DB")
#define SD_DB_SHARED_DLLS		_T("SD18.DB")
#define SD_DB_SSODLREG			_T("SD19.DB")
#define SD_DB_USER_NETWORK      _T("UserNetCon.DB")
#define SD_DB_NETWORK			_T("SD20.DB")
#define SD_DB_USER_BANNER      _T("UserBanner.DB")
#define SD_DB_BANNER			_T("SD34.DB")
#define SD_DB_REMOVE			_T("Quarantine\\QuarantineRemove.DB")
#define SD_DB_MAIL_REMOVE		_T("Quarantine\\MailQuarantineRemove.DB")
#define SD_DB_FILE_SCAN_STATUS	_T("Quarantine\\FileScanStatus.DB")
#define SD_DB_NOTIFY			_T("SD21.DB")
#define SD_DB_SHELLEXECUTEHOOKS	_T("SD22.DB")
#define SD_DB_DEFINITIONCOUNT	_T("SD23.DB")
#define SD_DB_REGFIX			_T("SD24.DB")
#define SD_DB_HOST				_T("SD25.DB")
#define SD_DB_WHITE_APPINIT		_T("SD26.DB")
#define SD_DB_WHITE_NOTIFY		_T("SD27.DB")
#define SD_DB_PE				_T("SD28.DB")
#define SD_DB_QPE				_T("SD29.DB")
#define SD_DB_FS				_T("SD30.DB")
#define SD_DB_WFS				_T("SD31.DB")
#define SD_DB_SYSFILES			_T("SD32.DB")
#define SD_DB_FSQ				_T("SD33.DB")
#define SD_DB_SPYNAME			_T("SD40.DB")
#define SD_DB_FS_TRJ			_T("SD41.DB")
#define SD_DB_FS_QIK			_T("SD42.DB")
#define SD_DB_FS_BLK			_T("SD43.DB")
#define SD_DB_FS_WHT			_T("SD44.DB")
#define SD_DB_ANTI_BANNER		_T("SD45.DB")
#define SD_DB_ANTI_PHISHING		_T("SD46.DB")
#define SD_DB_FS_FULLFILE_MD5	_T("SD47.DB")
#define SD_DB_HOST_EXCLUDE      _T("HostExclude.DB")
#define SD_DB_APP_EXCLUDE      _T("AppExcludeDB.db")
#define SD_DB_FILE_INTEGRITY_CHECK				_T("FIC.db")
#define SD_DB_WHITE_FILE_REGSHOT_ENTRIES		_T("WhiteFile.db")		        
#define SD_DB_WHITE_REGISTRY_REGSHOT_ENTRIES	_T("WhiteRegistry.db")	        
#define SD_DB_FS_BLK_DEL        _T("DSD43.DB")
#define SD_FS_BLK               _T("SD43")


#define SD_DB_VIRUS_SIG			_T("SDVS50.DB")
#define SD_DB_VIRUS_REP			_T("SDVR50.DB")

#define THREAT_COMMUNITY_FOLDER	 _T("ThreatCommunity")
#define TC_HEURISTIC_FOLDER		 _T("Heuristic")
#define TC_ANTI_ROOTKIT_FOLDER	 _T("AntiRootKit")
#define THREAT_COMMUNITY_ZIP	 _T("ThreatCommunity.zip")
#define TC_CT_BY_THREAT			 _T("Threat")
#define TC_RESCAN_ANALYZE		 _T("Analyze")
#define TC_FROM_ADDDRESS		 _T("")
#define TC_MESSAGE_BODY			 _T("Threat Community Message for Research Team")
#define TC_DEFAULT_SUBJECT		 _T("Threat Community Data & Logs")
#define TC_HEURISTIC_LOCAL_DB	 _T("SDHeuristic.txt")
#define	DISASMDLL				 _T("DisasmEngineDll.dll")
#define GETSIGINFOFN			 "GetSignatureInformation"
#define HEURISTIC_WHITE_DB		 _T("SDWH.DB")
#define RESCAN_FILES_NOEXT		 _T("ReScannedEntries")
#define RESCAN_FILES_DB			 _T("Quarantine\\ReScannedEntries.DB")
#define HEURISTIC_DATABASE		 _T("Quarantine\\HeuristicEntries.DB")
const UINT	  TC_MAX_ZIP_SIZE	=	3145728;  
const int SIZE_OF_BLOCK			= 512;

#define VIRUS_DB_REPAIR			_T("SDR1.DB")
#define VIRUS_DB_PE_SIG			_T("SDV1.DB")
#define VIRUS_DB_DOS_SIG		_T("SDV2.DB")
#define VIRUS_DB_COM_SIG		_T("SDV3.DB")
#define VIRUS_DB_WMA_SIG		_T("SDV4.DB")
#define VIRUS_DB_SCRIPT_SIG		_T("SDV5.DB")
#define VIRUS_DB_OLE_SIG		_T("SDV6.DB")
#define VIRUS_DB_INF_SIG		_T("SDV7.DB")
#define VIRUS_DB_PDF_SIG		_T("SDV8.DB")
#define VIRUS_DB_SIS_SIG		_T("SDV9.DB")
#define VIRUS_DB_DEX_SIG		_T("SDV10.DB")
#define VIRUS_DB_RTF_SIG		_T("SDV11.DB")
#define VIRUS_DB_CURSOR_SIG		_T("SDV12.DB")
#define VIRUS_DB_DIGI_SIG		_T("SDV13.DB")
#define VIRUS_YARA_SIG			_T("SDV14.DB")

#define AUTOLATION_LAB_VAL			_T("AutomationLab")
#define CURRENT_MAX_DB_VAL			_T("CurrentMDB")
#define EXIT_RECOVER_SCANNER		_T("EXIT_RECOVER_SCANNER")
#define EXIT_QUARENTINE_SCANNER		_T("EXIT_QUARENTINE_SCANNER")

enum eVirusFileType
{
	VIRUS_FILE_TYPE_REPAIR = -1,
	VIRUS_FILE_TYPE_PE = 1,
	VIRUS_FILE_TYPE_DOS,
	VIRUS_FILE_TYPE_COM,
	VIRUS_FILE_TYPE_WMA,
	VIRUS_FILE_TYPE_SCRIPT,
	VIRUS_FILE_TYPE_OLE,
	VIRUS_FILE_TYPE_INF,
	VIRUS_FILE_TYPE_PDF,
	VIRUS_FILE_TYPE_SIS,
	VIRUS_FILE_TYPE_DEX,
	VIRUS_FILE_TYPE_RTF,
	VIRUS_FILE_TYPE_CUR,
	VIRUS_FILE_TYPE_ELF,
	VIRUS_FILE_TYPE_GIF,
	VIRUS_FILE_TYPE_PNG,
	VIRUS_FILE_TYPE_REG,
	VIRUS_FILE_TYPE_EML,
	VIRUS_FILE_TYPE_ICON,
	VIRUS_FILE_TYPE_JCLASS,
	VIRUS_FILE_TYPE_TTF,
	VIRUS_FILE_TYPE_MSSZDD,
	VIRUS_FILE_TYPE_MSCHM,
	VIRUS_FILE_TYPE_CRYPTCFF,
	VIRUS_FILE_TYPE_RAR,
	VIRUS_FILE_TYPE_ZIP,
	VIRUS_FILE_TYPE_MSI,
	VIRUS_FILE_TYPE_BMP,
	VIRUS_FILE_TYPE_BAT,
	VIRUS_FILE_TYPE_UB,
	VIRUS_FILE_TYPE_DMG,
	VIRUS_FILE_TYPE_MAC,
	VIRUS_FILE_TYPE_UB_CLASS,
	VIRUS_FILE_TYPE_IOS_DEB,
	VIRUS_FILE_TYPE_MSCAB,
	VIRUS_FILE_TYPE_GZ,
	VIRUS_FILE_TYPE_7Z,
	VIRUS_FILE_TYPE_EICAR,
	VIRUS_FILE_TYPE_LNK,
	VIRUS_FILE_TYPE_7ZSFX,
	VIRUS_FILE_TYPE_A3X,  
	VIRUS_FILE_TYPE_NSIS,
	
	VIRUS_FILE_TYPE_BZ,
	VIRUS_FILE_TYPE_ARJ,
	VIRUS_FILE_TYPE_FLV,
	VIRUS_FILE_TYPE_PDB,
	VIRUS_FILE_TYPE_OBJ,
	VIRUS_FILE_TYPE_DMP,
	VIRUS_FILE_TYPE_MP4,
	VIRUS_FILE_TYPE_MP3,
	VIRUS_FILE_TYPE_MPEG,
	VIRUS_FILE_TYPE_VOB,
	VIRUS_FILE_TYPE_M4V,
	VIRUS_FILE_TYPE_M4A,
	VIRUS_FILE_TYPE_M4A_2,
	VIRUS_FILE_TYPE_WEBM,
	VIRUS_FILE_TYPE_MSU,
	VIRUS_FILE_TYPE_LIB,
	VIRUS_FILE_TYPE_WMF,
	VIRUS_FILE_TYPE_AVI,
	VIRUS_FILE_TYPE_PREF,
	VIRUS_FILE_TYPE_PNF,
	VIRUS_FILE_TYPE_MNG,
	VIRUS_FILE_TYPE_DCT,
	VIRUS_FILE_TYPE_SAV,
	VIRUS_FILE_TYPE_TLB,
	VIRUS_FILE_TYPE_RMVD,
	VIRUS_FILE_TYPE_AWB,
	VIRUS_FILE_TYPE_MDB,
	VIRUS_FILE_TYPE_MKV,
	VIRUS_FILE_TYPE_DWG,
	VIRUS_FILE_TYPE_PSD,
	VIRUS_FILE_TYPE_JPEG,
	VIRUS_FILE_TYPE_MST,
	VIRUS_FILE_TYPE_MXQRT,
	VIRUS_FILE_TYPE_BPF
};
#define CMDUI_EVENT_NAME					L"Global\\CMDUI_CE"

#pragma pack(1)
struct SCAN_RESULTS
{
	int		SD_Message_Info;
	ULONG	ulSpyNameID;
	WCHAR	strValue[MAX_PATH];
};
#pragma pack()

#pragma pack(1)
struct SCAN_INFO
{
	int		SD_Message_Info;
};
#pragma pack()

#pragma pack(1)
struct SCAN_REQUEST
{
	bool	bSignatureScan;
	bool	bVirusScan;
	bool	bRootkitScan;
	bool	bKeyLoggerScan;
	bool	bHeuristicScan;
	bool	bCustomScan;
	WCHAR	strDrivesToScan[MAX_PATH];
};
#pragma pack()

#pragma pack(1)
struct SCAN_OPTIONS    
{
	unsigned char DBScan			: 1;	  
	unsigned char SignatureScan		: 1;	  
	unsigned char VirusScan			: 1;	  
	unsigned char RootkitScan		: 1;	  
	unsigned char KeyLoggerScan		: 1;	  
	unsigned char HeuristicScan		: 1;	  
	unsigned char RegFixScan		: 1;	  
	unsigned char RecoverSpyware	: 1;	  
	
	unsigned char CustomScan		: 1;	  
	unsigned char RegFixOptionScan	: 1;	      
	unsigned char Quarantine		: 1;	   
	unsigned char PromptToUser      : 1;
    unsigned char CleanTempIE       : 1; 
	unsigned char DeepScan          : 1;       
	unsigned char LogOnly           : 1;	   
	unsigned char NoOutputInCMD		: 1;	          

	unsigned char ReferenceScan		: 1;	  
	unsigned char AutoQuarantine	: 1;	  
	unsigned char IsUSBScanner		: 1;	       
	unsigned char QuarentineEntries	: 1;	       
	unsigned char RootkitOption		: 2;	  
	unsigned char PluginScan		: 1;	       
	unsigned char MachineLearning	: 1;	   
};
#pragma pack()


#pragma pack(1)
struct SCAN_OPTIONS_CMD    
{
	unsigned char LogType			: 1;	  
	unsigned char ArchiveScan		: 1;	  
	unsigned char LogLevel			: 1;	 
	unsigned char BackGScanner		: 1;	    
	unsigned char ScanADStream		: 1;	    
	unsigned char Reserve2			: 1;	    
	unsigned char Reserve3			: 1;	    
	unsigned char Reserve4			: 1;	    
};
#pragma pack()

enum eEntry_Status
{
	eStatus_Detected = 0,
	eStatus_Quarantined,
	eStatus_Repaired,
	eStatus_Deleted,
	eStatus_Recovered,
	eStatus_Excluded,
	eStatus_NotApplicable
};

#pragma pack(1)
typedef struct 
{													          
	int					eMessageInfo;				 	
	SCAN_OPTIONS		sScanOptions;				 	
	ULONG				ulSpyNameID;				 	
	TCHAR				strValue[MAX_PATH];			 	 
	TCHAR				strBackup[MAX_PATH];		 	 
	TCHAR				strFreshFile[MAX_PATH];           
	eEntry_Status		eStatus;					 	
	TCHAR				szGUID[50];					 	   
}MAX_PIPE_DATA, *LPMAX_PIPE_DATA;
#pragma pack()

#pragma pack(1)
typedef struct 
{													
	SCAN_OPTIONS_CMD	sScanOptionsCmd;				 	
	TCHAR				strPath[MAX_PATH];				 	 
}MAX_PIPE_DATA_CMD, *LPMAX_PIPE_DATA_CMD;
#pragma pack()

const int SIZE_OF_MAX_PIPE_DATA = sizeof(MAX_PIPE_DATA);

#pragma pack(1)
typedef struct
{														          
	int						eMessageInfo;				 	
	SCAN_OPTIONS			sScanOptions;				 	
	ULONG					ulSpyNameID;				 	
	TCHAR					strKey[MAX_PATH];			 	 
	TCHAR					strBackup[MAX_PATH];		 	 	        
	TCHAR					strValue[MAX_PATH];               
	eEntry_Status			eStatus;					 	
	TCHAR					szGUID[50];					 	   
	union
	{
		HKEY				Hive_Type;
		ULONG64             ulPad;
	};
	int						Type_Of_Data;
	int						iSizeOfData;
	BYTE					bData[MAX_PATH*4];
	REG_FIX_OPTIONS			sReg_Fix_Options;
	int						iSizeOfReplaceData;
	BYTE					bReplaceData[MAX_PATH*4];
}MAX_PIPE_DATA_REG, *LPMAX_PIPE_DATA_REG;
#pragma pack()

const int SIZE_OF_MAX_PIPE_DATA_REG = sizeof(MAX_PIPE_DATA_REG);

#pragma pack(1)
typedef struct
{														
	int						iOper;
	TCHAR					strValue[MAX_PATH];
	HWND					hWnd;
	TCHAR					strSpyName[MAX_PATH];
	bool					bParent;
	bool					bReturn;

}OPTION_DATA, *LPOPTION_DATA;
#pragma pack()

#pragma pack(1)
typedef struct
{
	DWORD dwPID;
	int eProcType;
	unsigned char dwMonitorType		:6;
	unsigned char bStatus			:1;
	bool bShutDownStatus			:1 ;
}SHARED_ACTMON_SWITCH_DATA,*LPSHARED_ACTMON_SWITCH_DATA;
#pragma pack()


#pragma pack(1)
typedef struct
{
	int   dwMsgType;					    
	int   dwProtectionType;				
	BYTE  bProtectionStatus;			
	TCHAR szOldValue[MAX_PATH];
	TCHAR szNewValue[MAX_PATH*2];
    TCHAR szParentProcessName[MAX_PATH];
}AM_MESSAGE_DATA,*PAM_MESSAGE_DATA;
#pragma pack()
enum WD_ACTION
{
	NOTIFY_PIPE, 
	NOTIFY_AND_RESTART,
	RESTART_PROCESS,
	RESTART_SERVICE
};

#pragma pack(1)
typedef struct 
{
	int					eMessageInfo;
	TCHAR				szProcessName[MAX_PATH];
	int					nProcessType;
	DWORD				dwProcessID;
	WD_ACTION			nAction;
	int					eActionMsgInfo;
	TCHAR				szActionPipeName[MAX_PATH];
}MAX_WD_DATA, *LPMAX_WD_DATA;
#pragma pack()

enum EMAX_PIPE_DATA_TYPE
{
	EScanRequest,
	ESpywareData
};


enum ENUM_FIREWALL_OPTIONS
{
	NETAPP_FILTER,
	INTERNET_FILTER,
	EMAIL_FILTER,
	PARENTAL_CONTROL,
	NETWORK_FW_BLOCK,
	SHOW_ALL_TABS
};

class CS2U;

typedef struct _TAG_MAX_SCANNER_INFO MAX_SCANNER_INFO, * PMAX_SCANNER_INFO;


typedef BOOL (CALLBACK *SENDMESSAGETOUI)(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData);
typedef BOOL (CALLBACK *SENDMESSAGETOUIMS)(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR* strKey, const WCHAR* strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS* psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData, PMAX_SCANNER_INFO pScanInfo);
typedef BOOL (CALLBACK *SENDTDSSMESSAGETOUI)(PWSTR rPath);
typedef BOOL (CALLBACK *SENDVOIDMESSAGETOUI)(LPVOID lpVoid, DWORD dwSize);

typedef void (*STARTSCANNING)(SENDMESSAGETOUIMS lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions, const TCHAR *strDrivesToScan);
typedef void (*STARTSCANNINGTH)(SENDMESSAGETOUI lpSendMessaegToUI, SCAN_OPTIONS& sScanOptions, const TCHAR* strDrivesToScan);
typedef void (*STARTSCANNINGForRef)(SENDMESSAGETOUIMS lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions, const TCHAR *strDrivesToScan, CS2U* objFilesList, CS2U* objFoldersList);
typedef void (*STOPSCANNING)();
typedef void (*REMOVESPLSPY)();
typedef bool (*ISRESTARTREQUIRED)();
typedef bool (*PERFORMDBACTION)(LPMAX_PIPE_DATA lpPipeData);
typedef bool (*PERFORMREGACTION)(LPMAX_PIPE_DATA_REG lpMaxregdata, PMAX_SCANNER_INFO pScanInfo);
typedef bool (*REPAIRFILE)(ULONG ulVirusName , LPCTSTR csFullFilename);
typedef void (*QUARANTINERTKT)(LPCTSTR csWorm, LPCTSTR csBackupFileName);
typedef void (*PERFORMRTKTQUARANTINE)(LPMAX_PIPE_DATA lpPipeData, QUARANTINERTKT lpQuarantineRtKt);
typedef bool (*PERFORMRECOVER)(LPMAX_PIPE_DATA_REG lpPipeData, bool bUpdateDB);
typedef bool (*PERFORMSCANFILE)(LPMAX_PIPE_DATA_REG lpPipeData);
typedef void (*PERFORMQUARANTINE)(SENDMESSAGETOUIMS lpSendMessaegToUI);
typedef void (*INITIALIZEDLL)(SENDMESSAGETOUIMS lpSendMessaegToUI, bool bIsUSBScan, bool bIsMachineLearning, LPMAX_PIPE_DATA_CMD lpMaxPipeDataCmd);
typedef void (*DEINITIALIZEDLL)();
typedef void (*RELOADMAILSCANERDB)();
typedef void (*SKIPFOLDER)();

typedef BOOL (*LPFN_TextToSpeak)(LPCTSTR szTextToSpeak);
typedef BOOL (*LPFN_WipeOutData)(LPCTSTR szDriveName);
typedef BOOL (*LPFN_BlockDesktop)();
typedef BOOL (*LPFN_WebCamPicture)(HWND camhwnd,HWND m_hWnd,HDC hdc,HDC hdcMem,PAINTSTRUCT ps,HBITMAP hbm,RECT rc,int flag);


const int ESCAPE_BUTTON  = 27;
const CString SD_CMD_GUID = _T("Global\\{F39B93A0-17B1-45ef-B52A-6690B618F751}");
const CString SDUI_GUID = _T("Global\\{312DFC78-C767-4fd4-80EE-81570A801500}");
const CString MTSUI_GUID = _T("Global\\{4AA14170-2782-4b7b-8600-8BE77B6E9BAE}");

enum Max_Dispatch_Type
{
	eStartScanning = 1,
	eStopScanning,
	eQuarantine,
	eSpecialQuarantine,		
	eRestartQuarantine,		
	eRestartRequired,		
	eRecover,
	eDelete,
	eOptionTab,
	eSaveQuarantineDB,
	eInitScanDll,
	eDeInitScanDll,
	eScanFromUI,
	eScanFile,
	eReloadMailScannerDB,
	eSkipFolder,
	eSpyDTypeEnd,	
	eLoadMerger			= 1000,
	eUnLoadMerger,
	eStartLiveUpdate	= 1100
};

#pragma pack(1)
typedef struct 
{
	Max_Dispatch_Type		eDispatch_Type;				 	
	SENDMESSAGETOUI			pSendMessageToUI;			 	    
	SENDVOIDMESSAGETOUI		pSendVoidMessageToUI;		 	    
	SENDTDSSMESSAGETOUI		pSendTdssMessageToUI;
}MAX_DISPATCH_MSG,		*LPMAX_DISPATCH_MSG;
#pragma pack()

typedef void (*MAXSECUREDISPATCHER)(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid);
typedef void (*MAXSECURECMDLOG)(LPVOID lpVoid);

enum ENUM_ACTION_ON_DETECTION		        
{
	E_LOGONLY,				   
	E_DELETE,				      
	E_QUARANTINE			   
};


typedef struct
{
	DWORD dwPrivacySetting;
	VARIANT VarFilelist;
	VARIANT VarFolder;

}MAX_FILE_SHREDDER,*LPMAX_FILE_SHREDDER;

#pragma pack(1)
typedef struct _tagSpywareEntryDetails
{
	DWORD	dwIndexDB;
	WORD	eTypeOfEntry;
	union
	{
		SIZE_T	ulHive;
		ULONG64 ulHivePad;
	};
	DWORD	dwRegDataSize;
	DWORD	dwReplaceRegDataSize;
	WORD	wRegDataType;
	DWORD	dwSpywareID;
	BYTE	byStatus;
	BYTE	byChecked;
	BYTE	byThreatLevel;
	ULONG64	ul64DateTime;
	BYTE	byFix_Type;
	BYTE	byFix_Action;
	ULONG64 ulDate;
	DWORD	dwTime;
	TCHAR	szDateTime[50];
	TCHAR	szMachineName[MAX_PATH];
	TCHAR	szMachineID[MAX_PATH];
	TCHAR	szSpyName[MAX_PATH];
	TCHAR	szKey[MAX_PATH];
	TCHAR	szValue[MAX_PATH];
	TCHAR	szBackupFileName[MAX_PATH];
	BYTE	byData[MAX_PATH*4];
	BYTE	byReplaceData[MAX_PATH*4];
}SPY_ENTRY_DETAIL, *LPSPY_ENTRY_DETAIL;
#pragma pack()

#define SIZE_OF_SPY_ENTRY_DETAIL sizeof(SPY_ENTRY_DETAIL)


#pragma pack(1)
typedef struct _FirewallRuls
{
	bool	bIsNetworkRule;
	bool    bEnableFirewall;	
	TCHAR	strIPRangeStart[100];
	TCHAR	strIPRangeEnd[100];
	TCHAR	strStartPort[100];
	TCHAR	strEndPort[100];
	TCHAR	strStartRemotePort[100];
	TCHAR	strEndRemotePort[100];
	TCHAR	strIBAction[100];
	TCHAR	strOBAction[100];
	TCHAR	strOwner[100];
	TCHAR	strRuleID[100];
	TCHAR   szRuleCondition[MAX_PATH];
}FIREWALLRULES, *LPFIREWALLRULES;
#pragma pack()

#pragma pack(1)
typedef struct tag_THREAT_ENGINECONFIG
{
	int nPolicyType;
	TCHAR szPolicyFile[MAX_PATH];
}THREATENGINECONFIG, *LPTHREATENGINECONFIG;
#pragma pack()

#pragma pack(1)
typedef struct _EmailProtection
{
	bool bEnableEmailProt;
	bool bBadURLChecking;
	bool bMicrosoftOutlook;
	bool bOutlookExpress;
	bool bOtherClient;
	bool bWndLiveMailClient;
	int iAction;
	int nMaxAttachmentSize;
}EMAILPROTECTION, *LPEMAILPROTECTION;
#pragma pack()

#pragma pack(1)
typedef struct tag_QuarantinedItems
{
	int iPurgeDays;
	TCHAR strThreatName[MAX_PATH];
	TCHAR strThreatType[MAX_PATH];
	TCHAR strQuarantineDate[MAX_PATH];
	TCHAR strQuarantineID[50];
	TCHAR strQuarantineData[MAX_PATH];
}QUARANTINEITEMS, *LPQUARANTINEITEMS;
#pragma pack()

#pragma pack(1)
typedef struct tag_WebFilter
{
	bool	bIsEnabled;
	TCHAR	strOwner[100];
	int		nMatchMode;
	bool	bFilterCookieSession;
	bool	bFilterCookieForeign;
	bool	bFilterCookiePermanent;
	bool	bFilter3rdParty;
	bool	bFilterReferer;
	bool	bFilterADs;
	bool	bFilterPersonalInfo;
	bool	bFilterJavaScript;
	bool	bFilterVBScript;
	bool	bFilterActiveX;
	bool	bFilterPopups;
}WEBFILTERRULES, *LPWEBFILTERRULES;
#pragma pack()

#pragma pack(1)
typedef struct tag_NetworkFilter
{
	bool	bSystemOwner;
	int		nMatchMode;
	DWORD	nRuleID;
}NETWORKFILTER, *LPNETWORKFILTER;
#pragma pack()

#pragma pack(1)
struct IO_SCAN_OPTIONS    
{
	unsigned char TCPWindowSize			: 1;	  
	unsigned char DefaultTTL			: 1;	  
	unsigned char BlackHoleDetect		: 1;	  
	unsigned char SackOpts				: 1;	  
	unsigned char MaxDupAcks			: 1;	  
	unsigned char HttpPatch				: 1;	  
	unsigned char DNSErrorCaching		: 1;	  
	unsigned char HostResolution		: 1;	  
	
	unsigned char MTUSize				: 1;	  
	unsigned char IndexDat				: 1;	      
	unsigned char Reserved				: 6;	
};
#pragma pack()

#pragma pack(1)
typedef struct 
{
	int					eMessageInfo;				
	IO_SCAN_OPTIONS 	sIOScanOptions;
	bool				bReturn;

}IO_MAX_PIPE_DATA, *LPIO_MAX_PIPE_DATA;
#pragma pack()

#pragma pack(1)
struct RC_SCAN_OPTIONS    
{
	unsigned char StartUpScan			: 1;	  
	unsigned char StartMenuScan			: 1;	  
	unsigned char SharedDLLScan			: 1;	  
	unsigned char FontScan				: 1;	  
	unsigned char AppInfoScan			: 1;	  
	unsigned char AppEventScan			: 1;	  
	unsigned char UserInfoScan			: 1;	  
	unsigned char FileExtScan			: 1;	  
	
	unsigned char SharedFolderScan		: 1;	  
	unsigned char HelpFileScan			: 1;	      
	unsigned char MRUScan				: 1;	   
	unsigned char EmptyRegKeysScan      : 1;
    unsigned char COMScan				: 1; 
	unsigned char DeepScan				: 1;       
	unsigned char ShortcutsScan         : 1;	   
	unsigned char CookieScan			: 1;	          

	unsigned char AddressURLScan		: 1;	  
	unsigned char RecycleBinScan		: 1;	  
	unsigned char ClipBoardScan			: 1;	  
	unsigned char WinAPPLogScan			: 1;	  
	unsigned char TempFilesScan			: 1;	  
	unsigned char NetTetmpFilesScan		: 1;	  
	unsigned char Reserved				: 2;	
};
#pragma pack()

#pragma pack(1)
typedef struct 
{													          
	int					eMessageInfo;				 	
	ULONGLONG			m_ullSizeBefore;
	ULONGLONG			m_ullSizeAfter;
	ULONGLONG			m_ullGain;
	bool				bStatus;

}RC_DEFRAG_PIPE_DATA, *LPRC_DEFRAG_PIPE_DATA;
#pragma pack()

#pragma pack(1)
typedef struct 
{
	int					eMessageInfo;				
	RC_SCAN_OPTIONS 	sRCScanOptions;
	int					iWormTypeID;
	int					iWormCount;
	int					iThreatLevel;
	bool				bIsChild;
	bool				bIsAdminEntry;
	DWORD				dwRegType;
	TCHAR				strKey[MAX_PATH*2];
	TCHAR				strValue[MAX_PATH];
	TCHAR				strData[MAX_PATH*2];
	TCHAR				strDisplayName[MAX_PATH];
	TCHAR				strBackupFileName[MAX_PATH];
}RC_MAX_PIPE_DATA, *LPRC_MAX_PIPE_DATA;
#pragma pack()

typedef BOOL (CALLBACK *RC_SENDMESSAGETOUI)(SD_Message_Info eTypeOfScanner, const CString &csKey, const CString &csValue, const CString &csData, const bool bIsChild, const int iWormTypeID, const int iThreatLevel,const CString &csDisplayName, const bool bIsAdminEntry, const int iWormCount);
typedef bool (*PFSTARTSCANNING)(RC_SENDMESSAGETOUI lpSendMessageToUI, LPRC_MAX_PIPE_DATA lpRCMaxPipeData);
typedef bool (*PFSTOPSCANNING)(bool bStopScanning);
typedef bool (*PFPERFORMRCQUARANTINE)(RC_SENDMESSAGETOUI pRCSendMessageToUI, LPRC_MAX_PIPE_DATA pRCMaxPipeData);
typedef bool (*PFPERFORMRCRECOVER)(RC_SENDMESSAGETOUI pRCSendMessageToUI, LPRC_MAX_PIPE_DATA pRCMaxPipeData);
typedef bool (*PFADDENTRYINIGNOREDB)(RC_SENDMESSAGETOUI pRCSendMessageToUI, LPRC_MAX_PIPE_DATA pRCMaxPipeData);
typedef bool (*PFREMOVEENTRYFROMIGNOREDB) (RC_SENDMESSAGETOUI pRCSendMessageToUI, LPRC_MAX_PIPE_DATA pRCMaxPipeData);
typedef bool (*PFANALYZE) (ULONGLONG &ullSizeBefore, ULONGLONG  &ullSizeAfter, ULONGLONG &ullGain);
typedef bool (*PFDEFRAG) (ULONGLONG &ullSizeBefore, ULONGLONG  &ullSizeAfter, ULONGLONG &ullGain);
typedef bool (*PFSTOPANALYZING)(LPRC_DEFRAG_PIPE_DATA pRCDefragPipeData);
typedef bool (*PFUPDATEREMOVEDB) (const CString &csKey, const CString &csValue, const CString &csData, const CString &csWormType, const CString &csFileName);
typedef bool (*PFLOADIGNORELIST) (RC_SENDMESSAGETOUI pRCSendMessageToUI, LPRC_MAX_PIPE_DATA pRCMaxPipeData);
#pragma pack(1)
typedef struct 
{													
	bool     bBlocked;
	bool	bPublishingPrompt;
	TCHAR	szAppName[MAX_PATH];
	DWORD	dwPID;
	TCHAR	szLocalIP[MAX_PATH];
	TCHAR	szRemoteIP[MAX_PATH];
	int		nLocalPort;
	int		nRemotePort;
	int		nRuleID;
	int		nDirection;
}FW_REPORT_DATA, *LPFW_REPORT_DATA;
#pragma pack()

enum THREAT_ENGINE_RULES_INDEX
{
	FIREWALL_RULES_ID,
	QUARANTINED_ITEMS_ID,
	WEB_FILTER_RULES_ID,
	WEB_FILTER_EXCLUSIONDOMAINS_RULES_ID,
	WEB_FILTER_EXCLUSIONAPPS_RULES_ID,
	WEB_FILTER_ADS_RULES_ID
};


#define DB_EXIST							0x0001
#define DB_NOTEXIST							0x0000



#define MAX_HOURS							24
#define MIN_WEEKDAYS_BTN_ID					101
#define MAX_WEEKDAYS_BTN_ID					124

#define MIN_WEEKENDS_BTN_ID					201
#define MAX_WEEKENDS_BTN_ID					224

enum PCCategoryID
{
	Social_Networking = 1,
	Pornography,
	Drugs,
	Weapons,
	Violance,
	Webmail,
	Forum_Chats,
	Payment_Gateway,
	Gambling,
	Casual_Games,
	Illegal_Software,
	Online_Store,
	Explicit_Language,
	Anonymous_Proxy_Server
};


#pragma pack(1)
typedef struct tagCATEGORY_SELECTION
{
	unsigned char Social_Networking			: 1;
	unsigned char Pornography				: 1;
	unsigned char Drugs						: 1;
	unsigned char Weapons					: 1;
	unsigned char Violance					: 1;
	unsigned char Webmail					: 1;
	unsigned char Forum_Chats				: 1;
	unsigned char Payment_Gateway			: 1;

	unsigned char Gambling					: 1;
	unsigned char Casual_Games				: 1;
	unsigned char Illegal_Software			: 1;
	unsigned char Online_Store				: 1;
	unsigned char Explicit_Language			: 1;
	unsigned char Anonymous_Proxy_Server	: 1;
	unsigned char Reserved_2				: 2;

	unsigned char Reserved_8				: 8;

}	CATEGORY_SELECTION, *PCATEGORY_SELECTION;
#pragma pack()



#pragma pack(1)
typedef struct tagHOUR_SELECTION
{
	unsigned char Hour_1		: 1;
	unsigned char Hour_2		: 1;
	unsigned char Hour_3		: 1;
	unsigned char Hour_4		: 1;
	unsigned char Hour_5		: 1;
	unsigned char Hour_6		: 1;
	unsigned char Hour_7		: 1;
	unsigned char Hour_8		: 1;

	unsigned char Hour_9		: 1;
	unsigned char Hour_10		: 1;
	unsigned char Hour_11		: 1;
	unsigned char Hour_12		: 1;
	unsigned char Hour_13		: 1;
	unsigned char Hour_14		: 1;
	unsigned char Hour_15		: 1;
	unsigned char Hour_16		: 1;

	unsigned char Hour_17		: 1;
	unsigned char Hour_18		: 1;
	unsigned char Hour_19		: 1;
	unsigned char Hour_20		: 1;
	unsigned char Hour_21		: 1;
	unsigned char Hour_22		: 1;
	unsigned char Hour_23		: 1;
	unsigned char Hour_24		: 1;

}	HOUR_SELECTION, *P_HOUR_SELECTION;
#pragma pack()

#pragma pack(1)
typedef struct tagSELECTED_HOUR
{
	union
	{
		HOUR_SELECTION	h;
		DWORD			d;
	};

} SELECTED_HOUR;


#pragma pack(1)
typedef struct tagINET_USAGE_BLOCKING
{
	BOOLEAN				bEnableParentalControl;

	BOOLEAN				bEnableURLBlocking;

	BOOLEAN				bEnableCategoryBlocking;
	CATEGORY_SELECTION	Category_To_Block;

	BOOLEAN				bINetUsageBlocking;
	BOOLEAN				bINetBlockingWeekDays;
	BOOLEAN				bINetBlockingWeekEnds;
	HOUR_SELECTION		INetBlockWeekdays;
	HOUR_SELECTION		INetBlockWeekends;

	BOOLEAN				bCompUsageUsageBlocking;
	BOOLEAN				bCompUsageBlockingWeekDays;
	BOOLEAN				bCompUsageBlockingWeekEnds;
	HOUR_SELECTION		CompUsageBlockWeekdays;
	HOUR_SELECTION		CompUsageBlockWeekends;

}	INET_USAGE_BLOCKING, *P_INET_USAGE_BLOCKING;
#pragma pack()

enum SD_Detected_BY
{
	Detected_BY_NONE,					       
	Detected_BY_Max_Pattern,			  
	Detected_BY_Max_Instant,			  
	Detected_BY_Max_FileSig,			   
	Detected_BY_Max_FullFileSig,
	Detected_BY_Vipre,					 
	Detected_BY_MaxVirus_DB,			   
	Detected_BY_MaxVirus_Poly,			   
	Detected_BY_Max_ML,					   
	Detected_BY_Max_Yara,				   
	Detected_BY_MaxVirus_Icon,			   
	Detected_BY_MaxVirus_Digicert,		   
	Detected_BY_MaxCloud_PE,			    
	Detected_BY_MaxAVModule
};

enum SD_Scanner_Type
{
	Scanner_Type_UNKNOWN,		  
	Scanner_Type_Max_ThreadScan,		  
	Scanner_Type_Max_ProcScan,			  
	Scanner_Type_Max_Startup,			  
	Scanner_Type_Max_ModuleScan,		   
	Scanner_Type_Max_SignatureScan,		   
	Scanner_Type_Max_ActMonProcScan,	   
	Scanner_Type_Max_ActMonModuleScan,	   
	Scanner_Type_Max_Recursive_Scan,	  
	Scanner_Type_Max_Email_Scan			  
};

#pragma pack(1)
typedef struct _tagPESigCRCLocalDB
{
	ULONG64	ulSignature;
	ULONG64	ulFullFileSignature;
	DWORD	dwModifiedTimeHigh;
	DWORD	dwModifiedTimeLow;
	DWORD	dwFileSizeHigh;
	DWORD	dwFileSizeLow;
	
	DWORD	dwSD43Version;   
	DWORD	dwSD47Version;   
	DWORD	dwPatternVersion;   
	DWORD	dwMLVersion;   
	DWORD	dwYrVersion;   

	BYTE	btVirusPolyScanStatus[16]; 
	
	unsigned char iFileSigCreated		: 1;
	unsigned char iIsWhiteFile			: 1;
	unsigned char iVerTabInfo			: 2;
	unsigned char UpdateLocalDB			: 1;
	unsigned char Reserved				: 3;
}PESIGCRCLOCALDB, *PPESIGCRCLOCALDB, *LPPESIGCRCLOCALDB;
#pragma pack()

#pragma pack(1)
typedef struct _tagVirusLocalDB
{
	unsigned char iIsArchiveFile		: 1;
	unsigned char iMaxVirusScanDone		: 1;
	unsigned char iVirusFoundStatus		: 1;
	unsigned char Reserved				: 5;
}VIRUSLOCALDB, *PVIRUSLOCALDB, *LPVIRUSLOCALDB;
#pragma pack()

class CMaxPEFile;


const WORD MAX_SCAN_TIME =	1000	* 60	* 1;			   

#pragma pack(1)
struct _TAG_MAX_SCANNER_INFO
{
	union
	{
		LPVOID	pThis = NULL;							         
		ULONG64	ulPadThis;
	};
	union
	{
		HANDLE hModuleHandleToScan = NULL;				          
		ULONG64	ulPadModuleHandle;
	};
	union
	{
		HANDLE hProcessHandleIDToScan = NULL;			          
		ULONG64	ulPadProcessHandle;
	};

	ULONG ulReplicatingProcess;					            
	ULONG ulProcessIDToScan;					         
	ULONG ulThreadIDToScan;						          
	TCHAR szFileToScan[MAX_PATH] = { 0x00 };
	TCHAR szContainerFileName[MAX_PATH] = { 0x00 };
	DWORD dwStartTickCount;						                     
	unsigned char AutoQuarantine		: 1;	         

	unsigned char ThreatDetected		: 1;	        
	unsigned char ThreatSuspicious		: 1;	       
	unsigned char MultipleInfection		: 1;	          
	unsigned char ThreatRepaired		: 1;	    
	unsigned char ThreatNonCurable		: 1;	                    
	unsigned char ThreatQuarantined		: 1;	    
	unsigned char IsArchiveFile			: 1;	           
	unsigned char IsPackedFile			: 1;	          
	unsigned char IsPasswordProtected	: 1;	     
	unsigned char IsExcluded			: 1;	               
	unsigned char FreeNextScanInfo		: 1;	           
	unsigned char IsLockedFile			: 1;	            
	unsigned char SkipPolyMorphicScan	: 1;	          
	unsigned char SkipPatternScan		: 1;	          
	unsigned char IsWhiteFile			: 1;	               
	unsigned char IsChildFile			: 1;	            
	unsigned char IsEMLFile				: 1;	         
	unsigned char Reserved				: 6;	 
	

	ULONG ulThreatID;							   
	SD_Message_Info eMessageInfo;				       

	SD_Detected_BY	eDetectedBY;				    
	SD_Scanner_Type	eScannerType;				       
	TCHAR szThreatName[MAX_PATH] = { 0x00 };
	TCHAR szOLEMacroName[MAX_PATH] = { 0x00 };
	TCHAR szBackupFileName[MAX_PATH] = { 0x00 };
	TCHAR szFreshFile[MAX_PATH] = { 0x00 };
	TCHAR szFileSig[MAX_PATH] = { 0x00 };
	DWORD eVirusFileType;						   

	union
	{
		PMAX_SCANNER_INFO pNextScanInfo = NULL;		                
		ULONG64	ulPadScannerInfo;
	};

	union
	{
		CMaxPEFile	*pMaxPEFile = NULL;				          
		ULONG64		ulPadThis;					                 
	};
};

#pragma pack()

const DWORD	REAPIR_STATUS_FAILURE	=	0x60;
const DWORD	REAPIR_STATUS_SUCCESS	=	0x70;
const DWORD	REAPIR_STATUS_CORRUPT	=	0x80;
const DWORD	REAPIR_STATUS_TIMEOUT	=	0x90;

const DWORD	SCAN_ACTION_CLEAN		=	0x0000;
const DWORD	SCAN_ACTION_REPAIR		=	0x0001;
const DWORD	SCAN_ACTION_DELETE		=	0x0002;
const DWORD	SCAN_ACTION_TIMEOUT		=	0x0003;

const ULONG FSS_NEW_FILE			=	0;
const ULONG FSS_SCAN_STARTED		=	1;	               
const ULONG FSS_SCAN_COMPLETED		=	2;
const ULONG FSS_REPAIR_STARTED		=	3;	               
const ULONG FSS_REPAIR_COMPLETED	=	4;

#pragma pack(1)
typedef struct 
{
	unsigned char FileStart			: 1;	
	unsigned char Cavity1			: 1;	
	unsigned char Cavity2			: 1;	
	unsigned char AEP				: 1;	
	unsigned char EndOfAEPSec		: 1;	
	unsigned char StartOfLastSec	: 1;	
	unsigned char EndOfLastSec		: 1;	
	unsigned char UPXSec			: 1;	
	
	unsigned char StartOfDataSec	: 1;	
	unsigned char StartOfOverlay	: 1;	
	unsigned char EndOfOverlay		: 1;	
	unsigned char Reserved			: 5;
}PERegions; 
#pragma pack()

#pragma pack(1)

typedef struct
{
	int typeID;
	TCHAR szPath[MAX_PATH];
	TCHAR szStatus[20];
}TOOLBAR_DATA, *LPTOOLBAR_DATA;
#pragma pack()


#pragma pack(1)

typedef struct
{
	TCHAR szBulletinID[20];
	TCHAR szLevel[20];
	TCHAR szDescription[MAX_PATH];
	TCHAR szWindows[20];
	TCHAR szDate[20];
	TCHAR szUrl[MAX_PATH];
}BULLETIN_DATA, *LPBULLETIN_DATA;
#pragma pack()

#pragma pack(1)

typedef struct
{
	TCHAR szCVENumber[MAX_PATH];
	TCHAR szCVEInfo[MAX_PATH];
	TCHAR szOSAffected[MAX_PATH*2];
	TCHAR szKBNumber[MAX_PATH];
}CVE_DATA, *LPCVE_DATA;
#pragma pack()

typedef struct
{
	int			iScannerType;      
	int			eUnpackerType;
	TCHAR		szFile2Unpack[MAX_PATH*2];
	TCHAR		szUnpackedFileName[MAX_PATH*2];
}SHARED_UNPACKER_SWITCH_DATA,*LPSHARED_UNPACKER_SWITCH_DATA;
#pragma pack()

