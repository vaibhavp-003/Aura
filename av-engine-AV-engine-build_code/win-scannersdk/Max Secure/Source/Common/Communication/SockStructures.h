#pragma once;
#include <string>
#include <vector>
	using namespace std;
#define WSA_VERSION				  MAKEWORD(2,0)
#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

//TODO:should be made Configurable in Registry
const int MAX_CONNECTION        = 80;
const int PORT_CONTROLPORT		= 4999; 
const int PORT_DATA_PORT	    = 5000; 
const int PORT_INFO_PORT	    = 5001; 
const int PORT_LOCAL_PORT		= 5002; 
const int MAX_VM_INSTRUCTIONS   = 50;
/******************************************
 Configurable Sizes: TODO:Registry/INI
 ******************************************/
const int MAX_DOUBLE_FILE_PATH = (MAX_PATH*2);
const int DEFAULT_PACKET_SIZE		= 8192;
const DWORD DEFAULT_TIMEOUT = 100L;
const int DEFAULT_FIELD_SIZE = 50;
const int BATCH_NAME_SIZE = 70;
const int IP_ADDRESS_SIZE = 15;
const int PARTITION_NAME_SIZE = 3;
const int MIN_PARTITION_DISK_FREE = 2; // in GB
const int MAX_BATCH_ALLOCATION_SIZE = 5; // for VM
const int SOCKET_TIMEOUT = 60*45*1000; //45 Minutes
const int ROUTING_TIMEOUT = 60*1*1000; //1 Minute
const int FILETRANFER_TIMEOUT = 60*5*1000; //5 Minutes


/*#ifdef MAX_BOT_AGENT
const TCHAR MAX_CONTROLLER_IPADDR[]					= _T("193.168.0.11");
const TCHAR MAX_CONTROLLER_PORT[]					= _T("5000");
const TCHAR MAX_VMWARE_SERVER_PORT[]				= _T("5000");
const TCHAR MAX_CONTROLLER_MEDUSAPORT[]				= _T("5000");
const TCHAR VM_HANDLER_SERVER_PORT[]				= _T("5000");
const TCHAR CONTROLLER_LOCAL_MEDUSA_IPADDR[]	    = _T("193.168.0.11");
const TCHAR CONTROLLER_LOCAL_SPYWARE_IPADDR[]		= _T("192.168.1.200");
const TCHAR BDB_WHITE_IPADDRESS[]					= _T("193.168.1.108");
const TCHAR BDB_WHITE_PORT[]						= _T("5001");
const TCHAR BDB_IPADDRESS[]							= _T("193.168.1.108");
const TCHAR SMS_GATEWAY[]							= _T("193.168.0.73");
const TCHAR SMS_GATEWAY_PORT[]						= _T("5000");
const TCHAR VMWARE_PORT[]							= _T("5000");

const TCHAR DOWNLOADMGR_WHITE_IPADDRESS[]			= _T("193.168.1.108");
const TCHAR DOWNLOADMGR_BLACK_IPADDRESS[]			= _T("193.168.0.63");
const TCHAR CRAWLER_WHITE_IPADDRESS[]				= _T("193.168.1.14");
const TCHAR CRAWLER_BLACK_IPADDRESS[]				= _T("193.168.1.63");
const TCHAR DOWNLOADMGR_PORT[]						= _T("5001");
const TCHAR CRAWLER_PORT[]							= _T("4999");

const TCHAR MAX_CONTROLLER_WHITE_IPADDR[]			= _T("193.168.0.11");
const TCHAR MAX_CONTROLLER_WHITE_PORT[]				= _T("5000");
const TCHAR CONTROLLER_LOCAL_WHITE_IPADDR[]			= _T("193.168.0.11");
#else
const TCHAR MAX_CONTROLLER_IPADDR[]					= _T("193.168.0.11");
const TCHAR MAX_CONTROLLER_PORT[]					= _T("5000");
const TCHAR MAX_VMWARE_SERVER_PORT[]				= _T("5000");
const TCHAR MAX_CONTROLLER_MEDUSAPORT[]				= _T("5000");
const TCHAR VM_HANDLER_SERVER_PORT[]				= _T("4999");
const TCHAR CONTROLLER_LOCAL_MEDUSA_IPADDR[]	    = _T("193.168.0.11");
const TCHAR CONTROLLER_LOCAL_SPYWARE_IPADDR[]		= _T("193.168.1.108");
const TCHAR BDB_WHITE_IPADDRESS[]					= _T("193.168.1.108");
const TCHAR BDB_WHITE_PORT[]						= _T("5000");
const TCHAR BDB_IPADDRESS[]							= _T("193.168.1.108");
const TCHAR SMS_GATEWAY[]							= _T("193.168.0.73");
const TCHAR SMS_GATEWAY_PORT[]						= _T("4999");
const TCHAR VMWARE_PORT[]							= _T("4999");

const TCHAR DOWNLOADMGR_WHITE_IPADDRESS[]			= _T("193.168.1.108");
const TCHAR DOWNLOADMGR_BLACK_IPADDRESS[]			= _T("193.168.0.63");
const TCHAR CRAWLER_WHITE_IPADDRESS[]				= _T("193.168.1.14");
const TCHAR CRAWLER_BLACK_IPADDRESS[]				= _T("193.168.1.63");
const TCHAR DOWNLOADMGR_PORT[]						= _T("5001");
const TCHAR CRAWLER_PORT[]							= _T("4999");

const TCHAR MAX_CONTROLLER_WHITE_IPADDR[]			= _T("193.168.0.11");
const TCHAR MAX_CONTROLLER_WHITE_PORT[]				= _T("5000");
const TCHAR CONTROLLER_LOCAL_WHITE_IPADDR[]			= _T("193.168.0.11");
#endif
*/

#ifdef MAX_BOT_AGENT
const TCHAR MAX_CONTROLLER_IPADDR[]					= _T("192.168.1.108");
const TCHAR MAX_CONTROLLER_PORT[]					= _T("5000");
const TCHAR MAX_VMWARE_SERVER_PORT[]				= _T("5000");
const TCHAR MAX_CONTROLLER_MEDUSAPORT[]				= _T("5000");
const TCHAR VM_HANDLER_SERVER_PORT[]				= _T("5000");
const TCHAR CONTROLLER_LOCAL_MEDUSA_IPADDR[]	    = _T("192.168.1.108");
const TCHAR CONTROLLER_LOCAL_SPYWARE_IPADDR[]		= _T("192.168.1.200");
const TCHAR BDB_WHITE_IPADDRESS[]					= _T("192.168.0.108");
const TCHAR BDB_WHITE_PORT[]						= _T("5001");
const TCHAR BDB_IPADDRESS[]							= _T("193.168.0.21");
const TCHAR SMS_GATEWAY[]							= _T("193.168.0.73");
const TCHAR SMS_GATEWAY_PORT[]						= _T("5000");
const TCHAR VMWARE_PORT[]							= _T("4999");

const TCHAR DOWNLOADMGR_WHITE_IPADDRESS[]			= _T("192.168.1.253");
const TCHAR DOWNLOADMGR_BLACK_IPADDRESS[]			= _T("192.168.1.253");
const TCHAR CRAWLER_WHITE_IPADDRESS[]				= _T("193.168.1.14");
const TCHAR CRAWLER_BLACK_IPADDRESS[]				= _T("192.168.1.252");
const TCHAR DOWNLOADMGR_PORT[]						= _T("5001");
const TCHAR CRAWLER_PORT[]							= _T("4999");

const TCHAR MAX_CONTROLLER_WHITE_IPADDR[]			= _T("192.168.1.108");
const TCHAR MAX_CONTROLLER_WHITE_PORT[]				= _T("5000");
const TCHAR CONTROLLER_LOCAL_WHITE_IPADDR[]			= _T("192.168.1.108");
#else
const TCHAR MAX_CONTROLLER_IPADDR[]					= _T("192.168.1.108");
const TCHAR MAX_CONTROLLER_PORT[]					= _T("5000");
const TCHAR MAX_VMWARE_SERVER_PORT[]				= _T("4999");
const TCHAR MAX_CONTROLLER_MEDUSAPORT[]				= _T("5000");
const TCHAR VM_HANDLER_SERVER_PORT[]				= _T("4999");
const TCHAR CONTROLLER_LOCAL_MEDUSA_IPADDR[]	    = _T("192.168.1.108");
const TCHAR CONTROLLER_LOCAL_SPYWARE_IPADDR[]		= _T("192.168.1.200");
const TCHAR BDB_WHITE_IPADDRESS[]					= _T("192.168.0.108");
const TCHAR BDB_WHITE_PORT[]						= _T("5001");
const TCHAR BDB_IPADDRESS[]							= _T("192.168.0.108");
const TCHAR SMS_GATEWAY[]							= _T("193.168.0.73");
const TCHAR SMS_GATEWAY_PORT[]						= _T("4999");
const TCHAR VMWARE_PORT[]							= _T("4999");

const TCHAR DOWNLOADMGR_WHITE_IPADDRESS[]			= _T("192.168.1.253");
const TCHAR DOWNLOADMGR_BLACK_IPADDRESS[]			= _T("192.168.1.253");
const TCHAR CRAWLER_WHITE_IPADDRESS[]				= _T("193.168.1.14");
const TCHAR CRAWLER_BLACK_IPADDRESS[]				= _T("192.168.1.252");
const TCHAR DOWNLOADMGR_PORT[]						= _T("5001");
const TCHAR CRAWLER_PORT[]							= _T("4999");

const TCHAR MAX_CONTROLLER_WHITE_IPADDR[]			= _T("192.168.1.108");
const TCHAR MAX_CONTROLLER_WHITE_PORT[]				= _T("5000");
const TCHAR CONTROLLER_LOCAL_WHITE_IPADDR[]			= _T("192.168.1.108");
#endif





const TCHAR DATABASE_ZIP_FILENAME[]					= _T("ToTransfer.zip");
const TCHAR PARSER_AUTOMATION_FOLDER[]				= _T("e:\\Parser\\Automated Parsing\\Black Automation");
const TCHAR PARSER_NOINFECTION_FOLDER[]				= _T("e:\\Parser\\Automated Parsing\\Black NoInfection");
const TCHAR PARSER_COPYFAILED_FOLDER[]				= _T("e:\\Parser\\Automated Parsing\\CopyFailed");
const TCHAR PARSER_WHITE_AUTOMATION_FOLDER[]		= _T("e:\\Parser\\Automated Parsing\\White Automation");
const TCHAR REPARSER_BLACK_AUTOMATION_FOLDER[]		= _T("e:\\Parser\\Automated Parsing\\Reparse");
const TCHAR REPARSER_WHITE_AUTOMATION_FOLDER[]		= _T("e:\\Parser\\Automated Parsing\\WhiteReparse");
const TCHAR PARSER_PRIORITY_AUTOMATION_FOLDER[]		= _T("e:\\Parser\\Automated Parsing\\Priority Black");
const TCHAR PARSER_PRIORITY_VIRUS_FOLDER[]			= _T("e:\\Parser\\Automated Parsing\\Priority Virus");
const TCHAR PARSER_PRIORITY_WHITE_FOLDER[]			= _T("e:\\Parser\\Automated Parsing\\Priority White");
const TCHAR AUTO_OUTPUT_MOD_FOLDER[]				= _T("e:\\Parser\\Automated Parsing\\Modified");
const TCHAR AUTO_OUTPUT_VIRUS_FOLDER[]				= _T("e:\\Parser\\Automated Parsing\\Virus Automation");
const TCHAR AUTO_OUTPUT_BAD_FOLDER[]				= _T("e:\\Parser\\Automated Parsing\\Bad");
const TCHAR AUTO_OUTPUT_DBFAIL_FOLDER[]				= _T("e:\\Parser\\Automated Parsing\\Black DBTesting Failed");
const TCHAR VMSETTINGS_DATAFOLDER[]					= _T("\\VMSetting\\Data");
const TCHAR BDB_PROCESSED_BINARYFOLDER[]			= _T("F:\\BinaryDump\\Temp");
const TCHAR BDB_MANUAL_BINARYFOLDER[]				= _T("F:\\BinaryDump\\Manual");
const TCHAR VM_SETTING_TEMP[]					    = _T("C:\\VMSetting\\Temp\\");
const TCHAR VM_SETTING_UPDATES[]					= _T("C:\\VMSetting\\Updates\\");
const TCHAR AUTOMATION_TEMP_PATH[]					= _T("C:\\Automation\\Temp");

const TCHAR BOT_INPUT_FOLDER_PATH[]                 = _T("F:\\BinaryDump\\BotDump");
//const TCHAR BOT_PRIORITY_FOLDER_PATH[] 					= _T("F:\\BinaryDump\\BotPriorityDump");

const TCHAR VM_REGSHOT_FILENAME[]					= _T("RegShot.ini");
const TCHAR VM_AUTO_CONFIG_FILENAME[]				= _T("AutoConfiguration.ini");
const TCHAR VM_UPGRADE_PATCH_FILENAME[]				= _T("AutomationPatch.exe");
const TCHAR VM_UPGRADE_IMAGE_FILENAME[]				= _T("FreshImage.rar");
const TCHAR VM_UPGRADE_3RDPARTY_FILENAME[]			= _T("ExternalSetup.rar");


const TCHAR MAX_AUTOMATION_ALERT[]					= _T("Automation Alert!!!");
const TCHAR COMM_LOG_FILE[]							= _T("Communication.Log");
const TCHAR COMM_UI_LOG_FILE[]						= _T("CommUI.Log");
const TCHAR COMM_VM_LOG_FILE[]						= _T("VMCommunication.Log");
const TCHAR VM_REGSHOT_CONFIGPATH[]					= _T("D:\\Controller\\Updates\\RegShot.ini");
const TCHAR VM_AUTO_CONFIGPATH[]					= _T("D:\\Controller\\Updates\\AutoConfiguration.ini");
const TCHAR VM_UPGRADE_PATCH_PATH[]					= _T("D:\\Controller\\Updates\\AutomationPatch.exe");
const TCHAR VM_UPGRADE_IMAGE_PATH[]					= _T("D:\\Controller\\Updates\\Research Image Final.rar");
const TCHAR VM_UPGRADE_3RDPARTY_PATH[]				= _T("D:\\Controller\\Updates\\ExternalSetup.rar");
/******************************************
 Socket Events
 ******************************************/
// Event value
#define EVT_CONSUCCESS      0x0000  // Connection established
#define EVT_CONFAILURE      0x0001  // General failure - Wait Connection failed
#define EVT_CONDROP         0x0002  // Connection dropped
#define EVT_ZEROLENGTH      0x0003  // Zero length message
#define EVT_SHUTDOWN  0x0004  // Zero length message

/******************************************
 Message Categories For Communication
 ******************************************/
const int MA_Message_Info_TYPE_CONTROL		      = 0;
const int MA_Message_Info_TYPE_DATA			      = 100;
const int MA_Message_Info_TYPE_VMAUTOMATION		  = 200;
const int MA_Message_Info_TYPE_ADMIN		      = 300;
const int MA_Message_Info_TYPE_CUSTOM		      = 400;

enum MA_Message_Info
{
	// Type Of Value Passed
	MA_Connection_Header = MA_Message_Info_TYPE_CONTROL,
	MA_Control_Header,
	MA_Notify_Duplicate_Files,
	MA_Check_Duplicate_Files,
	MA_Notify_Register_Files,
	MA_Register_Files,
	MA_Files_Registered,
	MA_Get_Available_VM,
	MA_VM_Info,
	MA_Notify_VM_BatchInfo,
	MA_Update_Batch_Status,
	MA_Update_VM_DiskSpace,
	MA_Start_File_Transfer,						
	MA_End_File_Transfer,
	MA_File_Received,
	MA_File_Save_Error,
	MA_SendVM_Output,
	MA_Resend_VMOutput,
	MA_SendDBTesting_Output,
	MA_Generate_DB,
	MA_Get_DBTestingFiles,
	MA_Send_DBTestingFiles,
	MA_Report_Error,
	MA_Generate_Alert,
	MA_WatchDog_Register_Node,
	MA_WatchDog_Node_Crashed,
	MA_Submit_Binary_DataBank,
	MA_Assign_Queue_VM,
	MA_Submit_Processed_Binary_DataBank,
	MA_Processed_Priority_Binary,
	MA_Notify_Download_Task,
	MA_Download_Task,
	MA_CreateDownloadTask,
	MA_Update_Download_Task_Status,
	MA_Unregister_QueueVM,
	MA_WatchDog_Register_Controller,
	MA_WatchDog_Controller_Down,
	MA_Shutdown_VMWare,
	MA_Finish_Stop_VMWare,
	MA_Restart_VMWare,
	MA_Batch_Status_Updated,
	MA_Batch_Status_Failed,
	MA_Input_File_Search,
	MA_Output_File_Search,
	MA_Host_Log_File,
	MA_Notify_Crawler_Task,
	MA_Crawler_Task,
	MA_CreateCrawlerTask,
	
	VM_Automation_Start = MA_Message_Info_TYPE_VMAUTOMATION,
	VM_InitAutomationConfig,
	VM_Perform_Instructions,
	VM_Started_Instructions,
	VM_Register_with_Watchdog,
	VM_Update_File,
	VM_Upgrade_Patch,
	VM_Upgrade_VMImage,
	VM_Install_3rdParty,
	VM_Change_IP,
	VM_Change_PCName,
	VM_Change_PCTime,
	VM_Update_Success,
	VM_Update_Fail,
	VM_Send_VM_Input,
	VM_Checkpoint_Status,
	VM_Send_VM_Output,
	VM_Send_Alert,
	VM_Send_KeepAlive,
	VM_Send_Alive,
	VM_Restart_Automation_EXE,
	VM_Output_Success,
	VM_Output_Success_Modified,
	VM_Output_Success_Virus,
	VM_Output_BadInput,
	VM_Output_DBTest_Fail,
	VM_Upgrade_RegShotINI,
	VM_Upgrade_AutomationINI,
	VM_WatchDog_Node_Down,
	VM_Output_NoInfection,
	VM_Upgrade_Host,
	VM_Output_RequiredManual_Input,
	VM_Output_FailedToCopy_Binary
};
//Batch Status
//***Update BatchStatus Stored Procedure should also be synchronized on any change
enum MA_Batch_Status
{
	// Type Of Value Passed
	e_Batch_Registered,
	e_Batch_Start,
	e_Automation_Start,
	e_Automation_Failure,
	e_Automation_End,
	e_Waiting_For_Review,
	e_DB_Transferred,
	e_DBTesting_Start,
	e_DBTesting_Failure,
	e_DBTesting_End,
	e_Batch_End,
	e_Batch_Failure,
	e_Batch_Processing_NotRequired,
	e_Batch_BadInput,
	e_Batch_Modified,
	e_Batch_VirusOutput,
	e_DBTesting_Modified,
	e_DBTesting_Bad,
	e_DBTesting_VirusOutput,
	e_Automation_NoInfection,
	e_Batch_RequiredManualInput,
	e_Batch_CopyFail, //failed to copy binary for MD5 / EP
	e_DBTesting_CopyFail
};
//IMP*** Do Not insert in between the Batch Status

enum MA_Batch_Type
{
	e_Batch_Spyware,
	e_Batch_White,
	e_Batch_Virus,
	e_Batch_MaxBot
};

enum MA_Download_Task_Status
{
	e_URL_Waiting_For_URL,
	e_URL_Waitng_For_Download,
	e_URL_Assigned_Queue,
	e_URL_Download_Start,
	e_URL_Download_Failed,
	e_URL_Invalid_Path,
	e_URL_Download_Done
};

enum MA_Download_Task_Priority
{
	e_DT_Low,
	e_DT_High
};

enum MA_URL_Type
{
	eUnknown_URLType = -1,
	eWhite_DownloadURL = 0,
	eBlack_DownloadURL,
	eWhite_CrawlerURL,
	eBlack_CrawlerURL,
	eBlack_Xandora_DownloadURL,
	eBlack_Xandora_DownloadURL1
};

enum MA_VM_Status
{
	e_VMUp,
	e_VMDown
};

enum MA_Node_Status
{
	e_NodeUp,
	e_NodeDown
};

enum MA_Binary_Source_Type
{
	eVendor,
	e_ManualBrowsing,
	e_Forums,
	e_MaxBot,
	e_Client,
	e_RegShot,
	e_MaxVirusScan,
	e_MaxSunbelt,
	e_MaxThreatCom,
	e_MaxKasp
};

enum MA_File_Types
{
	eSpyware_EXE,
	eSpyware_DLL,
	eVirus_DLL,
	eVirus_EXE,
	eGEN_EXE,
	eGEN_DLL,
	eScript_File,
	eBatch_File,
	eDB_File,
	eDB_Testing_Results,
	eAutomation_Output_File,//Success
	eProcessed_Binary_Files,
	eUpgrade_File,
	eGEN_FILES,
	eAutomation_Modified_Output_File,
	eAutomation_Virus_Output_File,
	eAutomation_Bad_Output_File,
	eAutomation_DBTesting_Failed_Output_File,
	eWhite_EXE,
	eWhite_DLL,
	eRegShot_INI,
	eAutomation_INI,
	eAutomation_Patch,
	eUpdate_VMImage,
	eInstall_3rdParty,
    eInputFile_Extract,
	eUpdate_Host,
	eAutomation_NoInfection_Output_File,
	eAutomation_RequiredManual_Input_File,
	eAutomation_FailedToCopy_Binary_File,
	eMaxBot_Binary_Files
};

enum MA_Application_Type
{
	eSpyware_SnapShot,
	eWhite_SnapShot,
	eVirus_SnapShot,
	eMax_MaxBot,
	eMax_MaxDownloadMgr
};

enum MA_Domain_Category
{
	eUnClassified,
	eGames_Site,
	ePorn_Site,
	eDownload_Site,
	eNews_Site,
	eSecurity_Software,
	eScreenSavers_WallpapersSite,
	eMultiMedia_Site,
	eTools_Site,
	eDrivers_Site,
	eBusiness_Software,
	eDesktop_Software,
	eCommunication_Site,
	eNetworking_Software,
	eUtilities_Software,
	eVideo_Software,
	eMP3_Audio_Software,
	eWindows_Update,
	eEntertainment_Software
};

enum MA_Domain_Type
{
	eWhite_Domain,
	eBlack_Domain
};

enum MA_Protocol_Type
{
	eProtocol_HTTP,
	eProtocol_FTP
};
enum MAX_NETWORK_TYPE
{
	MEDUSA_NETWORK,
	AUTOMATION_NETWORK	
};

/******************************************
Enum for VM AUTOMATION
******************************************/
enum VM_Automation_Config
{
	e_BrowsingSites
	
};

enum VM_Instruction_Status
{
	eInstNotStarted,//0 
	eStartInstruction,//1
	eLastInstruction,//2
	eEndInstructionSuccess,//3
	eFailedInstructions//4
	
};
typedef enum 
{
	eRegister_Components,
	eKeepAlive_Request,
	eExecute_Spywares,
	eTake_Screenshots,
	eSystem_TrayClick,
	eFirst_RegShot,
	eTemp_RegShot,
	eStart_Browsing,
	eEnd_Browsing,
	eRestart_VM,
	eStopVM,
	eLaunch_Scanner,
	eLaunch_Scanner_Without_Rootkit,
	eTakeSecond_RegShot,
	eCapture_Resource,
	eExecute_VirusApp,
	eSaveVMLog,
	eUpdateFile,
	eUpgradePatch,
	eInstall3rdParty,
	eChangeIP,
	eChangePCName,
	eChangePCTime,
	eLoadUserHive,
	eWaitForNetworkActivity,
    eInputFileExtract,
    eAfter_Restart_Launch_Scanner,
    eLaunch_Scanner_With_Virus,
	/******Internal Instructions*******/
	eMonitorCPU,
	eMonitorMemory,
	eMonitorDiskUsage,
	/******Internal Instructions*******/
	eStart_Resource_Monitor,//Should be after eExecute_Spywares
	eExecuteApp,//For starting any Process E.g. Explorer, Winword with Command Line Parameter
	eStop_Resource_Monitor,
	ePauseInstruction,
	eButton_Click,
	eCleanAllLogs,
	eCheckVirusType,
	eEndofInstructions//Always Add a new instruction Before this
}VM_Automation_Instructions;

/******************************************
 struct for Start of Every Communication
 ******************************************/
const BYTE MAHEADER[39] = "{A11DA7C0-7FD9-4649-9DC2-64260FFF1353}";


enum eSTRUCT_TYPE{
	eFILE_REGISTRATION_INFORMATION = 1,
	eBATCH_REGISTRATION_INFORMATION,
	eFILE_INFORMATION,
	eBATCH_INFORMATION,
	eVM_INFORMATION,
	eNODE_INFORMATION,
	eCATEGORY_INFORMATION,
	eURL_INFORMATION,
	eVM_NODE_INFORMATION,
	eCONTROL_INFORMATION,
	eDOWNLOAD_TASK_INFORMATION,
	eVM_AUTOMATION_CONFIG, //Used by VMWARE Automation
	eVM_AUTOMATION_INSTRUCTION,
	eMA_FILE_SEARCHTRANSFER
};

#pragma pack(1)
typedef	struct
{
	BYTE MsgGUID[39];
	DWORD dwPacketSize;
	bool m_bRouting;
	TCHAR szDestRoutingAddress[IP_ADDRESS_SIZE]; 
	TCHAR szDestRoutingPort[IP_ADDRESS_SIZE]; 
	TCHAR szRoutingLocalIPAddr[IP_ADDRESS_SIZE]; 
}MA_HEADERINFO,*LPMA_HEADERINFO;
#pragma pack()

#pragma pack(1)
typedef struct tagCONTROL1
{
	WORD vt;
	MA_Message_Info eMessageInfo;			//MA_Message_Info
	bool bOverwrite;//Default False
	bool bRouting;
	bool bFlashAlert;
	bool bMonitorConnection;
	DWORD dwPriority;//0 Low 1 Medium
	DWORD dwStartByte;
	DWORD dwMsgCount;
	TCHAR szFileDestinationLocation[MAX_PATH]; 
	TCHAR szDescription[MAX_PATH]; 
	TCHAR m_szPeerName[DEFAULT_FIELD_SIZE]; 
	union{
		//CATALOG_DB-STRUCTURES
		struct tag_MA_FILE_INFORMATION
		{
			bool bDuplicate;
			WORD  wStatus;
			WORD  wFileType;
			WORD  wSourceType;
			DWORD dwFileID;
			DWORD dwCategoryID;
			DWORD dwURLID;
			LONGLONG dwFileSize;
			TCHAR szRegistrationTime[20];
			BYTE bMD5[16];
			TCHAR szFileName[MAX_DOUBLE_FILE_PATH];
			TCHAR szThreatName[DEFAULT_FIELD_SIZE];
		}MA_FILE_INFORMATION,*LPMA_FILE_INFORMATION;				// CheckDuplicate & Register File

		struct tag_MA_URL_INFORMATION
		{
			DWORD dwURLID;
			DWORD dwContentLength;
			TCHAR szURLName[1024];
			TCHAR szLastModifiedTime[35];
			WORD  wProtocolType;									// MA_Protocol_Type
			TCHAR Etag[50];
			DWORD dwAge;
			TCHAR szProductName[MAX_PATH];
		}MA_URL_INFORMATION,*LPMA_URL_INFORMATION;					// insert url details add attach with file info

		struct tag_MA_Domain_INFORMATION
		{
			DWORD dwDomainID;
			TCHAR szDomainAddress[MAX_PATH];
			DWORD dwDomainType;										// MA_Domain_Type
			DWORD dwDomainCategory;									// MA_Domain_Category
		}MA_DOMAIN_INFORMATION,*LPMA_DOMAIN_INFORMATION;			// insert domain details attached with URL info

		struct tag_MA_Download_Task
		{
			DWORD dwDownloadID;
			DWORD dwURLID;
			WORD  wStatus;											// MA_Download_Task_Status
			TCHAR szRegistrationTime[20];									
			ULONG ulLastVisited;
			WORD  wPriority;										// MA_Download_Task_Priority
			DWORD dwURLType;										// MA_URL_Type
			WORD  wReVisitDuration;									// define duration in Days to revist this URL
		}MA_DOWNLOAD_TASK,*LPMA_DOWNLOAD_TASK;						//insert url details add attach with file info

		struct tag_MA_BATCH_INFORMATION
		{
			DWORD dwBatchID;								//MA_Update_Batch_Status// DBManager creats
			DWORD dwParentBatchID;							// NULL
			DWORD dwFileIDStart;							// Fill file and set start and end
			DWORD dwFileIDEnd;
			WORD wVMID;										// NULL - Assign vmid accroding to availablity
			WORD wStatus;									//MA_Update_Batch_Status// Batch registered
			TCHAR szRegistrationTime[20];						// GETDATE()
			TCHAR szAutomationStartTime[20];						// NULL
			TCHAR szAutomationEndTime[20];						// NULL
			TCHAR szDBTestingStartTime[20];						// NULL
			TCHAR szDBTestingEndTime[20];						// NULL
			TCHAR szBatchName[BATCH_NAME_SIZE];				// Batch Name
			float wBatchFileSize;							// Size of the batch ( size of all files from dwFileIDStart to dwFileIDEnd)
			WORD wBatchType;								// MA_Batch_Type
		}MA_BATCH_INFORMATION,*LPMA_BATCH_INFORMATION;		// 

		struct tag_MA_VM_INFORMATION
		{
			DWORD dwVMID;									// MA_Update_VM_DiskSpace query
			DWORD dwNodeID;
			DWORD dwCurrentBatchID; 
			WORD wStatus;									// new assignment will be done only if its e_VMUp
			WORD wVMNoOfProcessors;
			WORD wVMProcessorType;
			float wVMRAMSize;
			float wVMDiskSize;		
			float wNodePartitionDiskSize;
			float wNodePartitionDiskFree;					//MA_Update_VM_DiskSpace	// has to be greater than batch size + MIN_PARTITION_DISK_FREE
			WORD wNoOfBatchesAssigned;						//MA_Update_VM_DiskSpace	
			TCHAR szLastUpdateTime[20];
			TCHAR szIPAddress[IP_ADDRESS_SIZE];				//MA_Update_VM_DiskSpace input
			TCHAR szMachineName[DEFAULT_FIELD_SIZE];
			TCHAR szOSInfo[DEFAULT_FIELD_SIZE];
			TCHAR szPartitionName[PARTITION_NAME_SIZE];
			DWORD dwApplicationType;						//MA_Application_Type
		}MA_VM_INFORMATION,*LPMA_VM_INFORMATION;			// updatevmstatus

		struct tag_MA_NODE_INFORMATION
		{
			DWORD dwNodeID;
			WORD wStatus;
			float wHardDiskSize;
			float wHardDiskFree;
			float wRAMSize;
			WORD wNoOfProcessors;
			WORD wProcessorType;
			WORD wNoOfPartitions;
			TCHAR szNodeIPAddress[IP_ADDRESS_SIZE];
			TCHAR szNodeOSInfo[DEFAULT_FIELD_SIZE];
			TCHAR szMachineName[DEFAULT_FIELD_SIZE];
			TCHAR szPartitionName[PARTITION_NAME_SIZE];
		}MA_NODE_INFORMATION,*LPMA_NODE_INFORMATION;		

		struct tag_MA_CATEGORY_INFORMATION
		{
			DWORD dwCategoryID;
			TCHAR szCategoryName[DEFAULT_FIELD_SIZE];
			WORD wBatchSize;
			TCHAR szDescription[DEFAULT_FIELD_SIZE];

		}MA_CATEGORY_INFORMATION,*LPMA_CATEGORY_INFORMATION;		//get batch size by categoryname
		
		struct tag_MA_File_SearchTransfer
		{
			TCHAR szBatchName[MAX_PATH];
			TCHAR szFileDestIPAddress[IP_ADDRESS_SIZE];
			TCHAR szFileDestPortNo[IP_ADDRESS_SIZE];
			int iBatchStatus;
			
		}MA_FILE_SEARCHTRANSFER,*LPMA_FILE_SEARCHTRANSFER;
		
		struct tagCONTROL7
		{
			tag_MA_FILE_INFORMATION sMA_FILE_INFORMATION;
			tag_MA_URL_INFORMATION sMA_URL_INFORMATION;
			tag_MA_CATEGORY_INFORMATION sMA_CATEGORY_INFORMATION;
		}FILE_REGISTRATION_INFORMATION,*LPFILE_REGISTRATION_INFORMATION;

		struct tagCONTROL8
		{
			tag_MA_BATCH_INFORMATION sMA_BATCH_INFORMATION;
			tag_MA_VM_INFORMATION sMA_VM_INFORMATION;
			tag_MA_NODE_INFORMATION sMA_NODE_INFORMATION;
		}BATCH_REGISTRATION_INFORMATION,*LPBATCH_REGISTRATION_INFORMATION;

		struct tagCONTROL9
		{
			DWORD dwBatchID;
			tag_MA_VM_INFORMATION sMA_VM_INFORMATION;
			tag_MA_NODE_INFORMATION sMA_NODE_INFORMATION;
		}VM_NODE_INFORMATION,*LPVM_NODE_INFORMATION;

		struct tagCONTROL10
		{
			tag_MA_URL_INFORMATION sMA_URL_INFORMATION;
			tag_MA_Domain_INFORMATION sMA_Domain_INFORMATION;
			tag_MA_Download_Task sMA_Download_Task;
		}DOWNLOAD_TASK_INFORMATION,*LPDOWNLOAD_TASK_INFORMATION;

		struct tagVMAutomationConfig
		{
			int	  nProcessType; //;0: Regshot ;1: Db testing
			bool  bMonitorLSP;//1: default
			int	  nMaxCpuUsage;//80 ; = 0 Do not Monitor 
			int	  nTotalInstructions;//No of instructions to be executed
			float fMaxMemoryUsage;//= 0 Do not Monitor
			float fMaxDiskUsage;//= 0 Do not Monitor
			TCHAR szNodeIPAddress[IP_ADDRESS_SIZE];
			TCHAR szNodePortNo[IP_ADDRESS_SIZE];
			TCHAR szVMIPAddress[IP_ADDRESS_SIZE];
			TCHAR szVMPortNo[IP_ADDRESS_SIZE];
			TCHAR szOutputFolder[MAX_PATH];
			WORD  NoOfProcessors;
		}VM_AUTOMATION_CONFIG,*LPVM_AUTOMATION_CONFIG;
		
		struct tagVMAutomationInstructions
		{
			VM_Automation_Instructions eVMInstruction;
			VM_Instruction_Status eVMInstructionStatus;
			TCHAR szInstStartTime[20];
			TCHAR szInstEndTime[20];
			TCHAR szLastUpdateTime[20];
			TCHAR szInstParameter[MAX_PATH];//Used as Buffer for sending Parameters which can be Structure or Character strings or Binary Data
			int nMaxTime;//seconds
			int nInstOrder;
			TCHAR szVMIPAddress[IP_ADDRESS_SIZE];
		}VM_AUTOMATION_INSTRUCTION,*LPVM_AUTOMATION_INSTRUCTION;
	};

} MA_CONTROL_REQUEST,*LPMA_CONTROL_REQUEST;
#pragma pack()

const int SIZE_OF_MA_CONTROL_REQUEST		= sizeof(MA_CONTROL_REQUEST);
const int MA_HEADER_SIZE = sizeof(MA_HEADERINFO);

typedef std::vector<MA_CONTROL_REQUEST> MAControlVector;
typedef std::vector<MA_CONTROL_REQUEST*> MAControlVectorPtr;

enum SOCKET_ERROR_CODE
{
	ENUM_FIREWALL_BLOCKING,
	ENUM_SUCCESS,
	ENUM_SOCKET_OPEN,
	ENUM_INVALID_SOCKET,
	ENUM_SOCKET_ERROR,
	ENUM_VERSION_DIFF,
	ENUM_VERSION_SAME
};