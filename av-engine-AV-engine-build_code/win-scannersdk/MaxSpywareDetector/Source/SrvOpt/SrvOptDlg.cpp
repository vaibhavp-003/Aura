
#include "pch.h"
#include "SrvOpt.h"
#include "SrvOptDlg.h"
#include "MaxConstant.h"
#include "MigrateRecover.h"
#include "EnumProcess.h"
#include "Registry.h"
#include "SDSystemInfo.h"
#include "CPUInfo.h"
#include "Constants.h"
#include "UninstallOperations.h"
#include "ProductInfo.h"

const UINT TIMER_MIGRATION_PROGRESS = 1000;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

UINT StartApplication(LPVOID lParam);

/*--------------------------------------------------------------------------------------
Function       : CSrvOptDlg
In Parameters  : CWnd* pParent, 
Out Parameters : 
Description    : 
Author         : 
--------------------------------------------------------------------------------------*/
CSrvOptDlg::CSrvOptDlg(CWnd* pParent) : CDialog(CSrvOptDlg::IDD, pParent)
											, m_ctrlPrivacyPolicy(NULL)
{
	m_pMsg_Title_Font = NULL;
	m_pMsg_Sub_Title_Font = NULL;
	m_bShowWindow = FALSE;
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	//calling constructor to set the titlebar
	m_SpyDetectDlgBitmaps = new CSpyDetectDlgBitmaps(this, IDC_STATIC_SELECT_DRIVE_TITLE,
													IDC_STATIC_TITLE_EXTEND,
													NULL,
													NULL,
													NULL,
													IDC_STATIC_TITLEBAR_RIGHT_CORNER,
													IDC_STATIC_CORNER_LEFT_BOTTOM,
													IDC_STATIC_CORNER_RIGHT_BOTTOM);
}

/*--------------------------------------------------------------------------------------
Function       : ~CSrvOptDlg
In Parameters  : 
Out Parameters : 
Description    : 
Author         : 
--------------------------------------------------------------------------------------*/
CSrvOptDlg::~CSrvOptDlg()
{
	if( m_SpyDetectDlgBitmaps )
	{
		delete m_SpyDetectDlgBitmaps;
		m_SpyDetectDlgBitmaps = NULL;
	}
	if(m_pMsg_Title_Font)
	{
		delete m_pMsg_Title_Font;
		m_pMsg_Title_Font = NULL;
	}
	if(m_pMsg_Sub_Title_Font)
	{
		delete m_pMsg_Sub_Title_Font;
		m_pMsg_Sub_Title_Font = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : DoDataExchange
In Parameters  : CDataExchange* pDX, 
Out Parameters : void 
Description    : 
Author         : 
--------------------------------------------------------------------------------------*/
void CSrvOptDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MIGRATE_PROGRESS, m_ctrlMigrateProgress);
	DDX_Control(pDX, IDC_CONTINUE_BUTTON, m_btnContinue);
	DDX_Control(pDX, IDC_STATIC_TITLE, m_stTitle);
	DDX_Control(pDX, IDC_STATIC_MSG_TITLE, m_stMsg_Title);
	DDX_Control(pDX, IDC_STATIC_MSG_SUB_TITLE, m_stMsg_Sub_Title);
	DDX_Control(pDX, IDC_THREAT_YES, m_ctrlThreat_Yes);
	DDX_Control(pDX, IDC_STATIC_SECOND_TOP_LEFT_CORNER, m_stTopLeftCorner);
	DDX_Control(pDX, IDC_STATIC_SECOND_BOTTOM_LEFT_CORNER, m_stBottomLeftCorner);
	DDX_Control(pDX, IDC_STATIC_SECOND_TOP_RIGHT_CORNER, m_stTopRightCorner);
	DDX_Control(pDX, IDC_STATIC_SECOND_BOTTOM_RIGHT_CORNER, m_stBottomRightCorner);
	DDX_Control(pDX, IDC_MIGRATE_ANIMATION, m_MigrateAnim);
	DDX_Control(pDX, IDC_PRIVACY_POLICY, m_ctrlPrivacyPolicy);
	DDX_Control(pDX, IDC_MIGRATE_STATIC, m_ctrlMigrateStatic);
}

BEGIN_MESSAGE_MAP(CSrvOptDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_WM_TIMER()
	ON_WM_CLOSE()
	ON_WM_ERASEBKGND()
	ON_WM_CTLCOLOR()
	ON_WM_WINDOWPOSCHANGING()
	ON_BN_CLICKED(IDC_CONTINUE_BUTTON, &CSrvOptDlg::OnBnClickedContinueButton)
	ON_WM_NCHITTEST()
	ON_BN_CLICKED(IDCANCEL, &CSrvOptDlg::OnBnClickedCancel)
END_MESSAGE_MAP()

/*--------------------------------------------------------------------------------------
Function       : OnInitDialog
In Parameters  : 
Out Parameters : BOOL 
Description    : There are multiple params that can change the behaviour of this app
Author         : 
--------------------------------------------------------------------------------------*/
BOOL CSrvOptDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	CString csCommandLine = GetCommandLine();		
	int iIndex = csCommandLine.Find('#');
	if(iIndex != -1)
	{
		CString csCommandTemp = csCommandLine.Mid(iIndex+1);
		CString csCommand;
		CString csParam;
		iIndex = csCommandTemp.Find ('$');
		if(iIndex != -1)
		{
			csCommand = csCommandTemp.Left (iIndex);
			csParam = csCommandTemp.Mid (iIndex+1);
		}
		else
		{
			csCommand = csCommandTemp;
			csParam = _T("");
		}
		PostQuitMessage(WM_QUIT);
		return TRUE;	
	}		

	if(csCommandLine.Right(6) == _T("PROMPT"))
	{
		int iRet  = ::MessageBox(NULL,CSystemInfo::m_csProductName + _T(" needs to restart the system. Do you want to restart now?"),
								CSystemInfo::m_csProductName,MB_YESNO|MB_ICONQUESTION|MB_TOPMOST );
		CProductInfo objProductInfo;
		if(iRet == IDYES)
		{			
			CRemoteService objRemoteSrc;			
			objRemoteSrc.StartRemoteService(MAXWATCHDOG_SVC_NAME, objProductInfo.GetAppInstallPath() + _T("\\")
											+ MAXWATCHDOG_SVC_EXE , 16, 2 , false , true);	

			//This is required for driver update of sd acive monitor
			CEnumProcess objEnum ;
			objEnum.RebootSystem(); 	
			CDialog::EndDialog(0);
			return TRUE;
		}	
		else
		{
			CMigrateRecover oMigrateRecover;
			oMigrateRecover.AfterInstallSetup(true,false);
			CDialog::EndDialog(0);
			return TRUE;		
		}
	}
	OutputDebugString(csCommandLine);
	if(csCommandLine.Find(L"RESTARTMSG") != -1)
	{		
		CMigrateRecover oMigrateRecover;
		oMigrateRecover.AfterInstallSetup(false, true);
		CDialog::EndDialog(0);
		return TRUE;
	}
	else if(csCommandLine.Right(5) == L"PATCH")
	{		
		CMigrateRecover oMigrateRecover;
		oMigrateRecover.AfterInstallSetup(true,false);
		CDialog::EndDialog(0);
		return TRUE;
	}
	else if(csCommandLine.Find(L"ASKFORRESTART") != -1)
	{		
		CProductInfo objProductInfo;
		CString csAppPath = objProductInfo.GetAppInstallPath() + _T("\\");
		CMigrateRecover oMigrateRecover;
		oMigrateRecover.AskForRestart(csAppPath);
		CDialog::EndDialog(0);
		return TRUE;
	}
	else if(csCommandLine.Right(4) != L"HIDE")
	{
        m_bShowWindow = TRUE;
		m_ctrlMigrateProgress.SetRange(0, 500);
		m_ctrlMigrateProgress.SetPos(0);
		SetTimer(TIMER_MIGRATION_PROGRESS, 150, NULL);
		m_btnContinue.EnableWindow(FALSE);        
		
	} 		

	SetIcon(m_hIcon, TRUE);	// Set big icon
	SetIcon(m_hIcon, FALSE);	// Set small icon

    OnBnClickedContinueButton();
	return TRUE;  // return TRUE  unless you set the focus to a control
}

/*--------------------------------------------------------------------------------------
Function       : OnPaint
In Parameters  : 
Out Parameters : void 
Description    : If you add a minimize button to your dialog, you will need the code below
                 to draw the icon.  For MFC applications using the document/view model,
                 this is automatically done for you by the framework.
Author         :
--------------------------------------------------------------------------------------*/
void CSrvOptDlg::OnPaint()
{
	CDialog::OnPaint();
}

/*--------------------------------------------------------------------------------------
Function       : OnQueryDragIcon
In Parameters  : 
Out Parameters : HCURSOR 
Description    : The system calls this function to obtain the cursor to display while the user drags
                 the minimized window.
Author         : 
--------------------------------------------------------------------------------------*/
HCURSOR CSrvOptDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/*--------------------------------------------------------------------------------------
Function       : StartApplication
In Parameters  : LPVOID lParam, 
Out Parameters : UINT INT 
Description    : Statrs the required applications after installation is completed
Author         : 
--------------------------------------------------------------------------------------*/
UINT StartApplication(LPVOID lParam)
{
	CSrvOptDlg*pThis = (CSrvOptDlg*)lParam;
	if(pThis)
	{
		CMigrateRecover oMigrateRecover;
		oMigrateRecover.AfterInstallSetup(false,false);
	}
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : OnTimer
In Parameters  : UINT_PTR nIDEvent, 
Out Parameters : void 
Description    : To show progress bar moving
Author         : 
--------------------------------------------------------------------------------------*/
void CSrvOptDlg::OnTimer(UINT_PTR nIDEvent)
{
	m_ctrlMigrateProgress.StepIt();
	CDialog::OnTimer(nIDEvent);
}

/*--------------------------------------------------------------------------------------
Function       : OnClose
In Parameters  : 
Out Parameters : void 
Description    : Stops the animation and closes the app
Author         : 
--------------------------------------------------------------------------------------*/
void CSrvOptDlg::OnClose()
{
	if(m_bShowWindow)
	{
		KillTimer(TIMER_MIGRATION_PROGRESS);
		m_MigrateAnim.Stop();
		m_MigrateAnim.UnLoad();
		if(m_ctrlMigrateStatic.Load(MAKEINTRESOURCE(IDR_MIGRATE_STATIC),_T("GIF")))
		{
			m_ctrlMigrateStatic.Draw();
		}
		m_ctrlMigrateProgress.SetPos(500);
		m_btnContinue.EnableWindow(TRUE);
	}
	else
	{
		OnBnClickedContinueButton();
	}
}

/*--------------------------------------------------------------------------------------
Function       : OnBnClickedContinueButton
In Parameters  : 
Out Parameters : void 
Description    : 
Author         : 
--------------------------------------------------------------------------------------*/
void CSrvOptDlg::OnBnClickedContinueButton()
{
	CWinThread *pWinThread = AfxBeginThread(StartApplication, this);
	WaitForSingleObject(pWinThread->m_hThread, INFINITE);
	CDialog::EndDialog(0);
}

/*--------------------------------------------------------------------------------------
Function       : OnEraseBkgnd
In Parameters  : CDC* pDC, 
Out Parameters : BOOL 
Description    : Painting the background and adjusting control position
Author         : 
--------------------------------------------------------------------------------------*/
BOOL CSrvOptDlg::OnEraseBkgnd(CDC* pDC)
{
	//painting the dialog and also the titlebar
	m_SpyDetectDlgBitmaps->DoGradientFill(pDC);

	//to adjust the controls on the dialog
	AdjustControls( pDC );

	return FALSE;
}

/*--------------------------------------------------------------------------------------
Function       : OnCtlColor
In Parameters  : CDC* pDC, CWnd* pWnd, UINT nCtlColor, 
Out Parameters : HBRUSH 
Description    : Making static controls transparent
Author         : 
--------------------------------------------------------------------------------------*/
HBRUSH CSrvOptDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	int ctrlID = pWnd->GetDlgCtrlID();
	if((ctrlID == IDC_STATIC_MSG_TITLE) || (ctrlID == IDC_STATIC_TITLE) ||
		(ctrlID == IDC_STATIC_MSG_SUB_TITLE) || (ctrlID == IDC_STATIC_MSG_1) 
		|| (ctrlID == IDC_STATIC_MSG_2) || (ctrlID == IDC_STATIC_MSG_3) 
		|| (ctrlID == IDC_STATIC_MSG_4) || (ctrlID == IDC_THREAT_YES)
		|| (ctrlID == IDC_THREAT_NO))
	{
		pDC->SetBkMode(TRANSPARENT);
		hbr = (HBRUSH)GetStockObject(NULL_BRUSH);
	}
	return hbr;
}

/*--------------------------------------------------------------------------------------
Function       : OnWindowPosChanging
In Parameters  : WINDOWPOS* lpwndpos, 
Out Parameters : void 
Description    : Hiding the window, when the app is started with the -HIDE param
Author         : 
--------------------------------------------------------------------------------------*/
void CSrvOptDlg::OnWindowPosChanging(WINDOWPOS* lpwndpos)
{
	CDialog::OnWindowPosChanging(lpwndpos);
	if(!m_bShowWindow)
	{
		lpwndpos->flags &= ~SWP_SHOWWINDOW;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: AdjustControls
	In Parameters	: -
	Out	Parameters	: void 
	Purpose			: to adjust all the controls on dialog
	Author			: 
--------------------------------------------------------------------------------------*/
void CSrvOptDlg::AdjustControls( CDC * pDC )
{
	CRect rcDlgRect;
	GetClientRect( &rcDlgRect );

	m_SpyDetectDlgBitmaps ->OnSize( );

	HDWP hdwp = BeginDeferWindowPos( 20 );

	//Adjust dialog's Title
	CRect rcTitleRect;
	m_stTitle.GetClientRect( &rcTitleRect );
	ScreenToClient( &rcTitleRect );
	DeferWindowPos( hdwp , m_stTitle , NULL , rcDlgRect .left + 35, rcDlgRect .top + 7 , rcTitleRect .Width( ) , rcTitleRect .Height( )  , SWP_NOZORDER );

	//drawing rectangle
	int iStart = rcDlgRect .left + 21;
	int iEnd = rcDlgRect .right - 25;
	int nHeight = rcDlgRect .top + rcTitleRect .Height( ) + 28;
	int nBottom = rcDlgRect .bottom - 22;

	CRect rectangle;
	rectangle .SetRect( iStart , nHeight , iEnd , nBottom );

	// Full background white
	pDC ->FillSolidRect( &rectangle , WHITE );

	//left vertical line
	rectangle .SetRect( iStart - 1 , nHeight , iStart + 1 , nBottom );
	pDC ->FillSolidRect( &rectangle , RGB( 62 , 93 , 189 ) );
	//bottom horizontal line
	rectangle.SetRect(iStart, nBottom - 1, iEnd, nBottom + 1);
	pDC ->FillSolidRect( &rectangle , RGB( 62 , 93 , 189 ) );
	//right vertical line
	rectangle .SetRect( iEnd - 1 , nHeight , iEnd + 1 , nBottom );
	pDC ->FillSolidRect( &rectangle , RGB( 62 , 93 , 189 ) );
	//top horizontal line
	rectangle.SetRect(iStart, nHeight, iEnd, nHeight+2);
	pDC ->FillSolidRect( &rectangle , RGB( 62 , 93 , 189 ) );

	EndDeferWindowPos( hdwp );
}

/*--------------------------------------------------------------------------------------
Function       : OnNcHitTest
In Parameters  : CPoint point, 
Out Parameters : LRESULT 
Description    : Allow the use to move the dialog using mouse
Author         : 
--------------------------------------------------------------------------------------*/
LRESULT CSrvOptDlg::OnNcHitTest(CPoint point)
{
	if(!IsZoomed())
	{
		return HTCAPTION;
	}
	return CDialog::OnNcHitTest(point);
}

/*--------------------------------------------------------------------------------------
Function       : OnBnClickedCancel
In Parameters  : 
Out Parameters : void 
Description    : Blocking the default close event, we close the app when we are ready
Author         : 
--------------------------------------------------------------------------------------*/
void CSrvOptDlg::OnBnClickedCancel()
{
	// Do Nothing!
}
