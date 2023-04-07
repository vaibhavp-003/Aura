#include "StdAfx.h"
#include "CRTCheck.h"

/**********DECLARE THIS IN EVERY CPP FILE*************************/
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
/******************************************************************/

CCRTCheck::CCRTCheck(void)
{

}

CCRTCheck::~CCRTCheck(void)
{
	
}

void CCRTCheck::InitializeCRTCheck()
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_CRT_DF);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
}

void CCRTCheck::CheckMemory()
{
	_CrtCheckMemory(); // Reports the problem without file/line info at first (bad), but if you hit 
	_CrtDumpMemoryLeaks();
}