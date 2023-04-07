#include "MaxBMAlgo.h"

CMaxBMAlgo::CMaxBMAlgo(void)
{
	memset(&m_bPattern[0x00],0x00,MAX_PATH);	
	m_dwPatLength = 0x00;
}

CMaxBMAlgo::~CMaxBMAlgo(void)
{
	
}

BOOL CMaxBMAlgo::AddPatetrn2Search(BYTE *pszPatern,DWORD dwLen)
{
	BOOL	bRet = FALSE;

	if (NULL == pszPatern)
		return bRet;

	if (0x00 == dwLen)
		return bRet;

	m_dwPatLength = dwLen;
	memcpy(m_bPattern,pszPatern,dwLen);
	bRet = TRUE;

	return bRet;
}

BOOL CMaxBMAlgo::Search4Pattern(BYTE *pBuffer,DWORD dwBuffLen,DWORD *dwPatternOffset)
{
	BOOL	bRet = FALSE;
	DWORD	dwIndex = 0x00;
	int		iCharPos = 0x00;	

	if (0x00 == dwBuffLen || NULL == pBuffer)
		return bRet;

	for (;dwIndex<dwBuffLen;dwIndex+=m_dwPatLength)
	{
		bRet = IsPatternFound(&pBuffer[dwIndex],(dwBuffLen-dwIndex));
		if (TRUE == bRet)
			break;
		iCharPos = -1;
		
		if (dwIndex == 0x00)
			continue;

		while(1)
		{
			//iCharPos = GetCharPosition(pBuffer[dwIndex],(iCharPos == 0x00 ? iCharPos : iCharPos+1));	
			iCharPos = GetCharPosition(pBuffer[dwIndex],(iCharPos+1));	
			if (-1 == iCharPos)
				break;

			bRet = IsPatternFound(&pBuffer[dwIndex - iCharPos],(dwBuffLen-dwIndex + iCharPos));
			
			if (TRUE == bRet)
			{
				if(dwPatternOffset != NULL)
				{
					if (dwIndex >= iCharPos)
					{
						*dwPatternOffset = dwIndex - iCharPos;
					}
				}
				break;
			}
		}
		if (TRUE == bRet)
			break;

		//dwIndex+=(m_dwPatLength-1);
	}
	
	return bRet;
}

BOOL CMaxBMAlgo::IsPatternFound(BYTE *pBuffer,DWORD dwBuffLen)
{
	BOOL	bRet = FALSE;

	if (pBuffer[0x00] == m_bPattern[0x00])
	{
		if (memcmp(&pBuffer[0x00],&m_bPattern[0x00],m_dwPatLength) == 0x00)
		{
			bRet = TRUE;
			return bRet;
		}
	}

	return bRet;
}

int  CMaxBMAlgo::GetCharPosition(BYTE bChar2Search, DWORD dwStart = 0x00)
{
	int		iRet = -1;
	DWORD	dwIndex = 0x00;

	for(dwIndex = dwStart;dwIndex < m_dwPatLength;dwIndex++)
	{
		if (bChar2Search == m_bPattern[dwIndex])
		{
			iRet = dwIndex;
			break;
		}
	}

	return iRet;
}