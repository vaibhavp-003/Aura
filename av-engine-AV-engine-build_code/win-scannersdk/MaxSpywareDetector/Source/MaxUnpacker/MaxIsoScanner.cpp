#include "MaxIsoScanner.h"
#include <stdlib.h>
#include <string.h>

CMaxIsoScanner::CMaxIsoScanner(CMaxPEFile *pMaxSecureFile/*, CDBManager *pDBManager):CMaxScannerBase(VIRUS_FILE_TYPE_PDF, pMaxSecureFile, pDBManager*/)
{
	m_pbyBuffer = NULL;
	iFileSize = 0x00;
	iOffset = 0x00;
	iBuffSize = 0x4000;
	m_iTotalBytesWritten = 0x00;
	iBytesWritten = 0x00;
	iFileCnt = 0x00;

	bIsBigIndian = false;
	
	m_pMaxSecureFile = pMaxSecureFile;

	iFileSize = m_pMaxSecureFile->m_dwFileSize;
	parts = NULL;
	FIN = NULL; 
	FOUT = NULL; 
	FDBG = NULL;
	debug = 0;
	verbose = 1;
	listparts = 0;
	extractpart = -1;

	i = 0x00, err = 0x00, partnum = 0x00, scb = 0x00;
	tmp = NULL;
	otmp = NULL;
	dtmp = NULL;
	plist = NULL; 
	blkx = NULL;
	blkx_size = 0x00;
	data_begin = NULL;
	data_end = NULL;
	partname_begin = NULL;
	partname_end = NULL;
	mish_begin = NULL;
	partlen = NULL;
	data_size = 0x00;
	out_offs = 0x00, out_size = 0x00, in_offs = 0x00, in_size = 0x00, in_offs_add= 0x00, add_offs = 0x00, to_read = 0x00,
	      to_write, chunk = 0x00;
	block_type = 0x00, dw_reserved = 0x00;

	//strcpy(m_szTempPath,"C:\\Zv\\2");
	
}


CMaxIsoScanner::~CMaxIsoScanner(void)
{
	if(m_pbyBuffer != NULL)
	{
		delete []m_pbyBuffer;
	}
	if(m_pOutFile != NULL)
	{
		delete m_pOutFile;
		m_pOutFile = NULL;
	}

}

int convert_int(int i)
{
	int o;
	char *p_i = (char *) &i;
	char *p_o = (char *) &o;
	p_o[0] = p_i[3];
	p_o[1] = p_i[2];
	p_o[2] = p_i[1];
	p_o[3] = p_i[0];
	return o;
}

ULONG64 convert_int64(ULONG64 i)
{
	ULONG64 o;
	char *p_i = (char *) &i;
	char *p_o = (char *) &o;
	p_o[0] = p_i[7];
	p_o[1] = p_i[6];
	p_o[2] = p_i[5];
	p_o[3] = p_i[4];
	p_o[4] = p_i[3];
	p_o[5] = p_i[2];
	p_o[6] = p_i[1];
	p_o[7] = p_i[0];
	return o;
}

DWORD convert_char4(unsigned char *c)
{
	return (((DWORD) c[0]) << 24) | (((DWORD) c[1]) << 16) |
	(((DWORD) c[2]) << 8) | ((DWORD) c[3]);
}

ULONG64 convert_char8(unsigned char *c)
{
	return ((ULONG64) convert_char4(c) << 32) | (convert_char4(c + 4));
}

struct _kolyblk kolyblk;

bool CMaxIsoScanner::read_kolyblk(/*FILE* F,*/ struct _kolyblk* k, bool bcheck)
{
//	fread(k, 0x200, 1, F);
	DWORD iBytesRead = 0x00;
	if(bcheck)
	{
		if(!m_pMaxSecureFile->ReadBuffer((unsigned char *)k, (iFileSize - 0x200), sizeof(_kolyblk), sizeof(_kolyblk), &iBytesRead))
		{
			return false;
		}
	}
	else
	{
		if(!m_pMaxSecureFile->ReadBuffer((unsigned char *)k, 0x00, sizeof(_kolyblk), sizeof(_kolyblk), &iBytesRead))
		{
			return false;
		}
	}
	k->Signature = convert_int(k->Signature);
	k->Version = convert_int(k->Version);
	k->HeaderSize = convert_int(k->HeaderSize);
	k->Flags = convert_int(k->Flags);
	k->RunningDataForkOffset = convert_int64(k->RunningDataForkOffset);
	k->DataForkOffset = convert_int64(k->DataForkOffset);
	k->DataForkLength = convert_int64(k->DataForkLength);
	k->RsrcForkOffset = convert_int64(k->RsrcForkOffset);
	k->RsrcForkLength = convert_int64(k->RsrcForkLength);
	k->SegmentNumber = convert_int(k->SegmentNumber);
	k->SegmentCount = convert_int(k->SegmentCount);
	k->DataForkChecksumType = convert_int(k->DataForkChecksumType);
	k->DataForkChecksum = convert_int(k->DataForkChecksum);
	k->XMLOffset = convert_int64(k->XMLOffset);
	k->XMLLength = convert_int64(k->XMLLength);
	k->MasterChecksumType = convert_int(k->MasterChecksumType);
	k->MasterChecksum = convert_int(k->MasterChecksum);
	k->ImageVariant = convert_int(k->ImageVariant);
	k->SectorCount = convert_int64(k->SectorCount);
}

void fill_mishblk(char* c, struct _mishblk* m)
{
	memset(m, 0, sizeof(struct _mishblk));
	memcpy(m, c, 0xCC);
	m->BlocksSignature = convert_int(m->BlocksSignature);
	m->InfoVersion = convert_int(m->InfoVersion);
	m->FirstSectorNumber = convert_int64(m->FirstSectorNumber);
	m->SectorCount = convert_int64(m->SectorCount);
	m->DataStart = convert_int64(m->DataStart);
	m->DecompressedBufferRequested = convert_int(m->DecompressedBufferRequested);
	m->BlocksDescriptor = convert_int(m->BlocksDescriptor);
	m->ChecksumType = convert_int(m->ChecksumType);
	m->Checksum = convert_int(m->Checksum);
	m->BlocksRunCount = convert_int(m->BlocksRunCount);
}


int CMaxIsoScanner::mem_overflow()
{
	//printf("ERROR: not enough memory\n");
	if (FIN != NULL)
		fclose(FIN);
	if (FDBG != NULL)
		fclose(FDBG);
	if (FOUT != NULL)
		fclose(FOUT);
//	exit(-1);
	return true;
}

int CMaxIsoScanner::error_dmg_corrupted()
{
//	printf("ERROR: dmg image is corrupted\n");
	if (FIN != NULL)
		fclose(FIN);
	if (FDBG != NULL)
		fclose(FDBG);
	if (FOUT != NULL)
		fclose(FOUT);
//	exit(-1);
	return true;
}

void CMaxIsoScanner::percentage()
{
	int i, s;
	char sp[128];

	if (verbose < 1)
		return;
	s = offset / 0x28;
	if (verbose >= 3)
		printf("[%d] %6.2f%%\n", s, percent);
	else if (verbose == 2) {
		sprintf(sp, "[%d] %6.2f%%", s, percent);
		for (i = 0; i < strlen(sp); i++)
			printf("\b");
		printf("%s", sp);
	} else {
		sprintf(sp, "%6.2f%%", percent);
		for (i = 0; i < strlen(sp); i++)
			printf("\b");
		printf("%s", sp);
	}
	fflush(stdout);
//	return true;
}


bool CMaxIsoScanner::IsValidDMGFile()
{
	bool bRet = false;

	read_kolyblk(&kolyblk);
	if (kolyblk.Signature != 0x6b6f6c79) 
	{
		read_kolyblk(&kolyblk, false);
	}
	char szSignature[5];
	szSignature[4] = '\0';
	int rSignature = convert_int(kolyblk.Signature);
	memcpy(szSignature, &rSignature, 4);
		
	if (kolyblk.Signature != 0x6b6f6c79)
	{
		error_dmg_corrupted();
		return bRet;
	}
	
	return true;
}

bool CMaxIsoScanner::Check4ISOhrd()
{
	bool bRet = false;
	unsigned char byhrd[0x04] = {0x00};
	unsigned char byEmpty[0x04] = {0x00};
	DWORD	 iReadBytes = 0x00;

	if(!m_pOutFile->ReadBuffer(&byhrd[0x00], 0x00, 0x04, 0x04, &iReadBytes))
	{
		return bRet;
	}

	if(memcmp(byhrd, ISO_HDR_SIGNATURE, 0x04) == 0x00 || memcmp(byhrd, byEmpty, 0x04) == 0x00)
	{
		return true;
	}
	return false;
}

int CMaxIsoScanner::ExtractISOFile(CMaxPEFile *m_pOutFile)
{
	bool			bRet = false;
	TCHAR			szNewFilePath[1024] = {0x00};
	CMaxMACUBFile	*pUBFile = new CMaxMACUBFile;

	_stprintf(szNewFilePath, L"%s\\A.iso", m_szTempPath);
	if(!m_pOutFile->OpenFile(szNewFilePath,false))
	{
		return bRet;
	}
	iFileSize = m_pOutFile->m_dwFileSize;
	if(!Check4ISOhrd())
	{
		return bRet;
	}
	DWORD	 iTotalBytesrd = 0x00;
	DWORD	 iIndex = 0x00;
	DWORD	 iUBSize = 0x00;
	bool	 bUBFound = false;

	iFileCnt= 0x00;
	m_pbyBuffer = NULL;
	m_pbyBuffer = (unsigned char *)calloc(iBuffSize,sizeof(unsigned char));
	while(iOffset < iFileSize)
	{
		memset(m_pbyBuffer, 0, iBuffSize);
		iIndex = 0x00;
		if(!m_pOutFile->ReadBuffer(m_pbyBuffer, iOffset, iBuffSize, iBuffSize, &iTotalBytesrd))
		{
			return bRet;
		}

		if(OffSetBasedSignature(m_pbyBuffer, sizeof(bMAC_UB_BE), &iIndex))
		{
			bIsBigIndian = true;
			bUBFound = true;
		}
		else if(OffSetBasedSignature(m_pbyBuffer, sizeof(bMAC_UB_LE), &iIndex))
		{
			bIsBigIndian = false;
			bUBFound = true;
		}
		if(bUBFound)
		{
			iOffset+=iIndex;
			iTotalBytesrd = 0x00;
			bUBFound = false;
			pUBFile->SetDestDirPath(m_szTempPath);
			iUBSize = pUBFile->ExtractUBFile(m_pOutFile,(int *)&iFileCnt, bIsBigIndian, iOffset);
			if(!iUBSize)
			{
				iOffset+=0x04;
			}
			else
			{
				iOffset+=iUBSize;
			}
		}
		iOffset +=iTotalBytesrd;
	}
	if(pUBFile != NULL)
	{
		delete pUBFile;
		pUBFile = NULL;
	}
	return bRet;

}

bool CMaxIsoScanner::OffSetBasedSignature(unsigned char *m_pbyBuff, DWORD dwSizeofSig, DWORD *dwIndex)
{
	for(DWORD dwOffset = 0; dwOffset <= iBuffSize - (dwSizeofSig + 1); dwOffset++)
	{
		if((memcmp(&m_pbyBuff[dwOffset], bMAC_UB_BE, dwSizeofSig) == 0) || (memcmp(&m_pbyBuff[dwOffset], bMAC_UB_LE, dwSizeofSig) == 0))
		{
			if(dwIndex)
			{
				*dwIndex = dwOffset;
			}
			return true;
		}
	}	
	return false;
}

bool CMaxIsoScanner::CreateEmptyFile(LPCTSTR	pszFilePath)
{
	HANDLE	hNewFile = INVALID_HANDLE_VALUE;
	hNewFile = CreateFile(pszFilePath,GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if (INVALID_HANDLE_VALUE != hNewFile)
	{
		CloseHandle(hNewFile);
		hNewFile = INVALID_HANDLE_VALUE;
		return true;
	}
	hNewFile = INVALID_HANDLE_VALUE;
	return false;
}
bool CMaxIsoScanner::ExtractDMGFile(CMaxPEFile *m_pMaxSecureFile)
{
	bool		bRet = false;
	TCHAR		szNewFilePath[1024] = {0x00};
	DWORD		iByteRead = 0x00;

	m_pOutFile = new CMaxPEFile;
	iFileSize = m_pMaxSecureFile->m_dwFileSize;

	_stprintf(szNewFilePath, L"%s\\A.iso", m_szTempPath);
	CreateEmptyFile(szNewFilePath);
	if(!m_pOutFile->OpenFile(szNewFilePath, true))
	{
		return bRet;
	}

	if (kolyblk.XMLOffset != 0 && kolyblk.XMLLength != 0)
	{
		plist = (char *)malloc(kolyblk.XMLLength + 1);

		if (!plist)
		{
			mem_overflow();
			return bRet;
		}
		if(!m_pMaxSecureFile->ReadBuffer((unsigned char *)plist, kolyblk.XMLOffset, kolyblk.XMLLength, kolyblk.XMLLength, &iByteRead))
		{
			return bRet;
		}
		plist[kolyblk.XMLLength] = '\0';
		/*if (debug && verbose >= 3)
		{
			fprintf(FDBG, "%s\n", plist);
		}*/
		char *_blkx_begin = NULL;
		_blkx_begin = strstr(plist, blkx_begin);
		if(_blkx_begin == NULL)
		{
			return bRet;
		}
		blkx_size = strstr(_blkx_begin, list_end) - _blkx_begin;
		blkx = (char *)malloc(blkx_size + 1);
		memcpy(blkx, _blkx_begin, blkx_size);
		blkx[blkx_size] = '\0';

		if (!strstr(plist, plist_begin) || !strstr(&plist[kolyblk.XMLLength - 20], plist_end))
		{
		//	printf("ERROR: Property list is corrupted.\n");
			return bRet;
		}
		data_begin = blkx;
		partnum = 0;
		scb = strlen(chunk_begin);
		while (1)
		{
			char *base64data = NULL;
			unsigned int tmplen;
			data_begin = strstr(data_begin, chunk_begin);
			if (!data_begin)
				break;
			data_begin += scb;
			data_end = strstr(data_begin, chunk_end);
			if (!data_end)
				break;
			data_size = data_end - data_begin;
			i = partnum;
			++partnum;
			parts = (struct _mishblk *)realloc(parts, partnum * sizeof(struct _mishblk));
			if (!parts)
			{
				mem_overflow();
				return bRet;
			}
			base64data = (char *)malloc(data_size + 1);
			if (!base64data)
			{
				mem_overflow();
				return bRet;
			}
			base64data[data_size] = '\0';
			memcpy(base64data, data_begin, data_size);

			/*if (verbose >= 3)
				printf("%s\n", base64data);*/

			cleanup_base64(base64data, data_size);
			decode_base64(base64data, strlen(base64data), base64data, &tmplen);
			fill_mishblk(base64data, &parts[i]);
			if (parts[i].BlocksSignature != 0x6D697368)
			{
				break;
			}
			parts[i].Data = (char *)malloc(parts[i].BlocksRunCount * 0x28);
			if (!parts[i].Data)
			{
				mem_overflow();
				return bRet;
			}
			memcpy(parts[i].Data, base64data + 0xCC, parts[i].BlocksRunCount * 0x28);
			free(base64data);
			partname_begin = strstr(data_begin, name_key);
			partname_begin = strstr(partname_begin, name_begin) + strlen(name_begin);
			partname_end = strstr(partname_begin, name_end);
			memset(partname, 0, 255);
			memcpy(partname, partname_begin, partname_end - partname_begin);

			/*if (verbose >= 2) 
			{
				printf("partition %d: begin=%d, size=%d, decoded=%d\n", i, (int)(data_begin - blkx), data_size, tmplen);
				if (listparts)
					printf("             %s\n", partname);
			}
			else if (listparts)
				printf("partition %d: %s\n", i, partname);*/

		}
	}
	else if (kolyblk.RsrcForkOffset != 0 && kolyblk.RsrcForkLength != 0) 
	{
		//We have a binary resource fork to parse
			plist = (char *)malloc(kolyblk.RsrcForkLength);
		if (!plist)
		{
			mem_overflow();
			return bRet;
		}
		if(!m_pMaxSecureFile->ReadBuffer((unsigned char *)plist, kolyblk.RsrcForkOffset, kolyblk.RsrcForkLength, kolyblk.RsrcForkLength, &iByteRead))
		{
			return bRet;
		}
		plist[kolyblk.XMLLength] = '\0';

		/*if (debug && verbose >= 3) 
		{
			fprintf(FDBG, "%s\n", plist);
		}*/
		//char *_blkx_begin = strstr(plist, blkx_begin);
		char *_blkx_begin = NULL;
		_blkx_begin = strstr(plist, blkx_begin);
		if(_blkx_begin == NULL)
		{
			return bRet;
		}
		blkx_size = strstr(_blkx_begin, list_end) - _blkx_begin;
		blkx = (char *)malloc(blkx_size + 1);
		memcpy(blkx, _blkx_begin, blkx_size);
		blkx[blkx_size] = '\0';

		if (!strstr(plist, plist_begin) || !strstr(&plist[kolyblk.XMLLength - 20], plist_end))
		{
			//printf("ERROR: Property list is corrupted.\n");
			return bRet;
		}
		data_begin = blkx;
		partnum = 0;
		scb = strlen(chunk_begin);
		while (1)
		{
			char *base64data = NULL;
			unsigned int tmplen;
			data_begin = strstr(data_begin, chunk_begin);
			if (!data_begin)
				break;
			data_begin += scb;
			data_end = strstr(data_begin, chunk_end);
			if (!data_end)
				break;
			data_size = data_end - data_begin;
			i = partnum;
			++partnum;
			parts = (struct _mishblk *)realloc(parts, partnum * sizeof(struct _mishblk));
			if (!parts)
			{
				mem_overflow();
				return bRet;
			}

			base64data = (char *)malloc(data_size + 1);
			if (!base64data)
			{
				mem_overflow();
				return bRet;
			}
			base64data[data_size] = '\0';
			memcpy(base64data, data_begin, data_size);

			/*if (verbose >= 3)
				printf("%s\n", base64data);*/

			cleanup_base64(base64data, data_size);
			decode_base64(base64data, strlen(base64data), base64data, &tmplen);
			fill_mishblk(base64data, &parts[i]);
			if (parts[i].BlocksSignature != 0x6D697368)
				break;

			parts[i].Data = (char *)malloc(parts[i].BlocksRunCount * 0x28);
			if (!parts[i].Data)
			{
				mem_overflow();
				return bRet;
			}
			memcpy(parts[i].Data, base64data + 0xCC, parts[i].BlocksRunCount * 0x28);

			free(base64data);
	
			partname_begin = strstr(data_begin, name_key);
			partname_begin = strstr(partname_begin, name_begin) + strlen(name_begin);
			partname_end = strstr(partname_begin, name_end);
			memset(partname, 0, 255);
			memcpy(partname, partname_begin, partname_end - partname_begin);

		}
	}
	else 
	{
		error_dmg_corrupted();
		return bRet;
	}

	if (listparts || extractpart > partnum-1)
	{
		/*if (extractpart > partnum-1)
			printf("partition %d not found\n", extractpart);*/
		
		for (i = 0; i < partnum; i++)
			if (parts[i].Data != NULL)
				free(parts[i].Data);
		if (parts != NULL)
			free(parts);
		if (plist != NULL)
			free(plist);
		if (blkx != NULL)
			free(blkx);
		
		return 0;
	}

	tmp = (Bytef *) malloc(CHUNKSIZE);
	otmp = (Bytef *) malloc(CHUNKSIZE);
	dtmp = (Bytef *) malloc(DECODEDSIZE);
	if (!tmp || !otmp || !dtmp)
	{
		mem_overflow();
		return bRet;
	}
	z.zalloc = (alloc_func) 0;
	z.zfree = (free_func) 0;
	z.opaque = (voidpf) 0;
	bz.bzalloc = NULL;
	bz.bzfree = NULL;
	bz.opaque = NULL;

	in_offs = add_offs = in_offs_add = kolyblk.DataForkOffset;

	for (i = extractpart==-1?0:extractpart; i < (extractpart==-1?partnum:extractpart+1) && in_offs < kolyblk.DataForkLength - kolyblk.DataForkOffset; i++) 
	{
		offset = 0;
		add_offs = in_offs_add;
		block_type = 0;
		/*if (debug) 
		{
			fprintf(FDBG, "\n   run..... ..type.... ..reserved ..sectorStart..... ..sectorCount..... ..compOffset...... ..compLength......\n");
		}*/

		unsigned long bi = 0;
		while (block_type != BT_TERM && offset < parts[i].BlocksRunCount * 0x28) 
		{
			block_type = convert_char4((unsigned char *)parts[i].Data + offset);
			dw_reserved = convert_char4((unsigned char *)parts[i].Data + offset + 4);
			memcpy(&reserved, parts[i].Data + offset + 4, 4);
			out_offs = convert_char8((unsigned char *)parts[i].Data + offset + 8) * 0x200;
			out_size = convert_char8((unsigned char *)parts[i].Data + offset + 16) * 0x200;
			in_offs = convert_char8((unsigned char *)parts[i].Data + offset + 24);
			in_size = convert_char8((unsigned char *)parts[i].Data + offset + 32);
			if (block_type != BT_TERM)
				in_offs_add = add_offs + in_offs + in_size;
			if (debug) 
			{
				switch (block_type) 
				{
				case BT_ADC:
					strcpy(sztype, "adc");
					break;
				case BT_ZLIB:
					strcpy(sztype, "zlib");
					break;
				case BT_BZLIB:
					strcpy(sztype, "bzlib");
					break;
				case BT_ZERO:
					strcpy(sztype, "zero");
					break;
				case BT_IGNORE:
					strcpy(sztype, "ignore");
					break;
				case BT_RAW:
					strcpy(sztype, "raw");
					break;
				case BT_COMMENT:
					strcpy(sztype, "comment ");
					strcat(sztype, reserved);
					break;
				case BT_TERM:
					strcpy(sztype, "terminator");
					break;
				default:
					sztype[0] = '\0';
				}
				fflush(FDBG);
				bi++;
			}
			/*if (verbose >= 3)
				printf("offset = %u  block_type = 0x%08x\n", offset, block_type);*/

			if (block_type == BT_ZLIB) {
				/*if (verbose >= 3)
					printf("zlib inflate (in_addr=%llu in_size=%llu out_addr=%llu out_size=%llu)\n", (unsigned long long)in_offs, (unsigned long long)in_size, (unsigned long long)out_offs, (unsigned long long)out_size);*/

				if (inflateInit(&z) != Z_OK)
				{
				//	printf("ERROR: Can't initialize inflate stream\n");
					return bRet;
				}
				if(!m_pMaxSecureFile->SetFilePointer(in_offs + add_offs))
				{
					return bRet;
				}
				to_read = in_size;
				do {
					if (!to_read)
						break;
					if (to_read > CHUNKSIZE)
						chunk = CHUNKSIZE;
					else
						chunk = to_read;
					iByteRead = 0x00;
					if(!m_pMaxSecureFile->ReadBuffer((unsigned char *)tmp, chunk, &iByteRead))
					{
						(void)inflateEnd(&z);
						return bRet;
					}
					z.avail_in = iByteRead;
					/*if (ferror(FIN)) 
					{
						(void)inflateEnd(&z);
						return bRet;
					}*/
					if (z.avail_in == 0)
						break;
					to_read -= z.avail_in;
					z.next_in = tmp;
					do {
						z.avail_out = CHUNKSIZE;
						z.next_out = otmp;
						err = inflate(&z, Z_NO_FLUSH);
						assert(err != Z_STREAM_ERROR);	/* state not clobbered */
						switch (err) 
						{
						case Z_NEED_DICT:
							err = Z_DATA_ERROR;	/* and fall through */
						case Z_DATA_ERROR:
						case Z_MEM_ERROR:
							(void)inflateEnd(&z);
						//	printf("ERROR: Inflation failed\n");
							return bRet;
						}
						to_write = CHUNKSIZE - z.avail_out;
						iBytesWritten = 0x00;
						if(!m_pOutFile->WriteBuffer((unsigned char *)otmp, m_iTotalBytesWritten, to_write, to_write, &iBytesWritten))
						{
							(void)inflateEnd(&z);
							return bRet;
						}
						m_iTotalBytesWritten+=iBytesWritten;
						
					}
					while (z.avail_out == 0);
				}
				while (err != Z_STREAM_END);

				(void)inflateEnd(&z);
			} 
			else if (block_type == BT_BZLIB)
			{
				/*if (verbose >= 3)
					printf("bzip2 decompress (in_addr=%llu in_size=%llu out_addr=%llu out_size=%llu)\n", (unsigned long long)in_offs, (unsigned long long)in_size, (unsigned long long)out_offs, (unsigned long long)out_size);*/

				if (BZ2_bzDecompressInit(&bz, 0, 0) != BZ_OK) 
				{
				//	printf("ERROR: Can't initialize inflate stream\n");
					return bRet;
				}
				if(!m_pMaxSecureFile->SetFilePointer(in_offs + add_offs))
				{
					return bRet;
				}
				to_read = in_size;
				do {
					if (!to_read)
						break;
					if (to_read > CHUNKSIZE)
						chunk = CHUNKSIZE;
					else
						chunk = to_read;
					iByteRead = 0x00;
					if(!m_pMaxSecureFile->ReadBuffer((unsigned char *)tmp, chunk, &iByteRead))
					{
						(void)BZ2_bzCompressEnd(&bz);
						return bRet;
					}
					bz.avail_in = iByteRead;
					/*if (ferror(FIN)) {
						(void)BZ2_bzCompressEnd(&bz);
						printf("ERROR: reading file %s \n", input_file);
						return 0;
					}*/
					if (bz.avail_in == 0)
						break;
					to_read -= bz.avail_in;
					bz.next_in = (char *)tmp;
					do {
						bz.avail_out = CHUNKSIZE;
						bz.next_out = (char *)otmp;
						err = BZ2_bzDecompress(&bz);
						switch (err)
						{
						case BZ_PARAM_ERROR:
						case BZ_DATA_ERROR:
						case BZ_DATA_ERROR_MAGIC:
						case BZ_MEM_ERROR:
							(void)BZ2_bzDecompressEnd(&bz);
							//printf("ERROR: Inflation failed\n");
							return bRet;
						}
						to_write = CHUNKSIZE - bz.avail_out;

						 iBytesWritten = 0x00;
						 if (to_write > 0x00)
						 {
							 if(!m_pOutFile->WriteBuffer((unsigned char *)otmp, m_iTotalBytesWritten, to_write, to_write, &iBytesWritten))
							 {
								 (void)BZ2_bzDecompressEnd(&bz);
								 return bRet;
							 }
						 }
						m_iTotalBytesWritten+=iBytesWritten;
						/*if (fwrite(otmp, 1, to_write, FOUT) != to_write || ferror(FOUT)) {
							(void)BZ2_bzDecompressEnd(&bz);
							printf("ERROR: writing file %s \n", output_file);
							return 0;
						}*/
					}while (bz.avail_out == 0);
				} while (err != BZ_STREAM_END);

				(void)BZ2_bzDecompressEnd(&bz);
			}
		
		 else if (block_type == BT_ADC)
		 {
			/*if (verbose >= 3)
				printf("ADC decompress (in_addr=%llu in_size=%llu out_addr=%llu out_size=%llu)\n", (unsigned long long)in_offs, (unsigned long long)in_size, (unsigned long long)out_offs, (unsigned long long)out_size);*/

		//	fseek(FIN, in_offs + add_offs, SEEK_SET);
			if(!m_pMaxSecureFile->SetFilePointer(in_offs + add_offs))
			{
				return bRet;
			}
			to_read = in_size;
			
			while (to_read > 0)
			{
				iBytesWritten = 0x00;
				chunk = to_read > CHUNKSIZE ? CHUNKSIZE : to_read;
				iByteRead = 0x00;
				if(!m_pMaxSecureFile->ReadBuffer( (unsigned char *)tmp, chunk, &iByteRead))
				{
					return bRet;
				}
				to_write = iByteRead;
				int bytes_written;
				int read_from_input = adc_decompress(to_write, tmp, DECODEDSIZE, dtmp, &bytes_written);

				 
				if(!m_pOutFile->WriteBuffer((unsigned char *)otmp,m_iTotalBytesWritten, to_write, to_write, &iBytesWritten))
				{
					return bRet;
				}
				m_iTotalBytesWritten+=iBytesWritten;
			//	fwrite(dtmp, 1, bytes_written, FOUT);
				to_read -= read_from_input;
			}
		} 
		 else if (block_type == BT_RAW) 
		 {
			 if(!m_pMaxSecureFile->SetFilePointer(in_offs + add_offs))
			{
				return bRet;
			}
		//	fseek(FIN, in_offs + add_offs, SEEK_SET);
			to_read = in_size;
			while (to_read > 0) {
				if (to_read > CHUNKSIZE)
					chunk = CHUNKSIZE;
				else
					chunk = to_read;
				iByteRead = 0x00;
				if(!m_pMaxSecureFile->ReadBuffer( (unsigned char *)tmp, chunk, &iByteRead))
				{
					return bRet;
				}
				to_write = iByteRead;
				/*if (ferror(FIN) || to_write < chunk) {
					printf("ERROR: reading file %s \n", input_file);
					return 0;
				}*/
				iBytesWritten = 0x00;
				if(!m_pOutFile->WriteBuffer((unsigned char *)otmp, m_iTotalBytesWritten, to_write, to_write, &iBytesWritten))
				{
					return bRet;
				}
				m_iTotalBytesWritten+=iBytesWritten;
			//	fwrite(tmp, 1, chunk, FOUT);
				//copy
					to_read -= chunk;
			}
			/*if (verbose >= 3)
				printf("copy data  (in_addr=%llu in_size=%llu out_size=%llu)\n", (unsigned long long)in_offs, (unsigned long long)in_size, (unsigned long long)out_size);*/

		} 
		 else if (block_type == BT_ZERO || block_type == BT_IGNORE)
		 {
			memset(tmp, 0, CHUNKSIZE);
			to_write = out_size;
			while (to_write > 0) {
				if (to_write > CHUNKSIZE)
					chunk = CHUNKSIZE;
				else
					chunk = to_write;
				iBytesWritten = 0x00;
				if(!m_pOutFile->WriteBuffer((unsigned char *)otmp,m_iTotalBytesWritten, chunk, chunk, &iBytesWritten))
				{
					return bRet;
				}
				m_iTotalBytesWritten+=iBytesWritten;
				//fwrite(tmp, 1, chunk, FOUT);
				to_write -= chunk;
			}
			/*if (verbose >= 3)
				printf("null bytes (out_size=%llu)\n",
						(unsigned long long)out_size);*/

		} 
		/* else if (block_type == BT_COMMENT)
		 {
			printf("Resereved");
			if (verbose >= 3)
				printf("0x%08x (in_addr=%llu in_size=%llu out_addr=%llu out_size=%llu) comment %s\n", block_type, (unsigned long long)in_offs,
						(unsigned long long)in_size,
						(unsigned long long)out_offs,
						(unsigned long long)out_size, reserved);
		}*/
		 else if (block_type == BT_TERM) 
		 {
			if (in_offs == 0 && partnum > i+1) 
			{
				if (convert_char8((unsigned char *)parts[i+1].Data + 24) != 0)
					in_offs_add = kolyblk.DataForkOffset;
			} 
			else
				in_offs_add = kolyblk.DataForkOffset;

			/*if (verbose >= 3)
				printf("terminator\n");*/
		} 
		/* else 
		 {
			 printf("conti.\n");
			if (verbose)
				printf("\n Unsupported or corrupted block found: %d\n", block_type);
		}*/
		offset += 0x28;
		if (verbose) 
		{
			percent = 100 * (double)offset / ((double)parts[i].BlocksRunCount * 0x28);
			percentage();
		}
		}
		/*if (verbose)
			printf("  ok\n");*/
	}
	/*if (verbose)
		printf("\nArchive successfully decompressed as %s\n", output_file);*/

	if (tmp != NULL)
		free(tmp);
	if (otmp != NULL)
		free(otmp);
	if (dtmp != NULL)
		free(dtmp);
	for (i = 0; i < partnum; i++) {
		if (parts[i].Data != NULL)
			free(parts[i].Data);
	}
	if (parts != NULL)
		free(parts);
	if (partlen != NULL)
		free(partlen);
	if (plist != NULL)
		free(plist);
	if (blkx != NULL)
		free(blkx);
	if (FIN != NULL)
		fclose(FIN);
	if (FOUT != NULL)
		fclose(FOUT);
	if (FDBG != NULL)
		fclose(FDBG);
	/*if(m_pOutFile)
	{
		delete m_pOutFile;
		m_pOutFile = NULL;
	}*/
	
	m_pOutFile->CloseFile();
	//m_pOutFile = NULL;

	ExtractISOFile(m_pOutFile);
	return true;
}

bool CMaxIsoScanner::is_base64(const char c)
{
	if ((c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z') ||
	    (c >= '0' && c <= '9') ||
	    c == '+' ||
	    c == '/' ||
	    c == '=')
		return true;
	return false;
}

void CMaxIsoScanner::cleanup_base64(char *inp, const unsigned int size)
{
	char *tinp1, *tinp2;
	unsigned int i;
	tinp1 = inp;
	tinp2 = inp;
	for (i = 0; i < size; i++) {
		if (is_base64(*tinp2)) {
			*tinp1++ = *tinp2++;
		} else {
			*tinp1 = *tinp2++;
		}
	}
	*(tinp1) = 0;
}

unsigned char CMaxIsoScanner::decode_base64_char(const char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '=')
		return 0;
	return 63;
}

void CMaxIsoScanner::decode_base64(const char *inp, unsigned int isize,char *out, unsigned int *osize)
{
	char *tinp = (char *)inp;
	char *tout;
	unsigned int i;

	*osize = isize / 4 * 3;
	if (inp != out) {
		tout = (char *)malloc(*osize);
		out = tout;
	} else {
		tout = tinp;
	}
	for (i = 0; i < (isize >> 2); i++) {
		*tout = decode_base64_char(*tinp++) << 2;
		*tout++ |= decode_base64_char(*tinp) >> 4;
		*tout = decode_base64_char(*tinp++) << 4;
		*tout++ |= decode_base64_char(*tinp) >> 2;
		*tout = decode_base64_char(*tinp++) << 6;
		*tout++ |= decode_base64_char(*tinp++);
	}
	if (*(tinp - 1) == '=')
		(*osize)--;
	if (*(tinp - 2) == '=')
		(*osize)--;
}

int CMaxIsoScanner::adc_decompress(int in_size, unsigned char *input, int avail_size, unsigned char *output, int *bytes_written)
{
	
	bool output_full = false;
	unsigned char *inp = input;
	unsigned char *outp = output;
	int chunk_type;
	int chunk_size;
	int offset;
	int i;
	if (in_size == 0)
		return 0;

	while (inp - input < in_size) {
		chunk_type = adc_chunk_type(*inp);
		switch (chunk_type) {
		case ADC_PLAIN:
			chunk_size = adc_chunk_size(*inp);
			if (outp + chunk_size - output > avail_size) {
				output_full = true;
				break;
			}
			memcpy(outp, inp + 1, chunk_size);
			inp += chunk_size + 1;
			outp += chunk_size;
			break;

		case ADC_2BYTE:
			chunk_size = adc_chunk_size(*inp);
			offset = adc_chunk_offset(inp);
			if (outp + chunk_size - output > avail_size) {
				output_full = true;
				break;
			}
			if (offset == 0) {
				memset(outp, *(outp - offset - 1), chunk_size);
				outp += chunk_size;
				inp += 2;
			} else {
				for (i = 0; i < chunk_size; i++) {
					memcpy(outp, outp - offset - 1, 1);
					outp++;
				}
				inp += 2;
			}
			break;

		case ADC_3BYTE:
			chunk_size = adc_chunk_size(*inp);
			offset = adc_chunk_offset(inp);
			if (outp + chunk_size - output > avail_size) {
				output_full = true;
				break;
			}
			if (offset == 0) {
				memset(outp, *(outp - offset - 1), chunk_size);
				outp += chunk_size;
				inp += 3;
			} else {
				for (i = 0; i < chunk_size; i++) {
					memcpy(outp, outp - offset - 1, 1);
					outp++;
				}
				inp += 3;
			}
			break;
		}
		if (output_full)
			break;
	}
	*bytes_written = outp - output;
	return inp - input;
}

int CMaxIsoScanner::adc_chunk_type(char _byte)
{
	if (_byte & 0x80)
		return ADC_PLAIN;
	if (_byte & 0x40)
		return ADC_3BYTE;
	return ADC_2BYTE;
}

int CMaxIsoScanner::adc_chunk_size(char _byte)
{
	switch (adc_chunk_type(_byte)) {
		case ADC_PLAIN:
		return (_byte & 0x7F) + 1;
	case ADC_2BYTE:
		return ((_byte & 0x3F) >> 2) + 3;
	case ADC_3BYTE:
		return (_byte & 0x3F) + 4;
	}
	return -1;
}

int CMaxIsoScanner::adc_chunk_offset(unsigned char *chunk_start)
{
	unsigned char *c = chunk_start;
	switch (adc_chunk_type(*c)) {
	case ADC_PLAIN:
		return 0;
	case ADC_2BYTE:
		return ((((unsigned char)*c & 0x03)) << 8) + (unsigned char)*(c + 1);
	case ADC_3BYTE:
		return (((unsigned char)*(c + 1)) << 8) + (unsigned char)*(c + 2);
	}
	return -1;
}

bool CMaxIsoScanner::SetDestDirPath(LPCTSTR pszDestPath)
{
	_stprintf(m_szTempPath,L"%s",pszDestPath);	
	return true;
}