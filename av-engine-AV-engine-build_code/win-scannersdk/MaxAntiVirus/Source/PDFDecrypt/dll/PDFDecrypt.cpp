// PDFDecrypt.cpp : Defines the exported functions for the DLL application.
//

#include "pch.h"
#include <tchar.h>
extern "C"
{
#include <fitz.h>
#include <mupdf.h>
}

static FILE *out = NULL;
static char *uselist = NULL;
static int *ofslist = NULL;
static int *genlist = NULL;
static int *renumbermap = NULL;
static int dogarbage = 0;
static int doexpand = 0;
static int doascii = 0;
static pdf_xref *xref = NULL;

#define MAX_BUFF_LENGTH	0x80000
//char szBuff[MAX_BUFF_LENGTH];
//char szNextBuff[MAX_BUFF_LENGTH];
//char szNewBuff[MAX_BUFF_LENGTH];
//char g_szNextBuff[MAX_BUFF_LENGTH];

void die(fz_error error);
static void preloadobjstms(void);
static void writepdf(void);
static void writeobject(int num, int gen);
static void writexref(void);
static void expandstream(fz_obj *obj, int num, int gen);
static void copystream(fz_obj *obj, int num, int gen);
static int isbinarystream(fz_buffer *buf);
static fz_buffer *hexbuf(unsigned char *p, int n);
static void addhexfilter(fz_obj *dict);
static inline int isbinary(int c);



int m_nStreamCount = 0;
char m_szCryptMethod[MAX_BUFF_LENGTH];
//char m_szOutput[MAX_PATH];
TCHAR   m_szOutput[MAX_PATH];

char * LeftTrim(char *pszBuff, char chItem);
char * RightTrim(char *pszBuff, char chItem);
void SaveStream(char *pszBuff, int nLength);
//char * GetCryptMethod(char *pszBuff, unsigned long * nStreamLength);
int fz_my_get_stream(fz_stream *stm, char *mem, int n);

EXTC_DLL_EXP bool DecryptPDFFile(LPCTSTR szPDFFilePath, LPCTSTR szTmpFilePath, int * piStatus)
{
	__try
	{
		fz_error error;
		char *password = "";
		int num;
		int subset = 0;

		out = NULL;
		doexpand ++;	
		error = pdf_open_xref(&xref, szPDFFilePath, password);
		if(error)
		{
			return false;
		}

		out = _tfopen(szTmpFilePath, L"wb+");
		if(!out)
		{
			die(fz_throw("cannot open output file '%S'", szTmpFilePath));
			return false;
		}
		
		fprintf(out, "%%PDF-%d.%d\n", xref->version / 10, xref->version % 10);
		
		if(xref->len >= MAX_BUFF_LENGTH)
		{
			fclose(out);
			out = NULL;
			return false;
		}

		uselist = (char *)fz_calloc(xref->len + 1, sizeof(char));
		ofslist = (int *)fz_calloc(xref->len + 1, sizeof(int));
		genlist = (int *)fz_calloc(xref->len + 1, sizeof(int));
		renumbermap = (int *)fz_calloc(xref->len + 1, sizeof(int));

		for (num = 0; num < xref->len; num++)
		{
			uselist[num] = 0;
			ofslist[num] = 0;
			genlist[num] = 0;
			renumbermap[num] = num;
		}

		/* Make sure any objects hidden in compressed streams have been loaded */
		preloadobjstms();

		writepdf();

		if(fclose(out))
		{
			die(fz_throw("cannot close output file '%S'", szTmpFilePath));
		}

		out = NULL;
		fz_free(uselist);
		fz_free(ofslist);
		fz_free(genlist);
		fz_free(renumbermap);

		if(xref && xref->file)
		{
			xref->file->refs = 1;
		}

		pdf_free_xref(xref);
		return true;
	}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		if(piStatus)
		{
			*piStatus = 1;
		}

		AddLogEntry(_T("Exception: "), szPDFFilePath);

		FILE * out_dup = out;
		pdf_xref * xref_dup = xref;

		xref = NULL;
		out = NULL;
		fclose(out_dup);

		if(xref_dup && xref_dup->file)
		{
			xref_dup->file->refs = 1;
		}
		pdf_free_xref(xref_dup);
	}

	return false;
}

static void preloadobjstms(void)
{
	fz_error error;
	fz_obj *obj;
	int num;

	for (num = 0; num < xref->len; num++)
	{
		if (xref->table[num].type == 'o') // when obj is stream
		{
			error = pdf_load_object(&obj, xref, num, 0);
			if(!error)
				fz_drop_obj(obj);
		}
	}
}

static void writepdf(void)
{
	int lastfree;
	int num;

	for (num = 0; num < xref->len; num++)
	{
		if (xref->table[num].type == 'f')
			genlist[num] = xref->table[num].gen;
		if (xref->table[num].type == 'n')
			genlist[num] = xref->table[num].gen;
		if (xref->table[num].type == 'o')
			genlist[num] = 0;

		if (dogarbage && !uselist[num])
			continue;

		if (xref->table[num].type == 'n' || xref->table[num].type == 'o')
		{
			uselist[num] = 1;
			ofslist[num] = ftell(out);
			writeobject(num, genlist[num]);
		}
	}

	/* Construct linked list of free object slots */
	lastfree = 0;
	for (num = 0; num < xref->len; num++)
	{
		if (!uselist[num])
		{
			genlist[num]++;
			ofslist[lastfree] = num;
			lastfree = num;
		}
	}

	writexref();
}

static void writeobject(int num, int gen)
{
	fz_error error;
	fz_obj *obj;
	fz_obj *type;

	error = pdf_load_object(&obj, xref, num, gen);
	if (!error)
	{
		/* skip ObjStm and XRef objects */
		if (fz_is_dict(obj))
		{
			type = fz_dict_gets(obj, "Type");
			if (fz_is_name(type) && !strcmp(fz_to_name(type), "ObjStm"))
			{
				uselist[num] = 0;
				fz_drop_obj(obj);
				return;
			}
			if (fz_is_name(type) && !strcmp(fz_to_name(type), "XRef"))
			{
				uselist[num] = 0;
				fz_drop_obj(obj);
				return;
			}
		}

		if (!pdf_is_stream(xref, num, gen))
		{
			fprintf(out, "%d %d obj\n", num, gen);
			fz_fprint_obj(out, obj, !doexpand);
			fprintf(out, "endobj\n\n");
		}
		else
		{
			if (doexpand && !pdf_is_jpx_image(obj))
				expandstream(obj, num, gen);
			else
				copystream(obj, num, gen);
		}

		fz_drop_obj(obj);
	}
}

static void writexref(void)
{
	fz_obj *trailer;
	fz_obj *obj;
	int startxref;
	int num;

	startxref = ftell(out);

	fprintf(out, "xref\n0 %d\n", xref->len);
	for (num = 0; num < xref->len; num++)
	{
		if (uselist[num])
			fprintf(out, "%010d %05d n \n", ofslist[num], genlist[num]);
		else
			fprintf(out, "%010d %05d f \n", ofslist[num], genlist[num]);
	}
	fprintf(out, "\n");

	trailer = fz_new_dict(5);

	obj = fz_new_int(xref->len);
	fz_dict_puts(trailer, "Size", obj);
	fz_drop_obj(obj);

	obj = fz_dict_gets(xref->trailer, "Info");
	if (obj)
		fz_dict_puts(trailer, "Info", obj);

	obj = fz_dict_gets(xref->trailer, "Root");
	if (obj)
		fz_dict_puts(trailer, "Root", obj);

	obj = fz_dict_gets(xref->trailer, "ID");
	if (obj)
		fz_dict_puts(trailer, "ID", obj);

	fprintf(out, "trailer\n");
	fz_fprint_obj(out, trailer, !doexpand);
	fprintf(out, "\n");

	fz_drop_obj(trailer);

	fprintf(out, "startxref\n%d\n%%%%EOF\n", startxref);
}


static void expandstream(fz_obj *obj, int num, int gen)
{
	fz_error error;
	fz_buffer *buf = NULL, *tmp;
	fz_obj *newlen;

	error = pdf_load_stream(&buf, xref, num, gen);
	if (!error && buf->len < MAX_BUFF_LENGTH)
	{
		fz_dict_dels(obj, "Filter");
		fz_dict_dels(obj, "DecodeParms");

		if (doascii && isbinarystream(buf))
		{
			tmp = hexbuf(buf->data, buf->len);
			fz_drop_buffer(buf);
			buf = tmp;

			addhexfilter(obj);
		}

		newlen = fz_new_int(buf->len);
		fz_dict_puts(obj, "Length", newlen);
		fz_drop_obj(newlen);

		fprintf(out, "%d %d obj\n", num, gen);
		fz_fprint_obj(out, obj, !doexpand);
		fprintf(out, "stream\n");
		fwrite(buf->data, 1, buf->len, out);
		fprintf(out, "endstream\nendobj\n\n");
	}

	fz_drop_buffer(buf);
}


static void copystream(fz_obj *obj, int num, int gen)
{
	fz_error error;
	fz_buffer *buf = NULL, *tmp;
	fz_obj *newlen;

	error = pdf_load_raw_stream(&buf, xref, num, gen);
	if (!error && buf->len < MAX_BUFF_LENGTH)
	{
		if (doascii && isbinarystream(buf))
		{
			tmp = hexbuf(buf->data, buf->len);
			fz_drop_buffer(buf);
			buf = tmp;

			addhexfilter(obj);

			newlen = fz_new_int(buf->len);
			fz_dict_puts(obj, "Length", newlen);
			fz_drop_obj(newlen);
		}

		fprintf(out, "%d %d obj\n", num, gen);
		fz_fprint_obj(out, obj, !doexpand);
		fprintf(out, "stream\n");
		fwrite(buf->data, 1, buf->len, out);
		fprintf(out, "endstream\nendobj\n\n");

		fz_drop_buffer(buf);
	}
}

static int isbinarystream(fz_buffer *buf)
{
	int i;
	for (i = 0; i < buf->len; i++)
		if (isbinary(buf->data[i]))
			return 1;
	return 0;
}

static fz_buffer *hexbuf(unsigned char *p, int n)
{
	static const char hex[17] = "0123456789abcdef";
	fz_buffer *buf;
	int x = 0;

	buf = fz_new_buffer(n * 2 + (n / 32) + 2);

	while (n--)
	{
		buf->data[buf->len++] = hex[*p >> 4];
		buf->data[buf->len++] = hex[*p & 15];
		if (++x == 32)
		{
			buf->data[buf->len++] = '\n';
			x = 0;
		}
		p++;
	}

	buf->data[buf->len++] = '>';
	buf->data[buf->len++] = '\n';

	return buf;
}

static void addhexfilter(fz_obj *dict)
{
	fz_obj *f, *dp, *newf, *newdp;
	fz_obj *ahx, *nullobj;

	ahx = fz_new_name("ASCIIHexDecode");
	nullobj = fz_new_null();
	newf = newdp = NULL;

	f = fz_dict_gets(dict, "Filter");
	dp = fz_dict_gets(dict, "DecodeParms");

	if (fz_is_name(f))
	{
		newf = fz_new_array(2);
		fz_array_push(newf, ahx);
		fz_array_push(newf, f);
		f = newf;
		if (fz_is_dict(dp))
		{
			newdp = fz_new_array(2);
			fz_array_push(newdp, nullobj);
			fz_array_push(newdp, dp);
			dp = newdp;
		}
	}
	else if (fz_is_array(f))
	{
		fz_array_insert(f, ahx);
		if (fz_is_array(dp))
			fz_array_insert(dp, nullobj);
	}
	else
		f = ahx;

	fz_dict_puts(dict, "Filter", f);
	if (dp)
		fz_dict_puts(dict, "DecodeParms", dp);

	fz_drop_obj(ahx);
	fz_drop_obj(nullobj);
	if (newf)
		fz_drop_obj(newf);
	if (newdp)
		fz_drop_obj(newdp);
}

static inline int isbinary(int c)
{
	if (c == '\n' || c == '\r' || c == '\t')
		return 0;
	return c < 32 || c > 127;
}

void die(fz_error error)
{
	if(xref)
	{
		pdf_free_xref(xref);
	}
}

EXTC_DLL_EXP bool ExtractScriptFromPDF(LPCTSTR pszFile, LPCTSTR szTmpFolderPath)
{
//	fz_stream *file;
//	TCHAR szFileName[MAX_PATH];
//	unsigned long nStreamLength;
//	unsigned long nRead;
//	unsigned long nBuff;
//
//	char *pdest1 = NULL;
//	char *pdest2 = NULL;
//	char *pszBuff = NULL;
//	//char szBuff[MAX_BUFF_LENGTH];
//	//char szNextBuff[MAX_BUFF_LENGTH];
//	bool bReturn = false;
//
//	m_nStreamCount = 0;
//	_tcscpy(szFileName, pszFile);
//
//	//////neeraj
//	_tcscpy(m_szOutput,szTmpFolderPath);
//
//	// open pdf file
//	file = fz_open_file_w(szFileName);
//	if(!file) return bReturn;
//
//	while(1)
//	{
//		// check the EOF of pdf file
//		if(fz_is_eof(file)) break;
//
//		// read one line from pdf file
//		memset(szBuff, 0x0, MAX_BUFF_LENGTH);
//		fz_read_line(file, szBuff, MAX_BUFF_LENGTH);
//		if(strcmp(szBuff, "") == 0) continue;
//
//		// preprocess the pdf file
//		pszBuff = szBuff;
//		pszBuff = LeftTrim(pszBuff, ' ');
//		pszBuff = RightTrim(pszBuff, ' ');
//		pdest1 = strstr(pszBuff, "<<");
//		pdest2 = strstr(pszBuff, ">>");
//
//		if(pdest1 > pdest2) 
//		{
//			while(1)
//			{
//				memset(szNextBuff, 0x0, MAX_BUFF_LENGTH);
//				fz_read_line(file, szNextBuff, MAX_BUFF_LENGTH);
//				pdest1 = strstr(szNextBuff, ">>");
//				if(pdest1)
//				{
//					break;
//				}
//				if(fz_is_eof(file)) 
//				{
//					break;
//				}
//
//			}
//		}
//
//		pdest1 = strstr(szBuff, "/P ");
//		if(pdest1)
//		{
//			strcpy(szNextBuff, pdest1+3);
//			pdest2 = strstr(szNextBuff, ">>");
//			if(pdest2)
//			{
//				nBuff = pdest2 - szNextBuff;
//				szNextBuff[nBuff] = 0;
//			}
//			if((szNextBuff[0] != '/') && !strstr(szNextBuff, " R"))
//			{
//				bReturn = true;
//				nStreamLength = strlen(szNextBuff);
//				SaveStream(szNextBuff, nStreamLength);
//			}
//			continue;
//		}
//
//		pdest1 = strstr(szBuff, "/JS ");
//		if(pdest1)
//		{
//			strcpy(szNextBuff, pdest1+3);
//			pdest2 = strstr(szNextBuff, ">>");
//			if(pdest2)
//			{
//				nBuff = pdest2 - szNextBuff;
//				szNextBuff[nBuff] = 0;
//			}
//			if((szNextBuff[0] != '/') && !strstr(szNextBuff, " R"))
//			{
//				bReturn = true;
//				nStreamLength = strlen(szNextBuff);
//				SaveStream(szNextBuff, nStreamLength);
//				continue;
//			}
//		}
//
//		// return encrypt method and length of stream
//		pszBuff = GetCryptMethod(szBuff, &nStreamLength);
//		if(nStreamLength <= 0 || nStreamLength >= MAX_BUFF_LENGTH) continue;
//		strcpy(pszBuff, LeftTrim(pszBuff, ' '));
//		strcpy(pszBuff, RightTrim(pszBuff, ' ' ));
//		strcpy(pszBuff, LeftTrim(pszBuff, '['));
//		strcpy(pszBuff, RightTrim(pszBuff, ']'));
//		strcpy(pszBuff, LeftTrim(pszBuff, ' '));
//		strcpy(pszBuff, RightTrim(pszBuff, ' ' ));
//
//		// read stream data from pdf file		
//		nRead = fz_my_get_stream(file, szBuff, MAX_BUFF_LENGTH);
//
//		// find a stream from pdf file with the above encrypt method and length
//		if(szBuff[0] == 's' && szBuff[1] == 't' && szBuff[2] == 'r' && szBuff[3] == 'e' && szBuff[4] == 'a' && szBuff[5] == 'm')
//		{
//			pdest1 = szBuff;
//			if(szBuff[6] == '\n') pdest1 += 7;
//			else if(szBuff[6] == '\r' && szBuff[7] == '\n') pdest1 += 8;
//			else if(szBuff[6] == ' ' && szBuff[7] == '\n') pdest1 += 8;
//			else if(szBuff[6] == ' ' && szBuff[7] == '\r' && szBuff[8] == '\n') pdest1 += 9;
//			else pdest1 += 6;
//			if(nStreamLength >= MAX_BUFF_LENGTH) nStreamLength = MAX_BUFF_LENGTH;
//			memcpy(szBuff, pdest1, nStreamLength);
//			memcpy(szNextBuff, szBuff, nStreamLength);
//		}
//		else
//		{
//			nBuff = 0;
//			while(nBuff < nRead)
//			{
//				if(szBuff[nBuff] == 's' && szBuff[nBuff+1] == 't' && szBuff[nBuff+2] == 'r' && 
//					szBuff[nBuff+3] == 'e' && szBuff[nBuff+4] == 'a' && szBuff[nBuff+5] == 'm')
//				{
//					pdest1 = szBuff;
//					if(szBuff[nBuff+6] == '\n') pdest1 += nBuff + 7;
//					else if(szBuff[nBuff+6] == '\r' && szBuff[nBuff+7] == '\n') pdest1 += nBuff + 8;
//					else if(szBuff[nBuff+6] == ' ' && szBuff[nBuff+7] == '\n') pdest1 += nBuff + 8;
//					else if(szBuff[nBuff+6] == ' ' && szBuff[nBuff+7] == '\r' && szBuff[nBuff+8] == '\n') pdest1 += nBuff + 9;
//					else pdest1 += nBuff + 6;
//					if(nStreamLength >= MAX_BUFF_LENGTH) nStreamLength = MAX_BUFF_LENGTH;
//					memcpy(szBuff, pdest1, nStreamLength);
//					memcpy(szNextBuff, szBuff, nStreamLength);
//					break;
//				}
//				nBuff ++;
//			}
//		}
//
//		if(nRead > 0) 
//		{
//			bReturn = true;
//			SaveStream(szBuff, nStreamLength);
//		}
//	}
//
//	// close pdf file and release memory
//	fz_close(file);
//	fz_flush_warnings();
//
//	return bReturn;
	return true;
}

char * LeftTrim(char *pszBuff, char chItem)
{
	while(1) 
	{
		if(pszBuff[0] == chItem) pszBuff++;
		else break;
	}
	return pszBuff;
}

char * RightTrim(char *pszBuff, char chItem)
{
	while(1)
	{
		if(pszBuff[strlen(pszBuff) - 1] == chItem) pszBuff[strlen(pszBuff) - 1] = 0;
		else break;
	}
	return pszBuff;
}

void SaveStream(char *pszBuff, int nLength)
{
	FILE *OutFile;
	TCHAR szFileName[MAX_PATH];
	TCHAR szNumber[100];

	if(nLength > 0)
	{
		m_nStreamCount ++;

		_tcscpy(szFileName, m_szOutput);
		_tcscat(szFileName, L"\\");
		_stprintf(szNumber, L"stream%d.dmp", m_nStreamCount);
		_tcscat(szFileName, szNumber);	

		OutFile = _tfopen(szFileName, L"w+");
		if(OutFile)
		{
			fwrite("<austreamdump>", 1, 15, OutFile); //neeraj
			fwrite(pszBuff, 1, nLength, OutFile);
			fclose(OutFile);
		}
	}
}

// return encrypt method and length of stream
//char * GetCryptMethod(char *pszBuff, unsigned long * nStreamLength)
//{
//	int i, j, nLen, nBuff;
//	char *stopstring;
//	char szSearch[7];
//	//char szNewBuff[MAX_BUFF_LENGTH];
//	//char g_szNextBuff[MAX_BUFF_LENGTH];
//
//	// normalize filter name into character
//	nLen = strlen(pszBuff);
//	j = 0;
//	for(i=0; i<nLen; i++)
//	{
//		if(pszBuff[i] == '#')
//		{
//			szSearch[0] = pszBuff[i+1];
//			szSearch[1] = pszBuff[i+2];
//			szSearch[2] = 0;
//
//			szNewBuff[j] = (char)strtoul(szSearch, &stopstring, 16);
//
//			i += 2;
//			j ++;
//		}
//		else 
//		{
//			szNewBuff[j] = pszBuff[i];
//			j ++;
//		}
//	}
//	szNewBuff[j] = 0;
//
//	// initialize return value
//	m_szCryptMethod[0] = 0;
//	*nStreamLength = 0;
//
//	// find the encrypt method and length of a stream from pdf file
//	for(i=0; i<nLen; i++)
//	{
//		if(szNewBuff[i] == '/' && szNewBuff[i+1] == 'F' && szNewBuff[i+2] == 'i' && 
//			szNewBuff[i+3] == 'l' && szNewBuff[i+4] == 't' && szNewBuff[i+5] == 'e' && szNewBuff[i+6] == 'r')
//		{
//			strcpy(m_szCryptMethod, szNewBuff+i+7);
//			strcpy(m_szCryptMethod, LeftTrim(m_szCryptMethod, ' '));
//			stopstring = strstr(m_szCryptMethod, "/Length");
//			if(stopstring)
//			{
//				nBuff = stopstring - m_szCryptMethod;
//				m_szCryptMethod[nBuff] = 0;
//			}
//
//			for(j=i+7; j<nLen; j++)
//			{
//				if(szNewBuff[j] == '/' && szNewBuff[j+1] == 'L' && szNewBuff[j+2] == 'e' && 
//					szNewBuff[j+3] == 'n' && szNewBuff[j+4] == 'g' && szNewBuff[j+5] == 't' && szNewBuff[j+6] == 'h')
//				{
//					strcpy(g_szNextBuff, szNewBuff+j);
//					strcpy(g_szNextBuff, LeftTrim(g_szNextBuff, ' '));
//					stopstring = strchr(g_szNextBuff, ' ');
//					if(stopstring)
//					{
//						strcpy(g_szNextBuff, stopstring+1);
//					}
//					stopstring = strchr(g_szNextBuff, ' ');
//					if(stopstring)
//					{
//						nBuff = stopstring - g_szNextBuff;
//						g_szNextBuff[nBuff] = 0;
//					}
//
//					*nStreamLength = (unsigned long)strtoul(g_szNextBuff, &stopstring, 10);
//
//					return m_szCryptMethod;
//				}
//			}
//		}
//
//		if(szNewBuff[i] == '/' && szNewBuff[i+1] == 'L' && szNewBuff[i+2] == 'e' && 
//			szNewBuff[i+3] == 'n' && szNewBuff[i+4] == 'g' && szNewBuff[i+5] == 't' && szNewBuff[i+6] == 'h')
//		{
//			strcpy(g_szNextBuff, szNewBuff+i+7);
//			strcpy(g_szNextBuff, LeftTrim(g_szNextBuff, ' '));
//			stopstring = strchr(g_szNextBuff, ' ');
//			if(stopstring)
//			{
//				nBuff = stopstring - g_szNextBuff;
//				g_szNextBuff[nBuff] = 0;
//			}
//			*nStreamLength = (unsigned long)strtoul(g_szNextBuff, &stopstring, 10);
//
//			for(j=i+7; j<nLen; j++)
//			{
//				if(szNewBuff[j] == '/' && szNewBuff[j+1] == 'F' && szNewBuff[j+2] == 'i' && 
//					szNewBuff[j+3] == 'l' && szNewBuff[j+4] == 't' && szNewBuff[j+5] == 'e' && szNewBuff[j+6] == 'r')
//				{
//					strcpy(m_szCryptMethod, szNewBuff+j+7);
//					strcpy(m_szCryptMethod, LeftTrim(m_szCryptMethod, ' '));
//					stopstring = strstr(m_szCryptMethod, ">>");
//					if(stopstring)
//					{
//						nBuff = stopstring - m_szCryptMethod;
//						m_szCryptMethod[nBuff] = 0;
//					}
//
//					return m_szCryptMethod;
//				}
//			}
//		}
//	}
//	return m_szCryptMethod;
//}

int fz_my_get_stream(fz_stream *stm, char *mem, int n)
{
	char *s = mem;
	int c = EOF;
	int j, nRead = n;
	char szEndStream[10];

	while(n > 1)
	{
		c = fz_read_byte(stm);
		if(c == EOF) break;
		if(c == 'e') 
		{
			j = fz_read(stm, (unsigned char *)szEndStream, 8);
			szEndStream[j] = 0;
			if(strstr(szEndStream, "ndstream") || strstr(szEndStream, "ndobj"))
				break;
			else
			{
				*s++ = c; n--;
				fz_seek(stm, -8, SEEK_CUR);
			}
		}
		else
		{
			*s++ = c;
			n--;
		}
	}
	if(n)
	{
		*s = '\0';
		nRead -= n;
	}
	return nRead;
}
