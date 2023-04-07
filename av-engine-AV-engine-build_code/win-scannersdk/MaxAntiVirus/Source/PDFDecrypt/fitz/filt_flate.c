#include "fitz.h"

#include <zlib.h>

typedef struct fz_flate_s fz_flate;

struct fz_flate_s
{
	fz_stream *chain;
	z_stream z;
};

static void *zalloc(void *opaque, unsigned int items, unsigned int size)
{
	return fz_calloc(items, size);
}

static void zfree(void *opaque, void *ptr)
{
	fz_free(ptr);
}

int m_nTotalStreamCount = 0;
void SaveDecyptStream(char *pszBuff, int nLength)
{
	FILE *OutFile;
	char szFileName[512];
	char szNumber[100];

	m_nTotalStreamCount ++;

	//GetCurrentDirectory(512, szFileName);
	//if(szFileName[strlen(szFileName)-1] == '\\') szFileName[strlen(szFileName)-1] = 0;
	//strcat(szFileName, "\\");
	szFileName[0] = 0;
	sprintf(szNumber, "stream%d.dmp", m_nTotalStreamCount);
	strcat(szFileName, szNumber);

	OutFile = fopen(szFileName, "w+");
	fwrite(pszBuff, 1, strlen(pszBuff), OutFile);
	fclose(OutFile);
}

static int
read_flated(fz_stream *stm, unsigned char *outbuf, int outlen)
{
	fz_flate *state = stm->state;
	fz_stream *chain = state->chain;
	z_streamp zp = &state->z;
	int code;

	zp->next_out = outbuf;
	zp->avail_out = outlen;

	while (zp->avail_out > 0)
	{
		if (chain->rp == chain->wp)
			fz_fill_buffer(chain);

		zp->next_in = chain->rp;
		zp->avail_in = chain->wp - chain->rp;

		code = inflate(zp, Z_SYNC_FLUSH);

		chain->rp = chain->wp - zp->avail_in;

		if (code == Z_STREAM_END)
		{
			return outlen - zp->avail_out;
		}
		else if (code == Z_BUF_ERROR)
		{
			fz_warn("premature end of data in flate filter");
			return outlen - zp->avail_out;
		}
		else if (code == Z_DATA_ERROR && zp->avail_in == 0)
		{
			fz_warn("ignoring zlib error: %s", zp->msg);
			return outlen - zp->avail_out;
		}
		else if (code != Z_OK)
		{
			return fz_throw("zlib error: %s", zp->msg);
		}
	}

	//SaveDecyptStream(outbuf, outlen - zp->avail_out);

	return outlen - zp->avail_out;
}

static void
close_flated(fz_stream *stm)
{
	fz_flate *state = stm->state;
	int code;

	code = inflateEnd(&state->z);
	if (code != Z_OK)
		fz_warn("zlib error: inflateEnd: %s", state->z.msg);

	fz_close(state->chain);
	fz_free(state);
}

fz_stream *
fz_open_flated(fz_stream *chain)
{
	fz_flate *state;
	int code;

	state = fz_malloc(sizeof(fz_flate));
	state->chain = chain;

	state->z.zalloc = zalloc;
	state->z.zfree = zfree;
	state->z.opaque = NULL;
	state->z.next_in = NULL;
	state->z.avail_in = 0;

	code = inflateInit(&state->z);
	if (code != Z_OK)
		fz_warn("zlib error: inflateInit: %s", state->z.msg);

	return fz_new_stream(state, read_flated, close_flated);
}

int fz_my_Flate_Decrypt(char *dst, long *dstLen, char *src, long srcLen)
{
	int nReturn = 1;
	z_stream zp;
	int code;
	long ndst = *dstLen;
	unsigned char *wp, *rp;

	memset(dst, 0x0, *dstLen);

	zp.zalloc = zalloc;
	zp.zfree = zfree;
	zp.opaque = NULL;
	zp.next_in = NULL;
	zp.avail_in = 0;

	code = inflateInit(&zp);
	if(code != Z_OK)
		fz_warn("zlib error: inflateInit: %s", zp.msg);

	ndst = 10335;
	zp.next_out = dst;
	zp.avail_out = ndst;

	rp = (unsigned char *)src;
	wp = (unsigned char *)((unsigned long)src + (unsigned long)srcLen);
	while(zp.avail_out > 0)
	{
		zp.next_in = rp;
		zp.avail_in = wp - rp;

		code = inflate(&zp, Z_SYNC_FLUSH);

		rp = wp - zp.avail_in;

		if(code == Z_STREAM_END)
		{
			break;
		}
		else if(code == Z_BUF_ERROR)
		{
			fz_warn("premature end of data in flate filter");
			break;
		}
		else if(code == Z_DATA_ERROR && zp.avail_in == 0)
		{
			fz_warn("ignoring zlib error: %s", zp.msg);
			break;
		}
		else if(code != Z_OK)
		{
			fz_throw("zlib error: %s", zp.msg);
			break;
		}
	}

	inflateEnd(&zp);

	nReturn = 1;
	*dstLen = ndst - zp.avail_out;

	if(strcmp(dst, "") != 0)
	{
		return nReturn;
	}
	else 
	{
		*dstLen = srcLen;
		strcpy(dst, src);
		nReturn = 0;
	}

	return nReturn;
}