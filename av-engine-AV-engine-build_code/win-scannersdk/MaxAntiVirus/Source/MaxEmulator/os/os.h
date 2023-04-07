#pragma once
#ifndef __OS__
#define __OS__  1
struct FileMapping
{
	MAX_DWORD hFile;
    MAX_DWORD hMapping;
    MAX_DWORD BaseAddress;
    MAX_DWORD FileLength;
};

//unsigned long LoadProcess(string);
unsigned long GetTime();
FileMapping* OpenFile(const wchar_t*);
FileMapping* OpenFile2(const wchar_t*);
FileMapping* CreateNewFile(const wchar_t* Filename,unsigned long size);
unsigned long CloseFile(FileMapping*);
void* malloc_emu(size_t size);
void* realloc_emu(void* ptr, size_t size);
void free_emu(void* ptr);
#endif