/*
 *
 *  Copyright (C) 2010-2011 Amr Thabet <amr.thabet@student.alx.edu.eg>
 *
 *  This program is free_emu software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Amr Thabet 
 *  amr.thabet@student.alx.edu.eg
 *
 */
 
#include "pch.h"
#include "x86emu.h"
#include "os/os.h"
#ifdef WIN32
#include <windows.h>
#endif
dword align(dword src,dword Alignment,bool lower)
{
    dword aligned_ptr=src;
    if (src % Alignment !=0){
        if(lower)aligned_ptr -= src % Alignment;
        else aligned_ptr += Alignment-(src % Alignment);
    };
    return aligned_ptr;
}

MAX_DWORD PELoader(wstring filename)
{
	//First we will open the file and read it
	long unsigned int size=0;
    WCHAR   szLogLine[1024] = { 0x00 };

    FileMapping* rawdata = OpenFile(filename.c_str());

    //------------
	//begin the PE parsing
	if (rawdata==0)
	{
		return 0;
	}

	image_header *PEHeader;
	MAX_DWORD FileHandler = 0, PEHeader_ptr = 0;

    MAX_DWORD imagebase;
	FileHandler = rawdata->BaseAddress;

    BYTE* pbyDm = (BYTE*)rawdata->BaseAddress;

    
	if (!(*((short*)FileHandler)==0x5a4d))
	{
        CloseFile(rawdata);
		return 0;
	}

	PEHeader_ptr = ((dos_header*)FileHandler)->e_lfanew + FileHandler;
	if (!(*((short*)PEHeader_ptr)==0x4550))
	{
		CloseFile(rawdata);
		return 0;
	}

	PEHeader = (image_header*)PEHeader_ptr;
	WORD wLastSecNo = PEHeader->header.number_of_sections - 1;

   image_section_header* sections=(image_section_header*)(PEHeader->header.size_of_optional_header + 
													(MAX_DWORD)&PEHeader->optional + 
													(DWORD) (wLastSecNo*40));

   if(sections->size_of_raw_data > sections->virtual_size)
	{
		size = (sections->virtual_address + sections->size_of_raw_data) +
			(PEHeader->optional.section_alignment - ((sections->virtual_address + sections->size_of_raw_data) % PEHeader->optional.section_alignment));

	}
	else
	{
		size = sections->virtual_address + sections->virtual_size +
			(PEHeader->optional.section_alignment - ((sections->virtual_address + sections->virtual_size) % PEHeader->optional.section_alignment));
	}

    //size = PEHeader->optional.size_of_image;       
	//--------------------
	//preparing the new place

	imagebase = (MAX_DWORD)VirtualAlloc(NULL, size+0x1000, MEM_COMMIT, PAGE_READWRITE);                      //the virtual place

    if(0 == imagebase)
	{
		CloseFile(rawdata);
		return 0;
	}

    memset((char*)imagebase,0,size+0x1000);                        //for reconstructing the import table
	size = PEHeader->optional.size_of_headers; 
	memcpy((char*)imagebase,(char*)FileHandler,size);

    //----------------------
	//copying the sections
	sections = NULL;
	sections=(image_section_header*)(PEHeader->header.size_of_optional_header+(MAX_DWORD)&PEHeader->optional);

    for (int i=0; i < PEHeader->header.number_of_sections; i++)
	{  
    
		dword aligned_ptr = align(sections[i].pointer_to_raw_data, PEHeader->optional.file_alignment, true);
		MAX_DWORD src  = aligned_ptr + FileHandler;
		MAX_DWORD dest = sections[i].virtual_address + imagebase;
		size = sections[i].size_of_raw_data;

		if (sections[i].pointer_to_raw_data !=0)
		{
			memcpy((char*)dest, (char*)src, size);
		}
	}

	CloseFile(rawdata);

	return imagebase; 
}

MAX_DWORD PELoader(CMaxPEFile *pMaxPEFile, MAX_DWORD &dwEmulatorFileSize)
{
	MAX_DWORD dwImageBase = 0;
	DWORD dwSizeOfImage = 0;

	WORD wLastSecNo = pMaxPEFile->m_stPEHeader.NumberOfSections - 1;

	if(pMaxPEFile->m_stSectionHeader[wLastSecNo].SizeOfRawData > 
		pMaxPEFile->m_stSectionHeader[wLastSecNo].Misc.VirtualSize)
	{
		dwSizeOfImage = (pMaxPEFile->m_stSectionHeader[wLastSecNo].VirtualAddress +
			pMaxPEFile->m_stSectionHeader[wLastSecNo].SizeOfRawData) +
			(pMaxPEFile->m_stPEHeader.SectionAlignment -
			((pMaxPEFile->m_stSectionHeader[wLastSecNo].VirtualAddress + 
			pMaxPEFile->m_stSectionHeader[wLastSecNo].SizeOfRawData) % 
			pMaxPEFile->m_stPEHeader.SectionAlignment));

	}
	else
	{
		dwSizeOfImage = (pMaxPEFile->m_stSectionHeader[wLastSecNo].VirtualAddress +
			pMaxPEFile->m_stSectionHeader[wLastSecNo].Misc.VirtualSize) +
			(pMaxPEFile->m_stPEHeader.SectionAlignment -
			((pMaxPEFile->m_stSectionHeader[wLastSecNo].VirtualAddress + 
			pMaxPEFile->m_stSectionHeader[wLastSecNo].Misc.VirtualSize) % 
			pMaxPEFile->m_stPEHeader.SectionAlignment));
	}
	
	dwSizeOfImage = (dwSizeOfImage > pMaxPEFile->m_stPEHeader.SizeOfImage) ? dwSizeOfImage : pMaxPEFile->m_stPEHeader.SizeOfImage;
	int *ptr = (int *)VirtualAlloc(NULL, dwSizeOfImage+0x1000, MEM_COMMIT, PAGE_READWRITE);
	dwImageBase = (MAX_DWORD)ptr;

	dwEmulatorFileSize = dwSizeOfImage + 0x1000;
	if(0 == dwImageBase)
	{
		return 0;
	}

	memset((char*)dwImageBase, 0, dwSizeOfImage+0x1000);
	dwSizeOfImage = pMaxPEFile->m_stPEHeader.SizeOfHeaders;
	pMaxPEFile->ReadBuffer((LPVOID)dwImageBase, 0, dwSizeOfImage);

	for (WORD i = 0; i < pMaxPEFile->m_stPEHeader.NumberOfSections; i++)
	{  
		dword aligned_ptr = align(pMaxPEFile->m_stSectionHeader[i].PointerToRawData, pMaxPEFile->m_stPEHeader.FileAlignment, true);
		if(pMaxPEFile->m_stSectionHeader[i].VirtualAddress < pMaxPEFile->m_stPEHeader.SizeOfHeaders)
		{
			return 0;
		}

		dword src = aligned_ptr;
		MAX_DWORD dest = pMaxPEFile->m_stSectionHeader[i].VirtualAddress + dwImageBase;
		dwSizeOfImage = pMaxPEFile->m_stSectionHeader[i].SizeOfRawData;
		pMaxPEFile->ReadBuffer((LPVOID)dest, src, dwSizeOfImage);
	}

	return dwImageBase; 
}


dword FindAPI(Process* c,dword ApiName,dword DllHandle,dword napi,dword ndll,bool defined){
      //getting the important variables from the virtual memory
      dword ptr=0;
      dword dllhandle=0;
      
      char* name=(char*)c->SharedMem->read_virtual_mem(ApiName);
	  if(name == 0)
	  {
		  return 0;
	  }

	  wchar_t szwName[MAX_PATH] = {0};
	  convert_cptr2wcptr(name, szwName, _countof(szwName));
      if(defined==true)
	  {
		  dllhandle = (dword)c->SharedMem->read_virtual_mem(DllHandle);
		  if(dllhandle == 0)
		  {
			  return 0;
		  }
		  ptr=c->getsystem()->GetAPI(szwName,dllhandle);
	  }
	  ptr=c->SharedMem->get_virtual_pointer(ptr);
      //cout << "Ptr = "<<(int*)ptr << "\n";
      
      if (ptr==0 && defined==true)return 0;
      //getting the image pointer and size to begin searching
      dword image=(dword)c->SharedMem->read_virtual_mem(c->GetImagebase());
      dword PEHeader_ptr=((dos_header*)image)->e_lfanew + image;
      image_header* PEHeader=(image_header*)PEHeader_ptr;
      dword size=PEHeader->optional.size_of_image;
      //create the virtual address that returned from getprocaddress as it's undefined dll
      if (defined==false){
         ptr=0xBBBB0000+(napi << 8) +ndll;
      };
      //begin searching
      for (DWORD i=0;i<size-4;i++){
          dword* p=(dword*)(image+i);             //the place we will test if it contains the address
          if (*p==ptr){
             return c->SharedMem->get_virtual_pointer((dword)p);
             };
      };
      //we don't found so return zero
      return 0;
      
};
dword ReconstructImportTable(Process* c){
      //creating a new section for the import table
      dword image=(dword)c->SharedMem->read_virtual_mem(c->GetImagebase());
      dword PEHeader_ptr=((dos_header*)image)->e_lfanew + image;
      image_header* PEHeader=(image_header*)PEHeader_ptr;
      dword size=PEHeader->optional.size_of_image;
      PEHeader->header.number_of_sections++;
      int i=PEHeader->header.number_of_sections-1; 
      image_section_header* sections=(image_section_header*)(PEHeader->header.size_of_optional_header+(dword)&PEHeader->optional);
      sections[i].name[0]=(char)'i';
      sections[i].name[1]=(char)'d';
      sections[i].name[2]=(char)'a';
      sections[i].name[3]=(char)'t';
      sections[i].name[4]=(char)'a';
      sections[i].virtual_address=size;
      sections[i].pointer_to_raw_data=size;
      sections[i].virtual_size=0x1000;
      sections[i].size_of_raw_data=0x1000;
      sections[i].characteristics =0xE0000040;
      PEHeader->optional.size_of_image+=0x1000;
      //getting the new section address
      image_import_descriptor* sec=(image_import_descriptor*)(sections[i].virtual_address+image);
      //parsing the new import table
      int nsec=0;
      for (DWORD i=0;i<c->nimports;i++){
         sec[nsec].name=c->imports[i]->name-c->GetImagebase();
         dword x=FindAPI(c,c->imports[i]->apis[0],c->imports[i]->addr,0,0,c->imports[i]->defined);
         //cout << "1  "<< i << "\n";
         if (x==0){
            x=FindAPI(c,c->imports[i]->apis[0],c->imports[i]->addr,0,i,c->imports[i]->defined);
            if (x==0){
               //cout << "Error = "<< (int*)c->imports[i]->apis[0] << "\n";
               continue;
               }
            };
            //cout << "nAPIs = "<<c->imports[i]->napis << "\n";
         dword maxAddr=0,minAddr=0xFFFFFFFF;
         for (DWORD l=0;l<c->imports[i]->napis;l++){
             dword x=FindAPI(c,c->imports[i]->apis[l],c->imports[i]->addr,l,i,c->imports[i]->defined);
             //cout << "2  "<< (int*)x << "\n";
             if (x==0){
                //cout << "Error = "<< (int*)c->imports[i]->apis[l] << "\n";
                break;
             };
             //cout << "3  "<< l << "\n";
             if (x<minAddr)minAddr=x;
             if (x>maxAddr)maxAddr=x;
             MAX_DWORD* thunk = c->SharedMem->read_virtual_mem(x);
             //cout << "4  "<< l << "\n";
             *thunk=c->imports[i]->apis[l]-2-c->GetImagebase();
         }; 
         MAX_DWORD* thunk=c->SharedMem->read_virtual_mem(maxAddr+4);
         *thunk=0;
         sec[nsec].original_first_thunk=minAddr-c->GetImagebase();
         sec[nsec].first_thunk=minAddr-c->GetImagebase();
         nsec++;
      };
      PEHeader->optional.data_directory[1].virtual_address=((dword)sec)-image;
      PEHeader->optional.data_directory[1].size=0x50;
      return 0;
};
dword PEDump(dword Eip,Process* c,wchar_t* filename){
      //FileMapping* rawdata=OpenFile(filename);
      image_header *PEHeader;
      dword FileHandler,PEHeader_ptr;
//      image_section_header* data;
      FileHandler=(dword)c->SharedMem->read_virtual_mem(c->GetImagebase());
      if (!(*((short*)FileHandler)==0x5a4d))return 0;
      PEHeader_ptr=((dos_header*)FileHandler)->e_lfanew + FileHandler;
      if (!(*((short*)PEHeader_ptr)==0x4550))return 0;
      PEHeader=(image_header*)PEHeader_ptr;
      dword size=align(PEHeader->optional.size_of_image,PEHeader->optional.section_alignment,false);
      image_section_header* sections=(image_section_header*)(PEHeader->header.size_of_optional_header+(dword)&PEHeader->optional);
      if (PEHeader->header.number_of_sections !=0){
          for (int i=0;i <PEHeader->header.number_of_sections-1;i++){
              sections[i].size_of_raw_data=sections[i+1].virtual_address-sections[i].virtual_address;
              sections[i].pointer_to_raw_data=sections[i].virtual_address;
              sections[i].characteristics |=0x80000000;
              //cout << "Section = "<< i << "\n";
        //          cout << "Size = "<<(int*)PEHeader->sections[i].size_of_raw_data << "\n";
        //          cout << "Pointer = "<< (int*)PEHeader->sections[i].pointer_to_raw_data << "\n";
          };
          dword index=PEHeader->header.number_of_sections-1;
          if (sections[index].virtual_size !=0)
          sections[index].size_of_raw_data=align(sections[index].virtual_size,PEHeader->optional.section_alignment,false);
          sections[index].pointer_to_raw_data=sections[index].virtual_address;
          sections[index].characteristics |=0x80000000;
      };
      //cout << "Section = "<< index << "\n";
//      cout << "Size = "<<(int*)PEHeader->sections[index].size_of_raw_data << "\n";
//      cout << "Pointer = "<< (int*)PEHeader->sections[index].pointer_to_raw_data << "\n";


      PEHeader->optional.address_of_entry_point=Eip-c->GetImagebase();
      //PEHeader->optional.data_directory[1].virtual_address=0;                      //delete the import table right now to be fixed by
      //PEHeader->optional.data_directory[1].size=0;                                 //another program or manually
      FileMapping* rawdata=CreateNewFile(filename,(unsigned long)size+0x1000);
      if (rawdata != 0){
          if(rawdata->hMapping==1){                                                 //Linux Writing File
              rawdata->BaseAddress=FileHandler;
          }else{
              memcpy((char*)rawdata->BaseAddress,(char*)FileHandler,size);
          }
         CloseFile(rawdata);
      };
	  return 0;
};
//-------------------------------------------------------------------------------------------------------------------------------
dword UnloadImportTable(Process* c){
     dword FileHandler=(dword)c->SharedMem->read_virtual_mem(c->GetImagebase());
     image_header* PEHeader=(image_header*)(((dos_header*)FileHandler)->e_lfanew + FileHandler);
     image_import_descriptor* Imports=(image_import_descriptor*)(PEHeader->optional.data_directory[1].virtual_address+FileHandler);
     for (int i=0;i<100;i++){
         if (Imports->original_first_thunk==0 && Imports->first_thunk==0 && Imports->name==0)break;
         image_import_by_name** names;                                       //pointer to the names that we will get's address
          dword* pointers;                                    //pointer to the the place that we will put the addresses there                                 
          if (Imports->original_first_thunk==0)return 0;
          names=(image_import_by_name**)Imports->original_first_thunk;                                               
          names=(image_import_by_name**)((dword)names+FileHandler);
          pointers=(dword*)(Imports->first_thunk + FileHandler);
          if (Imports->first_thunk==0)return 0;
          for (int i=0;i<200;i++){
              if (names[i]==0)break;
              memcpy(&pointers[i],&names[i],4);
          };
     };
	 return 0;
};
//-----------------------------------------------------------------------------------------------------------------------
