// MathClient.cpp : Client app for MathLibrary DLL.
// #include "pch.h" Uncomment for Visual Studio 2017 and earlier
#include <iostream>
#include "MathLibrary.h"
#include <windows.h> 
#include <stdio.h> 
#include <windows.h> 
#include <stdio.h> 
using namespace std;

typedef void (*MyFunctionPtr)(int, int);

int main()
{
    // first add dll in the source folder to use
    
    // create instance
    HINSTANCE hDLL = LoadLibrary(L"MathLibrary.dll");
    if (hDLL == NULL) {
        std::cout << "Failed to load DLL." << std::endl;
        return 1;
    }

    // create function pointer
    MyFunctionPtr add = (MyFunctionPtr)GetProcAddress(hDLL, "add");
    if (add == NULL) {
        std::cout << "Failed to get function address." << std::endl;
        return 1;
    }
    
    // call function using function pointer
    add(7, 2);

    // Unload the DLL
    FreeLibrary(hDLL);

    return 0;
}