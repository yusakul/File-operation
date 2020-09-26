//本项目目的为修复meterpreter框架生成的木马PE文件。
//这些文件在文件头构造启动代码，执行反射注入加载自身到内存
//同时反射加载自身时修复导入表，我们要做的就时代为修复IAT

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
//#include <ImageHlp.h>
using namespace std;

DWORD RvaToOffset(DWORD Rva, PIMAGE_DOS_HEADER m_pNewBuf)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		if (Rva >= pSection->VirtualAddress &&
			Rva <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
		{
			// 如果文件地址为0,将无法在文件中找到对应的内容
			if (pSection->PointerToRawData == 0)
			{
				return -1;
			}
			return Rva - pSection->VirtualAddress + pSection->PointerToRawData;
		}
		pSection = pSection + 1;
	}
}


#include  < Dbghelp.h >   // ImageRvaToVa
#pragma comment(lib,"Dbghelp.lib")
 

int  main(int  argc, char* argv[])
{
	int  i, j;
	HANDLE hFile = CreateFileA(
		"D:\\Project\\cpp_project\\RepariIAT\\RepariIAT\\Debug\\22.bin",  // PE文件名
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf(" Create File Failed.\n ");
		return   0;
	}

	DWORD64 FileSize = GetFileSize(hFile, NULL);
	LPVOID lpBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize);
	DWORD outSize = 0;
	ReadFile(hFile, lpBaseAddress, FileSize, &outSize, NULL);

	/*
	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hFileMapping == NULL || hFileMapping == INVALID_HANDLE_VALUE)
	{
		printf(" Could not create file mapping object (%d).\n ", GetLastError());
		return   0;
	}

	LPBYTE lpBaseAddress = (LPBYTE)MapViewOfFile(hFileMapping,    //  handle to map object
		FILE_MAP_READ, 0, 0, 0);
*/
	if (lpBaseAddress == NULL)
	{
		printf(" Could not map view of file (%d).\n ", GetLastError());
		return   0;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpBaseAddress + pDosHeader->e_lfanew);
	DWORD NumberOfSymbols = pNtHeaders->FileHeader.NumberOfSymbols;// 符号表中符号个数
	SIZE_T ImageSize = pNtHeaders->OptionalHeader.SizeOfImage;

	// 导入表的rva：0x2a000;
	DWORD Rva_import_table = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (Rva_import_table == 0)
	{
		printf(" no import table! ");
		UnmapViewOfFile(lpBaseAddress);
		//CloseHandle(hFileMapping);
		CloseHandle(hFile);
		getchar();
		return 0;
	}

	// 这个虽然是内存地址，但是减去文件开头的地址，就是文件地址了
	// 这个地址可以直接从里面读取你想要的东西了
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa(
		pNtHeaders,
		lpBaseAddress,
		Rva_import_table,
		NULL
	);

	// 减去内存映射的首地址，就是文件地址了。。（很简单吧）
	//printf(" FileAddress Of ImportTable: %p\n ", ((DWORD)pImportTable - (DWORD)lpBaseAddress));

	// 现在来到了导入表的面前：IMAGE_IMPORT_DESCRIPTOR 数组（以0元素为终止）
	// 定义表示数组结尾的null元素！
	IMAGE_IMPORT_DESCRIPTOR null_iid;
	IMAGE_THUNK_DATA null_thunk;
	memset(&null_iid, 0, sizeof(null_iid));
	memset(&null_thunk, 0, sizeof(null_thunk));

	// 每个元素代表了一个引入的DLL。
	for (i = 0; memcmp(pImportTable + i, &null_iid, sizeof(null_iid)) != 0; i++)
	{
		// LPCSTR: 就是 const char*
		//rva 2 va
		LPCSTR szDllName = (LPCSTR)ImageRvaToVa(
			pNtHeaders, lpBaseAddress,
			pImportTable[i].Name,  // DLL名称 rva
			NULL);

		//DWORD addr = RvaToOffset(pImportTable[i].Name + (DWORD)pDosHeader, pDosHeader); //到内存中的pe文件的 dll名称 的地址rva


		//LPCSTR dllNamefileoffset = (LPCSTR)pImportTable[i].Name  -  pImportTable[i].Name -dwOffset + ()lpBaseAddress;
		BYTE* ModName = (BYTE*)ImageRvaToVa(pNtHeaders, lpBaseAddress, pImportTable[i].Name, NULL);


		for (int l = 0; l < 0x40; ++l)
		{
			ModName[l] ^= NumberOfSymbols;   // 解密名称
			if (!(ModName[l] >= 'a' && ModName[l] <= 'z')
				&&
				!(ModName[l] >= 'A' && ModName[l] <= 'Z')
				&&
				!(ModName[l] == '_') 
				&&
				!(ModName[l] == '.')
				&&
				!(ModName[l] >='0' && ModName[l] <='9')
				)
			{
				ModName[l] = '\0';
				break;
			}
		}

		// 拿到了DLL的名字
		printf(" -----------------------------------------\n ");
		printf(" [%d]: %s\n ", i, ModName);
		printf(" -----------------------------------------\n ");

		// 现在去看看从该DLL中引入了哪些函数
		// 我们来到该DLL的 IMAGE_TRUNK_DATA 数组（IAT：导入地址表）前面
		PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)ImageRvaToVa(
			pNtHeaders, lpBaseAddress,
			pImportTable[i].OriginalFirstThunk, //【注意】这里使用的是OriginalFirstThunk
			NULL);

		for (j = 0; memcmp(pThunk + j, &null_thunk, sizeof(null_thunk)) != 0; j++)
		{
			// 这里通过RVA的最高位判断函数的导入方式，
			// 如果最高位为1，按序号导入，否则按名称导入
			if (pThunk[j].u1.AddressOfData & IMAGE_ORDINAL_FLAG32)
			{
				//printf(" \t [%d] \t %ld \t 按序号导入\n ", j, pThunk[j].u1.AddressOfData & 0xffff);
			}
			else
			{
				// 按名称导入，我们再次定向到函数序号和名称
				// 注意其地址不能直接用，因为仍然是RVA！
				PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(
					pNtHeaders, lpBaseAddress,
					pThunk[j].u1.AddressOfData,
					NULL);
				
				for (int k = 0; k < 0x40; ++k)
				{
					pFuncName->Name[k] ^= NumberOfSymbols;   // 解密名称
					if (!(pFuncName->Name[k] >= 'a' &&  pFuncName->Name[k] <= 'z')
						&&
						!(pFuncName->Name[k] >= 'A' && !pFuncName->Name[k] <= 'Z')
						) 
					{
						pFuncName->Name[k] = '\0';
						break;
					}
				}
				printf(" \t [%d] \t %ld \t %s\n ", j, pFuncName->Hint, pFuncName->Name);
			}
		}
	}

	HANDLE hFileFix = CreateFileA(
		"D:\\Project\\cpp_project\\RepariIAT\\RepariIAT\\Debug\\22.bin.fix",  // PE文件名
		GENERIC_ALL,
		FILE_SHARE_READ,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFileFix == INVALID_HANDLE_VALUE)
	{
		printf(" Create File Failed.\n ");
		return   0;
	}
	DWORD dwBytesWrite = 0;

	WriteFile(hFileFix, lpBaseAddress, ImageSize, &dwBytesWrite, NULL);


UNMAP_AND_EXIT:

	// 关闭文件，句柄。。
	UnmapViewOfFile(lpBaseAddress);
	//CloseHandle(hFileMapping);
	CloseHandle(hFileFix);
	CloseHandle(hFile);
	getchar();
	return   0;
}
