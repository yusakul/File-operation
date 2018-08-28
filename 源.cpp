#include<iostream>
#include<Windows.h>
#include <tchar.h>
#include<cstring>
using namespace std;

char* g_byBuffer;

int main() {
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi = { 0 };
	BOOL bRet = 0;
	OPENFILENAME stOF;
	HANDLE hFile;
	TCHAR szFileName[MAX_PATH] = { 0 }; //要打开的文件路径及名称名
	TCHAR szExtPe[] = TEXT("PE s\0*.exe;*.dll;*.bin;*.scr;*.fon;*.drv\0All s(*.*)\0*.*\0\0");
	RtlZeroMemory(&stOF, sizeof(stOF));
	stOF.lStructSize = sizeof(stOF);
	stOF.hwndOwner = NULL;
	stOF.lpstrFilter = szExtPe;
	stOF.lpstrFile = szFileName;
	stOF.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	stOF.lpstrInitialDir = NULL;
	stOF.nMaxFile = MAX_PATH;
	stOF.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileName(&stOF))		//让用户选择打开的文件
	{
		MessageBox(NULL, szFileName, TEXT("选中"), MB_OK);
	}
	else {
		MessageBox(NULL, _T("error"), TEXT(" not found"), MB_OK);
	}

	

	hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return false;
	}

	const int BUFSIZE = 4096;
	DWORD dwReatenSize = 0;
	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);
	g_byBuffer = (char*)malloc(dwFileSize);

	bRet = ReadFile(hFile, g_byBuffer, dwFileSize, &dwReatenSize, NULL);
	if (!bRet)
	{
		::MessageBox(NULL, "Read Failure...", _T("error"), MB_OK);
		CloseHandle(hFile);
		return true;
	}

	//检查文件是否为空
	if (dwReatenSize == 0) {
		TCHAR TEMP[50] = { 0 };
		wsprintf(TEMP, "Invalid file size: %u Bytes", dwReatenSize);
		::MessageBox(NULL, TEMP, _T("error"), MB_OK);
		return false;
	}
	CloseHandle(hFile);
	return true;
}



