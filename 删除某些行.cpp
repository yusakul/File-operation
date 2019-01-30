#include<iostream>
#include<fstream>
#include<string>
#include <iosfwd>
#include<Windows.h>
#include <tchar.h>
#include<cstring>
using namespace std;


int main(int argv, char *arg[])
{

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


	int i = 0;
	fstream  fpoint(szFileName);//创建一个fstream文件流对象
	if (!fpoint)
	{
		printf("打开文件失败\n");
		system("pause");
		return 0;
	}
	string   line; 
	string strFileData = "";
	while (getline(fpoint, line))//会自动把\n换行符去掉 
	{
		if (strstr(line.c_str(), "google") == NULL)//在line中查找google，如果不存在则留下
		{
			strFileData += line;
			strFileData += "\n";
		}
		i++;
			
	}
	fpoint.close();

	//写入文件
	ofstream out;
	out.open("D:\\log1.txt");
	out.flush();
	out << strFileData;
	out.close();
	printf("删除行数:%d\n", i);
	system("pause");
	return  0;

}

