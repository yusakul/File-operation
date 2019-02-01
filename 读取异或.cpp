#include <stdio.h>
#include <windows.h>

int main(void)
{
	char acDirAndFileName[] = { "D:\\source.abc" };
	int i, iByteNum,j,k;
	FILE* pFile, *pFileA;
	DWORD dwNum = 0;

	// 以二进制方式读取文件
	fopen_s(&pFile, acDirAndFileName, "rb");
	if (pFile == NULL)
	{
		printf("%s\n", "读取文件失败，请重新输入文件名。");
		goto EXIT_;
	}

	fopen_s(&pFileA, "D:\\result.efg", "ab+");
	
	fseek(pFile, 0, SEEK_END);
	// 统计文件字节数
	iByteNum = ftell(pFile);
	rewind(pFile);


	for (i = 1, j = 3; i <= iByteNum; i++)
	{
		BYTE byte0 = fgetc(pFile);
		dwNum = dwNum | (byte0 << ((j--)*8));
		
		
		if (j == -1)
		{
			dwNum ^= 0x63C399ED;
			for (k = 3; k >= 0; k--)
			{
				fputc(dwNum >> (k * 8), pFileA);
			}
			dwNum = 0;
			j = 3;
		}
	}

	// 关闭文件
	fclose(pFile);

EXIT_:
	//system("pause");
	return 0;
}
