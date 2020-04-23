#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* decrypt( char* buff, size_t size) {
    int v5; // r10
    size_t v6; // r6
    char* v7; // r11
    int v8; // r8
    char* _buf; // r0
    int v10; // r1
    signed int v11; // r2
    char* buf; // [sp+8h] [bp-28h]
    size_t v14; // [sp+Ch] [bp-24h]

    v6 = size;
    v7 = buff;

    buf = buff;
    v14 = size;
    if (*buff == 27 && buff[1] != 76)
    {
        _buf = (char*)malloc(size);
        if (v6)
        {
            *_buf = 0x1B;
            if (v6 != 1)
            {
                v10 = 0;
                v11 = 1;
                do
                {
                    v10 += v6;
                    _buf[v11] = v7[v11] ^ (v10
                        + ((unsigned int)(((unsigned __int64)(0xFFFFFFFF80808081LL * v10) >> 32) + v10) >> 7)
                        + ((signed int)(((unsigned __int64)(0xFFFFFFFF80808081LL * v10) >> 32) + v10) < 0));
                    ++v11;
                } while (v6 != v11);
            }
        }
        buf = _buf;
    }
    return buf;
}

char buff[0xFFFFFF];
int main(int argc, char* argv[]) {
    char filename[100] = "E:\\llyy\\source\\repos\\LuaDecrypt\\Debug\\main.lua";
    if (argc == 2)
        strcpy(filename, argv[1]);
    printf("File name: %s \n", filename);

    FILE* fp = fopen(filename, "rb");
    size_t size = 0;
    //获取文件长度
    fseek(fp, 0, SEEK_END); //定位到文件末 
    int nFileLen = ftell(fp); //文件长度
    fseek(fp, 0, SEEK_SET);
    size = fread(buff, sizeof(unsigned char), nFileLen, fp);
    printf("File size: %ld \n", size);

    char* res = decrypt(buff, size);

    strcat(filename, "c");
    FILE* fp1 = fopen(filename, "wb");
    fwrite(res, sizeof(unsigned char), size, fp1);
    printf("Output: %s", filename);

    return 0;
}
