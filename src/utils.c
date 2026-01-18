#include <windows.h>
#include <stdlib.h>

wchar_t* ascii_to_wide(const char* str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    wchar_t* dst = malloc(len * sizeof * dst + 2);
    MultiByteToWideChar(CP_UTF8, 0, str, -1, dst, len);
    return dst;
}

char* wide_to_ascii(wchar_t* str) {
    int len = WideCharToMultiByte(
        CP_UTF8,
        0,
        str,
        -1,
        NULL,
        0,
        NULL,
        NULL
    );

    char* dst = (char*)malloc(len);

    WideCharToMultiByte(
        CP_UTF8,
        0,
        str,
        -1,
        dst,
        len,
        NULL,
        NULL
    );

    return dst;
}