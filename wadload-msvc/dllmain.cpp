#define WIN32_LEAN_AND_MEAN//从 Windows 头文件中排除极少使用的内容
#include <windows.h>
#include <iostream>
#include <string>
using namespace std;

void WINAPI WadLoadCall(const char* WadPath, DWORD Esi_);
extern "C" __declspec(dllexport) void WINAPI Easy_hook_cpp();

//************************************************************************
DWORD hook_address = 0x006EA8D5;//hook地址
DWORD hook_return_address = hook_address + 5;//hook跳回地址

static BYTE* empty_memory;//空白内存
bool LoadFlag = 0;
DWORD CallAddress = 0x006E4750;//call地址

//************************************************************************
char* path = new char[MAX_PATH] {};
const char path_buf[] = "skn\\1.wad";
int serr = strcpy_s(path, MAX_PATH, path_buf);//文本内容赋值到缓冲区
DWORD DWORDwadpath = (DWORD)path;//取无符号整数首地址
//************************************************************************

void WINAPI WadLoadCall(const char* WadPath, DWORD Esi_)//*********************************** 加载call
{  
    DWORD address = CallAddress;
    char* buffer = new char[MAX_PATH] {};//申请内存
    strcpy_s(buffer, MAX_PATH, WadPath);
    DWORD wadpath = (DWORD)buffer;

    __asm push wadpath;
    __asm push Esi_;
    __asm call address;

    delete[] buffer;//释放内存
}
void Hook_function(DWORD esi)//************************************************************** 挂接函数，我们自己的call
{
    WadLoadCall("1.wad", esi);
}
__declspec(naked) void Hook_call_back()//**************************************************** 回调函数
{
	__asm pushad;//保存寄存器

	__asm push esi;
	__asm call Hook_function;
	__asm add esp, 0x4;

	__asm popad;//恢复寄存器
    __asm Jmp empty_memory;//跳回去
}
void WINAPI Easy_hook_cpp()//**************************************************************** 功能函数
{   
    //******************************************************************************** 保存 "push地址" 5个字节
    BYTE old_PushCore[5] = {0};
    ReadProcessMemory(INVALID_HANDLE_VALUE, (LPVOID)hook_address, old_PushCore, 5, 0);
    //******************************************************************************** 申请一块空白内存 改为可读可写权限
    empty_memory = new BYTE[100]{};//申请内存100个字节
    DWORD old_Protect = 0;//旧保护属性
    DWORD new_Protect = PAGE_EXECUTE_READWRITE;//新保护属性
    VirtualProtect(empty_memory, 100, new_Protect, &old_Protect);//修改内存属性
    //******************************************************************************** "push地址" 5个字节 写到空白内存
    WriteProcessMemory(INVALID_HANDLE_VALUE, (LPVOID)empty_memory, old_PushCore, 5, 0);
    //******************************************************************************** "jmp x" 5个字节 写到空白内存
    empty_memory[5] = 0xE9;//jmp + 4字节
    DWORD empty_jmp_address = hook_return_address - (DWORD)(empty_memory + 5) - 5;//公式：目标地址 - 当前地址 - 5
    *(DWORD*)(&empty_memory[0] + 6) = empty_jmp_address;
    //******************************************************************************** 机器码 写到hook地址
	BYTE jmp_code[5] = { 0xE9,0,0,0,0 };
    DWORD hook_jmp_addr = (DWORD)Hook_call_back - hook_address - 5;
    *(DWORD*)(&jmp_code[0] + 1) = hook_jmp_addr;
    
    return;
    //delete[] empty_memory;//释放内存
}
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {

    }
    return TRUE;
}
