#include <iostream>
#include <Windows.h>
using namespace std;

int InjectDLL(DWORD, char*);
int getDLLpath(char*);
int getPID(int*);

int getProc(HANDLE*, DWORD);

int getDLLpath(char* dll) 
{
	cout << "Enter path to your DLL" << endl;
	cin >> dll;
	return 1;
}

int getPID(int* pID) 
{
	cout << "Enter GTA V process ID" << endl;
	cin >> *pID;
	return 1;
}

int getProc(HANDLE* hToProcess, DWORD dwProcessId)
{
	*hToProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);
	DWORD dwLastError = GetLastError();
	if (hToProcess == NULL) {
		cout << "Handle to process is invalid. Unable to open GTA V process" << endl;
		return -1;
	}
	else
	{
		cout << "GTA V Process has been successfully opened!" << endl;
		return 1;
	}
} 

int InjectDLL(DWORD pID, char* dll)
{
	HANDLE hToProcess;
	LPVOID LoadLibAddr;
	LPVOID bAddr;
	HANDLE remoteThread;

	int dllLen = strlen(dll) + 1;

	if (getProc(&hToProcess, pID) < 0)
		return -1;

	LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	if (!LoadLibAddr)
		return -1;

	bAddr = VirtualAllocEx(hToProcess, NULL, dllLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!bAddr)
		return -1;

	if (!WriteProcessMemory(hToProcess, bAddr, dll, dllLen, NULL))
		return -1;

	remoteThread = CreateRemoteThread(hToProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, bAddr, 0, NULL);
	if (!remoteThread)
		return -1;

	WaitForSingleObject(remoteThread, INFINITE);

	VirtualFreeEx(hToProcess, bAddr, dllLen, MEM_RELEASE);

	if (CloseHandle(remoteThread) == 0)
		cout << "Failed to close handle for remote thread!";

	if (CloseHandle(hToProcess) == 0)
		cout << "Failed to close handle for target GTA V process!";
}

int main() {
	SetConsoleTitle(L"RAGE Injector v.1.0 by k0t0ff");

	int pID = -1;
	char* dll = new char[255];

	getDLLpath(dll);
	getPID(&pID);

	InjectDLL(pID, dll);

	system("pause");

	return 0;
}
