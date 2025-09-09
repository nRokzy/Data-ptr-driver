#include <iostream>
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <thread>
#include <chrono>
#include <string>

#include "xorstr.hpp"
#include "callstack_spoofer.hpp"

#include "driver.hpp"

int main()
{
	init_driver_deps();

	if (!is_driver_loaded()) {
		std::cout << xs("driver is not loaded!!!") << std::endl;
		std::cin.get();
		return 0;
	}
	std::cout << xs("driver is loaded!") << std::endl;

	HWND hwnd = 0;
	while (!hwnd)
	{
		hwnd = FindWindowA("UnityWndClass", NULL);
		Sleep(10);
	}

	DWORD process_id;

	GetWindowThreadProcessId(hwnd, &process_id);
	
	set_driver_target_process(process_id);

	while (true) {
		uint64_t base = get_module_base("RustClient.exe");
		printf("base -> 0x%llx\n", base);
	}

	//uint64_t addr = 0xFCF21999A0;
	//printf("addr before write -> %d\n", read<int>(addr));
	//write<int>(addr, 0);
	//printf("addr arter write -> %d\n", read<int>(addr));

	system("pause");
}