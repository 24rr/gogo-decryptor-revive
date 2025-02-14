#include <iostream>
#include <filesystem>

#include "decryptor/decryptor.hpp"

using namespace decryptor;

int main()
{
	std::printf("Starting decryptor...\n");
	
	// Check if files exist first
	if (!std::filesystem::exists("RobloxPlayerBeta.dll")) {
		std::printf("Error: RobloxPlayerBeta.dll not found in current directory\n");
		std::cin.get();
		return 1;
	}
	
	if (!std::filesystem::exists("RobloxPlayerBeta.exe")) {
		std::printf("Error: RobloxPlayerBeta.exe not found in current directory\n");
		std::cin.get();
		return 1;
	}

	code_decryptor static_decryptor{ "RobloxPlayerBeta.dll", "RobloxPlayerBeta.exe", "decrypted.bin" };

	if (!static_decryptor.is_initialized())
	{
		std::printf("Decryptor failed to initialize. Press Enter to exit...\n");
		std::cin.get();
		return 1;
	}

	std::printf("Starting decryption process...\n");
	static_decryptor.decrypt();

	std::printf("Decryptor successfully finished. Press Enter to exit...\n");
	std::cin.get();
	return 0;
}