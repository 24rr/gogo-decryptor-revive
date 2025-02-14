#pragma once

#include <cstdint>
#include <string>
#include <filesystem>
#include <fstream>
#include <array>

namespace decryptor
{
	class code_decryptor
	{
	public:
		code_decryptor(const std::filesystem::path& hyperion, const std::filesystem::path& roblox, const std::string& out_filename);
		~code_decryptor();

		void decrypt();

		bool is_initialized() const;

	private:
		std::uintptr_t get_base_from_handle(void* handle) const;
		bool find_encryption_context();
		bool validate_hyperion_version();
		bool process_hypv_version(std::uintptr_t hypv_loc);
		
	private:
		void* hyperion_handle;
		void* roblox_handle;

		std::uintptr_t page_info_base;
		std::uintptr_t encryption_context;

		std::ofstream out_file;
		bool is_valid;
	};
}