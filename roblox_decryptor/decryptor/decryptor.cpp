#include "decryptor.hpp"

#include "utils/memory.hpp"
#include "utils/pe.hpp"

#include <Windows.h>

#include <vendor/chacha20/chacha20.hpp>

namespace decryptor
{
	code_decryptor::code_decryptor(const std::filesystem::path& hyperion, const std::filesystem::path& roblox, const std::string& out_filename) : page_info_base{ 0 }, encryption_context{ 0 }, is_valid{ false }
	{
		std::printf("Loading modules...\n");
		
		hyperion_handle = LoadLibraryExA(hyperion.string().c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (!hyperion_handle) {
			std::printf("Failed to load Hyperion module (RobloxPlayerBeta.dll). Error: %lu\n", GetLastError());
			return;
		}
		
		roblox_handle = LoadLibraryExA(roblox.string().c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (!roblox_handle) {
			std::printf("Failed to load Roblox module (RobloxPlayerBeta.exe). Error: %lu\n", GetLastError());
			return;
		}

		std::printf("Validating Hyperion version...\n");
		if (!validate_hyperion_version()) {
			std::printf("Invalid or unsupported Hyperion version\n");
			return;
		}

		utils::pe roblox_image{ get_base_from_handle(roblox_handle) };
		utils::pe hyperion_image{ get_base_from_handle(hyperion_handle) };

		std::printf("Locating code sections...\n");
		const auto roblox_code = roblox_image.get_section(".text");
		if (!roblox_code.virtual_range.base) {
			std::printf("Failed to locate Roblox .text section\n");
			return;
		}

		
		const char* possible_sections[] = {
			".hyperion",
			".text",
			".Hyperion",
			".hyper",
			".hpv",
			".hvp",
			".secure"
		};

		utils::section_info hyperion_code = { { 0, 0 }, { 0, 0 } };
		
		std::printf("Searching for Hyperion code section...\n");
		for (const auto& section_name : possible_sections) {
			std::printf("Trying section: %s\n", section_name);
			const auto section = hyperion_image.get_section(section_name);
			if (section.virtual_range.base) {
				hyperion_code = section;
				std::printf("Found Hyperion code in section: %s\n", section_name);
				break;
			}
		}

		if (!hyperion_code.virtual_range.base) {
			
			std::printf("Failed to find Hyperion code section in known names, dumping all sections:\n");
			IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(hyperion_image.get_nt_headers());
			const auto num_sections = hyperion_image.get_nt_headers()->FileHeader.NumberOfSections;

			for (WORD i = 0; i < num_sections; i++) {
				char section_name[9] = {0};
				std::memcpy(section_name, section[i].Name, 8);
				std::printf("Section %d: %s (size: 0x%x)\n", 
					i, 
					section_name, 
					section[i].Misc.VirtualSize);

				
				if (section[i].Characteristics & IMAGE_SCN_CNT_CODE &&
					section[i].Misc.VirtualSize > 0x10000) { 
					std::printf("Found potential Hyperion section: %s\n", section_name);
					hyperion_code = {
						{ hyperion_image.get_image_base() + section[i].VirtualAddress, section[i].Misc.VirtualSize },
						{ section[i].PointerToRawData, section[i].SizeOfRawData }
					};
					break;
				}
			}

			if (!hyperion_code.virtual_range.base) {
				std::printf("Failed to locate Hyperion code section\n");
				return;
			}
		}

		std::printf("Setting up memory protection...\n");
		DWORD old;
		if (!VirtualProtect(reinterpret_cast<LPVOID>(roblox_code.virtual_range.base), 
						  roblox_code.virtual_range.size, PAGE_READWRITE, &old)) {
			std::printf("Failed to modify memory protection. Error: %lu\n", GetLastError());
			return;
		}

		std::printf("Locating encryption context...\n");
		if (!find_encryption_context()) {
			std::printf("Failed to locate encryption context\n");
			return;
		}

		std::printf("Setting up output file...\n");
		std::ifstream src{ roblox, std::ios::binary };
		if (!src.is_open()) {
			std::printf("Failed to open source file for reading\n");
			return;
		}
		
		out_file = std::ofstream{ out_filename, std::ios::binary };
		if (!out_file.is_open()) {
			std::printf("Failed to open output file for writing\n");
			return;
		}
		
		out_file << src.rdbuf();
		src.close();

		std::printf("Initialization complete\n");
		is_valid = true;
	}

	bool code_decryptor::validate_hyperion_version()
	{
		utils::pe hyperion_image{ get_base_from_handle(hyperion_handle) };
		
		
		constexpr std::array<std::uint8_t, 4> hypv_sig = { 
			'H', 'Y', 'P', 'V'
		};

		std::printf("Scanning for HYPV signature...\n");
		
		
		const auto rdata_section = hyperion_image.get_section(".rdata");
		if (rdata_section.virtual_range.base) {
			std::printf("Scanning .rdata section...\n");
			const auto hypv_loc = utils::signature_scan(
				rdata_section.virtual_range.base,
				rdata_section.virtual_range.size,
				hypv_sig
			);
			
			if (hypv_loc) {
				return process_hypv_version(hypv_loc);
			}
		}

		
		const auto text_section = hyperion_image.get_section(".text");
		if (text_section.virtual_range.base) {
			std::printf("Scanning .text section...\n");
			const auto hypv_loc = utils::signature_scan(
				text_section.virtual_range.base,
				text_section.virtual_range.size,
				hypv_sig
			);
			
			if (hypv_loc) {
				return process_hypv_version(hypv_loc);
			}
		}

		
		const auto data_section = hyperion_image.get_section(".data");
		if (data_section.virtual_range.base) {
			std::printf("Scanning .data section...\n");
			const auto hypv_loc = utils::signature_scan(
				data_section.virtual_range.base,
				data_section.virtual_range.size,
				hypv_sig
			);
			
			if (hypv_loc) {
				return process_hypv_version(hypv_loc);
			}
		}

		
		std::printf("Scanning all sections...\n");
		IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(hyperion_image.get_nt_headers());
		const auto num_sections = hyperion_image.get_nt_headers()->FileHeader.NumberOfSections;

		for (WORD i = 0; i < num_sections; i++) {
			const auto section_base = hyperion_image.get_image_base() + section[i].VirtualAddress;
			const auto section_size = section[i].Misc.VirtualSize;
			
			char section_name[9] = {0};
			std::memcpy(section_name, section[i].Name, 8);
			std::printf("Scanning section %s...\n", section_name);

			const auto hypv_loc = utils::signature_scan(
				section_base,
				section_size,
				hypv_sig
			);
			
			if (hypv_loc) {
				return process_hypv_version(hypv_loc);
			}
		}

		
		std::printf("Failed to find HYPV signature in any section\n");
		std::printf("Hyperion base: 0x%p\n", (void*)hyperion_image.get_image_base());
		std::printf("Hyperion size: 0x%llx\n", static_cast<unsigned long long>(hyperion_image.get_image_size()));
		return false;
	}

	bool code_decryptor::process_hypv_version(std::uintptr_t hypv_loc)
	{
		
		char version[32] = {0};
		std::memcpy(version, reinterpret_cast<void*>(hypv_loc), sizeof(version) - 1);
		
		
		std::string version_str(version);
		version_str.erase(std::remove_if(version_str.begin(), version_str.end(), 
			[](char c) { return c == '\r' || c == '\n' || c == '\0'; }), version_str.end());
		
		std::printf("Found Hyperion version: %s at 0x%p\n", version_str.c_str(), (void*)hypv_loc);
		return true;
	}

	bool code_decryptor::find_encryption_context()
	{
		utils::pe hyperion_image{ get_base_from_handle(hyperion_handle) };
		
		
		const auto byfron_section = hyperion_image.get_section(".byfron");
		if (!byfron_section.virtual_range.base) {
			std::printf("Failed to locate .byfron section for context scan\n");
			return false;
		}

		
		const std::array<std::array<std::uint8_t, 6>, 4> ctx_signatures = {{
			{ 0x48, 0x8D, 0x15, 0xCC, 0xCC, 0xCC },  
			{ 0x4C, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC },  
			{ 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC },  
			{ 0x4C, 0x8D, 0x05, 0xCC, 0xCC, 0xCC }   
		}};

		std::printf("Scanning .byfron section for encryption context...\n");
		std::printf("Section base: 0x%p, size: 0x%llx\n", 
			(void*)byfron_section.virtual_range.base,
			static_cast<unsigned long long>(byfron_section.virtual_range.size));

		
		for (const auto& sig : ctx_signatures) {
			const auto ctx_ref = utils::signature_scan(
				byfron_section.virtual_range.base,
				byfron_section.virtual_range.size,
				sig
			);

			if (ctx_ref) {
				
				std::printf("Found potential context reference at 0x%p\n", (void*)ctx_ref);

				
				encryption_context = ctx_ref + *reinterpret_cast<std::int32_t*>(ctx_ref + 3) + 7;
				
				
				const std::array<std::uint32_t, 4> possible_offsets = { 0x50, 0x48, 0x40, 0x58 };
				
				for (auto offset : possible_offsets) {
					page_info_base = encryption_context + offset;
					
					
					bool valid = true;
					for (int i = 0; i < 5; i++) {  
						const auto test_addr = *reinterpret_cast<std::uintptr_t*>(page_info_base + i * 0x18);
						const auto test_size = *reinterpret_cast<std::uint32_t*>(page_info_base + i * 0x18 + 0x10);
						
						if (test_size > 32) {  
							valid = false;
							break;
						}
					}
					
					if (valid) {
						std::printf("Found valid page info array at offset +0x%x\n", offset);
						return true;
					}
				}
				
				std::printf("Found context but couldn't locate valid page info array\n");
			}
		}
		
		std::printf("Failed to find encryption context with any known signature\n");
		return false;
	}

	code_decryptor::~code_decryptor()
	{
		if (hyperion_handle)
			FreeLibrary(static_cast<HMODULE>(hyperion_handle));

		if (roblox_handle)
			FreeLibrary(static_cast<HMODULE>(roblox_handle));
	}

	bool code_decryptor::is_initialized() const
	{
		return page_info_base != 0;
	}

	void code_decryptor::decrypt()
	{
		utils::pe roblox_image{ get_base_from_handle(roblox_handle) };
		utils::pe hyperion_image{ get_base_from_handle(hyperion_handle) };

		const auto roblox_code = roblox_image.get_section(".text");
		const auto byfron_code = hyperion_image.get_section(".byfron");

		std::printf("Starting decryption process...\n");
		std::printf("Roblox code section: base=0x%p, size=0x%llx\n", 
			(void*)roblox_code.virtual_range.base, 
			static_cast<unsigned long long>(roblox_code.virtual_range.size));
		
		std::printf("Page info base: 0x%p\n", (void*)page_info_base);
		std::printf("Encryption context: 0x%p\n", (void*)encryption_context);

		
		std::printf("\nFirst page info entry dump:\n");
		for (int i = 0; i < 0x18; i += 8) {
			std::printf("Offset +0x%02x: 0x%016llx\n", 
				i, 
				*reinterpret_cast<std::uint64_t*>(page_info_base + i));
		}
		std::printf("\n");

		
		constexpr std::uint32_t KEY_OFFSET = 0x0;  
		constexpr std::uint32_t SIZE_OFFSET = 0x10; 
		constexpr std::uint32_t FLAGS_OFFSET = 0x14; 

		for (auto target_page = roblox_code.virtual_range.base; 
			 target_page < roblox_code.virtual_range.base + roblox_code.virtual_range.size; 
			 target_page += 0x1000)
		{
			const auto target_page_number = (target_page - roblox_image.get_image_base()) / 0x1000;
			const auto target_page_info_base = page_info_base + (target_page_number % 10000) * 0x18;

			
			const auto key_ptr = *reinterpret_cast<std::uintptr_t*>(target_page_info_base + KEY_OFFSET);
			const auto key_size = *reinterpret_cast<std::uint32_t*>(target_page_info_base + SIZE_OFFSET);
			const auto flags = *reinterpret_cast<std::uint32_t*>(target_page_info_base + FLAGS_OFFSET);

			std::printf("Page 0x%llx: key_ptr=0x%p, size=0x%x, flags=0x%x\n",
				static_cast<unsigned long long>(target_page_number),
				(void*)key_ptr,
				key_size,
				flags);

			
			if (key_size == 0 || key_size > 32 || key_ptr == 0) {
				if (flags != 0) {  
					std::printf("Skipping page - flags=0x%x\n", flags);
				}
				continue;
			}

			try {
				std::array<std::uint8_t, 32> key{};
				
				
				if (!IsBadReadPtr(reinterpret_cast<const void*>(key_ptr), key_size)) {
					std::memcpy(key.data(), reinterpret_cast<void*>(key_ptr), key_size);
					
					std::printf("Key found for page 0x%llx: ", static_cast<unsigned long long>(target_page_number));
					for (std::uint32_t i = 0; i < key_size; i++) {
						std::printf("%02x", key[i]);
					}
					std::printf("\n");

					chacha20_context ctx;
					chacha20_init_context(&ctx, key.data(), 0);
					chacha20_xor(&ctx, reinterpret_cast<uint8_t*>(target_page), 0x1000);
				} else {
					std::printf("Invalid key pointer for page 0x%llx\n", 
						static_cast<unsigned long long>(target_page_number));
				}
			} catch (...) {
				std::printf("Exception while processing page 0x%llx\n", 
					static_cast<unsigned long long>(target_page_number));
			}
		}

		std::printf("Writing decrypted data...\n");
		
		std::printf("Creating IDA-friendly PE dump...\n");
		
		const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(roblox_image.get_image_base());
		const auto nt_headers = roblox_image.get_nt_headers();
		
		out_file.seekp(0);
		out_file.write(reinterpret_cast<const char*>(dos_header), sizeof(IMAGE_DOS_HEADER));
		out_file.seekp(dos_header->e_lfanew);
		out_file.write(reinterpret_cast<const char*>(nt_headers), 
			sizeof(IMAGE_NT_HEADERS) + (nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));

		out_file.seekp(roblox_code.raw_range.base);
		out_file.write(reinterpret_cast<char*>(roblox_code.virtual_range.base), roblox_code.virtual_range.size);
		
		const auto sections_to_copy = { ".rdata", ".data", ".rsrc" };
		for (const auto& section_name : sections_to_copy) {
			const auto section = roblox_image.get_section(section_name);
			if (section.virtual_range.base && section.raw_range.base) {
				std::printf("Copying section %s...\n", section_name);
				out_file.seekp(section.raw_range.base);
				out_file.write(reinterpret_cast<char*>(section.virtual_range.base), section.virtual_range.size);
			}
		}

		out_file.flush();
		std::printf("Decryption complete - saved as full PE dump\n");
		std::printf("\nTo load in IDA Pro:\n");
		std::printf("1. File -> New\n");
		std::printf("2. Select the output file\n");
		std::printf("3. Choose 'PE Executable' as file type\n");
		std::printf("4. Use default options for best results\n");
	}

	std::uintptr_t code_decryptor::get_base_from_handle(void* handle) const
	{
		return reinterpret_cast<std::uintptr_t>(handle);
	}
}