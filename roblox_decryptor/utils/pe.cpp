#include "pe.hpp"

namespace decryptor::utils
{
	pe::pe(std::uintptr_t base) : _base(base)
	{
		auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
	}

	section_info pe::get_section(const std::string& name) const
	{
		IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(_nt_headers);
		const auto num_sections = _nt_headers->FileHeader.NumberOfSections;

		for (WORD i = 0; i < num_sections; i++) {
			if (std::strncmp(reinterpret_cast<const char*>(section[i].Name), name.c_str(), 8) == 0) {
				return {
					{ _base + section[i].VirtualAddress, section[i].Misc.VirtualSize },
					{ section[i].PointerToRawData, section[i].SizeOfRawData }
				};
			}
		}

		return { { 0, 0 }, { 0, 0 } };
	}

	std::uintptr_t pe::get_image_base() const
	{
		return _base;
	}

	std::uint32_t pe::get_image_size() const
	{
		return _nt_headers->OptionalHeader.SizeOfImage;
	}

	IMAGE_NT_HEADERS* pe::get_nt_headers() const
	{
		return _nt_headers;
	}
}