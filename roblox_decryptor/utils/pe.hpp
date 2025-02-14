#pragma once

#include <cstdint>
#include <string>
#include <Windows.h>

namespace decryptor::utils
{
	struct range
	{
		std::uintptr_t base;
		std::uint32_t size;
	};

	struct section_info
	{
		range virtual_range;
		range raw_range;
	};

	class pe
	{
	public:
		pe(std::uintptr_t base);

		section_info get_section(const std::string& name) const;
		std::uintptr_t get_image_base() const;
		std::uint32_t get_image_size() const;
		IMAGE_NT_HEADERS* get_nt_headers() const;

	private:
		std::uintptr_t _base;
		IMAGE_NT_HEADERS* _nt_headers;
	};
}