#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <Windows.h>

namespace decryptor::utils
{
	template<std::size_t N>
	std::uintptr_t signature_scan(std::uintptr_t address, std::uint32_t size, const std::array<std::uint8_t, N>& pattern)
	{
		const auto data = reinterpret_cast<const std::uint8_t*>(address);
		const auto pattern_size = pattern.size();

		// Ensure we can safely read the memory
		__try {
			for (std::uint32_t i = 0; i <= size - pattern_size; ++i) {
				bool found = true;
				for (std::size_t j = 0; j < pattern_size; ++j) {
					if (pattern[j] != 0xCC && data[i + j] != pattern[j]) {
						found = false;
						break;
					}
				}

				if (found) {
					return address + i;
				}
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {
			return 0;
		}

		return 0;
	}

	// Helper function to scan for string patterns
	inline std::uintptr_t string_scan(std::uintptr_t address, std::uint32_t size, const char* str, std::size_t str_len)
	{
		const auto data = reinterpret_cast<const char*>(address);

		__try {
			for (std::uint32_t i = 0; i <= size - str_len; ++i) {
				if (std::memcmp(data + i, str, str_len) == 0) {
					return address + i;
				}
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {
			return 0;
		}

		return 0;
	}

	inline std::uintptr_t page_align(std::uintptr_t addr)
	{
		return addr & ~(static_cast<std::uintptr_t>(0xFFF));
	}
}