#pragma once

#ifndef DRIVER_API_H
#define DRIVER_API_H

constexpr auto magic_of_packet = 0x911deadbeeac;

constexpr auto magic_req_success = 0x666;
constexpr auto magic_req_failure = 0x911;

inline uintptr_t(__stdcall* dummy_ptr)(__int64 a1);

inline uint32_t target_process_id;

enum class request_type_e : uint32_t {
    is_loaded,
    get_module_base,
    read_memory,
    write_memory,
};

struct base_request_t {
    uint32_t process_id;
    const char* name;
    uintptr_t buffer;
};

struct memory_request_t {
    uint32_t process_id;
    uintptr_t address;
    uintptr_t buffer;
    uint32_t size;
};

struct packet_t {
    uintptr_t magic;
    request_type_e type;
    union {
        base_request_t base;
        memory_request_t memory;
    } data;
};

inline void init_driver_deps() {
    SPOOF_FUNC;

    HMODULE user32 = SPOOF_CALL(LoadLibrary)(xs("user32.dll"));
    HMODULE win32u = SPOOF_CALL(LoadLibrary)(xs("win32u.dll"));

    *(PVOID*)&dummy_ptr = SPOOF_CALL(GetProcAddress)(win32u, xs("NtUserSetImeInfoEx"));
}

inline bool is_driver_loaded() {
    SPOOF_FUNC;

    packet_t packet;
    packet.magic = magic_of_packet;
    packet.type = request_type_e::is_loaded;

    auto ret = dummy_ptr((__int64)(&packet));
    if (ret != magic_req_success) {
        return false;
    }

    return true;
}

inline void set_driver_target_process(uint32_t _process_id) {
    SPOOF_FUNC;

    target_process_id = _process_id;
}

inline uintptr_t get_module_base(const char* module_name) {
    SPOOF_FUNC;

    packet_t packet;
    packet.magic = magic_of_packet;
    packet.type = request_type_e::get_module_base;
    packet.data.base.process_id = target_process_id;
    packet.data.base.name = module_name;

    dummy_ptr((__int64)(&packet));

    return packet.data.base.buffer;
}

inline bool read_ex(uintptr_t address, void* buffer, uint32_t size) {
    SPOOF_FUNC;

    packet_t packet;
    packet.magic = magic_of_packet;
    packet.type = request_type_e::read_memory;
    packet.data.memory.process_id = target_process_id;
    packet.data.memory.address = address;
    packet.data.memory.buffer = reinterpret_cast<uintptr_t>(buffer);
    packet.data.memory.size = size;

    dummy_ptr((__int64)(&packet));

    return true;
}

inline bool write_ex(uintptr_t address, void* buffer, uint32_t size) {
    SPOOF_FUNC;

    packet_t packet;
    packet.magic = magic_of_packet;
    packet.type = request_type_e::write_memory;
    packet.data.memory.process_id = target_process_id;
    packet.data.memory.address = address;
    packet.data.memory.buffer = reinterpret_cast<uintptr_t>(buffer);
    packet.data.memory.size = size;

    dummy_ptr((__int64)(&packet));

    return true;
}

template<typename T>
void write(uintptr_t address, T value) {
    SPOOF_FUNC;

    write_ex(address, (uintptr_t*)&value, sizeof(T));
}

template<typename T>
T read(uintptr_t address) {
    SPOOF_FUNC;

    T buffer{};
    read_ex(address, (uintptr_t*)&buffer, sizeof(buffer));
    return buffer;
}

inline std::string read_str(uintptr_t addr, uint32_t size) {
    SPOOF_FUNC;

    if (!addr || size > 1024)
        return "";

    char buf[1024] = "";
    read_ex(addr, buf, size);

    return std::string(buf);
}

inline std::wstring read_wstr(uintptr_t addr, uint32_t size) {
    SPOOF_FUNC;

    if (!addr || size > 1024)
        return L"";

    wchar_t buf[1024] = L"";
    read_ex(addr, buf, size);

    return std::wstring(buf);
}

template <class T>
std::vector<T> read_vec(uintptr_t address, int size) {
    SPOOF_FUNC;

    if (!size || size == 0) {
        return std::vector<T>{};
    }

    std::vector<T> temp{};
    temp.resize(sizeof(T) * size);
    if (read_ex(address, &temp[0], sizeof(T) * size)) {
        return temp;
    }

    return temp;
}

template <class T>
T read_chain(uintptr_t base, std::vector<uintptr_t> chain) {
    SPOOF_FUNC;

    uintptr_t current = base;
    for (int i = 0; i < chain.size() - 1; i++) {
        current = read<uintptr_t>(current + chain[i]);
    }

    return read<T>(current + chain[chain.size() - 1]);
}

inline uintptr_t pattern_scan(uintptr_t start, uintptr_t length, const unsigned char* pattern, const char* mask) {
    SPOOF_FUNC;

    size_t pos = 0;
    auto mask_length = strlen(mask) - 1;

    auto start_address = start;
    for (auto it = start_address; it < start_address + length; ++it) {
        if (read<unsigned char>((it)) == pattern[pos] || mask[pos] == '?') {
            if (mask[pos + 1] == '\0') {
                return it - mask_length;
            }
            pos++;
        }
        else pos = 0;
    }
    return 0;
}

inline uintptr_t pattern_scan(uintptr_t module_base, const unsigned char* pattern, const char* mask) {
    SPOOF_FUNC;

    auto dos_header = read<IMAGE_DOS_HEADER>(module_base);
    auto nt_headers = read<IMAGE_NT_HEADERS>(module_base + dos_header.e_lfanew);

    return pattern_scan(
        module_base + nt_headers.OptionalHeader.BaseOfCode,
        module_base + nt_headers.OptionalHeader.SizeOfCode, pattern, mask);
}

#endif // DRIVER_API_H