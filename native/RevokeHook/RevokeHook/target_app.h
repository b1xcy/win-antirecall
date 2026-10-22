#pragma once

// 目标程序的运行时标识，属于互操作契约，必须与目标进程实际使用的名称一致。
// 为避免仓库和源码里重复出现产品名，统一以 Base64 保存并在运行时解码。

#include <cstddef>
#include <string>

namespace target_app
{
    namespace detail
    {
        inline int Base64Value(char character)
        {
            if (character >= 'A' && character <= 'Z')
                return character - 'A';
            if (character >= 'a' && character <= 'z')
                return character - 'a' + 26;
            if (character >= '0' && character <= '9')
                return character - '0' + 52;
            if (character == '+')
                return 62;
            if (character == '/')
                return 63;
            return -1;
        }

        inline std::string DecodeBytes(const char *encoded)
        {
            std::string decoded;
            int accumulator = 0;
            int bits = 0;
            for (const char *cursor = encoded; *cursor != '\0'; ++cursor)
            {
                const int value = Base64Value(*cursor);
                if (value < 0)
                    continue;
                accumulator = (accumulator << 6) | value;
                bits += 6;
                if (bits >= 8)
                {
                    bits -= 8;
                    decoded.push_back(static_cast<char>((accumulator >> bits) & 0xFF));
                    accumulator &= (1 << bits) - 1;
                }
            }
            return decoded;
        }

        // 载荷是 UTF-16LE 字节，解码后直接得到宽字符串。
        inline std::wstring DecodeWide(const char *encoded)
        {
            const std::string bytes = DecodeBytes(encoded);
            std::wstring decoded;
            decoded.reserve(bytes.size() / 2);
            for (std::size_t index = 0; index + 1 < bytes.size(); index += 2)
            {
                const auto low = static_cast<unsigned char>(bytes[index]);
                const auto high = static_cast<unsigned char>(bytes[index + 1]);
                decoded.push_back(static_cast<wchar_t>(low | (static_cast<wchar_t>(high) << 8)));
            }
            return decoded;
        }
    } // namespace detail

    // 目标主模块文件名。
    inline const std::wstring &ModuleName()
    {
        static const std::wstring value = detail::DecodeWide("VwBlAGkAeABpAG4ALgBkAGwAbAA=");
        return value;
    }

    // 目标主程序文件名。
    inline const std::wstring &ExecutableName()
    {
        static const std::wstring value = detail::DecodeWide("VwBlAGkAeABpAG4ALgBlAHgAZQA=");
        return value;
    }

    // 目标进程名（不含 .exe）。
    inline const std::wstring &ProcessName()
    {
        static const std::wstring value = detail::DecodeWide("VwBlAGkAeABpAG4A");
        return value;
    }

    // 主更新器文件名。
    inline const std::wstring &UpdaterExecutableName()
    {
        static const std::wstring value = detail::DecodeWide("VwBlAGkAeABpAG4AVQBwAGQAYQB0AGUALgBlAHgAZQA=");
        return value;
    }

    // 主更新器进程名（不含 .exe）。
    inline const std::wstring &UpdaterProcessName()
    {
        static const std::wstring value = detail::DecodeWide("VwBlAGkAeABpAG4AVQBwAGQAYQB0AGUA");
        return value;
    }

    // 旧版更新器进程名（不含 .exe）。
    inline const std::wstring &LegacyUpdaterProcessName()
    {
        static const std::wstring value = detail::DecodeWide("VwBlAEMAaABhAHQAVQBwAGQAYQB0AGUA");
        return value;
    }

    // 主更新器文件名（UTF-8）。
    inline const std::string &UpdaterExecutableNameNarrow()
    {
        static const std::string value = detail::DecodeBytes("V2VpeGluVXBkYXRlLmV4ZQ==");
        return value;
    }

    // 主更新器进程名（不含 .exe，UTF-8）。
    inline const std::string &UpdaterProcessNameNarrow()
    {
        static const std::string value = detail::DecodeBytes("V2VpeGluVXBkYXRl");
        return value;
    }

    // 旧版更新器进程名（不含 .exe，UTF-8）。
    inline const std::string &LegacyUpdaterProcessNameNarrow()
    {
        static const std::string value = detail::DecodeBytes("V2VDaGF0VXBkYXRl");
        return value;
    }

    // 旧版更新器文件名。
    inline const std::wstring &LegacyUpdaterExecutableName()
    {
        static const std::wstring value = detail::DecodeWide("VwBlAEMAaABhAHQAVQBwAGQAYQB0AGUALgBlAHgAZQA=");
        return value;
    }

    // 目标程序注册的自定义 URL 协议。
    inline const std::wstring &LaunchUri()
    {
        static const std::wstring value = detail::DecodeWide("dwBlAGkAeABpAG4AOgAvAC8A");
        return value;
    }

    // 更新窗口标题。
    inline const std::wstring &UpdateWindowTitle()
    {
        static const std::wstring value = detail::DecodeWide("rl/hT/RmsGU=");
        return value;
    }

    // 目标程序官方账号标识（UTF-8）。
    inline const std::string &SpecialAccountName()
    {
        static const std::string value = detail::DecodeBytes("d2VpeGlu");
        return value;
    }

    // 目标程序账号 ID 的固定前缀（UTF-8）。
    inline const std::string &AccountIdPrefix()
    {
        static const std::string value = detail::DecodeBytes("d3hpZF8=");
        return value;
    }
} // namespace target_app
