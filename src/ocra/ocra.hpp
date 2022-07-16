#pragma once

#include <array>
#include <functional>
#include <inttypes.h>
#include <stdexcept>
#include <string>
#include <utility>


namespace ocra
{

enum class OcraVersion
{
    OCRA_1 = 1
};


enum class OcraSha
{
    None = 0,
    SHA1 = 1,
    SHA256 = 256,
    SHA512 = 512
};


enum class OcraHotp
{
    HOTP_SHA1 = 1,
    HOTP_SHA256 = 256,
    HOTP_SHA512 = 512
};


enum class OcraDigits : uint32_t
{
    _0 = 0,
    _4 = 10000,
    _5 = 100000,
    _6 = 1000000,
    _7 = 10000000,
    _8 = 100000000,
    _9 = 1000000000,
    _10 = UINT32_MAX
};


struct OcraSuite
{
public:
    struct Challenge
    {
        char format = {};
        uint8_t length = {};
    };
    
    struct Timestamp
    {
        char step = {};
        uint8_t time = {};
    };

public:
    std::string to_string() const;

public:
    OcraVersion version;
    OcraHotp hotp;
    OcraDigits digits;
    bool isCounter{};
    Challenge challenge{};
    Timestamp timestamp{};
    OcraSha passwordSha{OcraSha::None};
    uint16_t sessionLength{};
};


class Ocra
{
public:
    explicit Ocra() = default;
    explicit Ocra(std::string suite);

    inline const OcraSuite& Suite() const { return m_suite; }

    void From(std::string suite);

    uint8_t* operator()(
                    std::function<uint8_t*(const uint8_t*)> sha,
                        std::function<uint8_t*(const uint8_t*)> hotp) const;

private:
    bool InsertChallengeInputData(std::string value);
    bool InsertCounterInputData(std::string value);
    bool InsertPasswordInputData(std::string value);
    bool InsertSessionInputData(std::string value);
    bool InsertTimestampInputData(std::string value);

    void Validate();
    void ValidateCryptoFunction(std::string function);
    void ValidateDataInput(std::string dataInput);
    void ValidateDataInputChallenge(std::string challenge);
    void ValidateDataInputPassword(std::string password);
    void ValidateDataInputSession(std::string sessioninfo);
    void ValidateDataInputTimestamp(std::string timestamp);
    void ValidateVersion(std::string version);

    template <std::size_t N, typename T>
    std::pair<std::array<std::string, N>, std::size_t> split(T&& data, char delimiter) const
    {
        auto result = std::array<std::string, N>{};
        auto status = split<0>(result, data.c_str(), delimiter);
        return std::make_pair(result, status);
    }

    template <std::size_t M, std::size_t N>
    std::size_t split(std::array<std::string, N>& result, const char* data, char delimiter) const
    {
        if constexpr (M >= N)
            return M + 1;
        else if (data[0] == '\0')
            return M + 1;
        else
        {
            auto i = 0u;
            while (data[i] != delimiter && data[i] != '\0') ++i;
            result[M] = std::string(data, i);
            if (data[i] == '\0')
                return M + 1;
            i += (data[i] == delimiter);
            return split<M + 1>(result, data + i, delimiter);
        }
    }

private:
    OcraSuite m_suite;
    std::string m_suiteStr;
};

}  // namespace ocra
