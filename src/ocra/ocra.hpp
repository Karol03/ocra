#pragma once

#include <array>
#include <inttypes.h>
#include <optional>
#include <cstring>
#include <utility>
#include <vector>


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


enum class OcraHmac
{
    HOTP_SHA1 = 1,
    HOTP_SHA256 = 256,
    HOTP_SHA512 = 512
};


enum class OcraDigits
{
    _0 = 0,
    _4 = 4,
    _5 = 5,
    _6 = 6,
    _7 = 7,
    _8 = 8,
    _9 = 9,
    _10 = 10
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
    OcraHmac hmac;
    OcraDigits digits;
    bool isCounter{};
    Challenge challenge{};
    Timestamp timestamp{};
    OcraSha passwordSha{OcraSha::None};
    uint16_t sessionLength{};
};


struct OcraParameters
{
public:
    std::vector<uint8_t> key;
    std::optional<uint64_t> counter;
    std::optional<uint64_t> timestamp;
    std::optional<std::string> password;
    std::optional<std::string> question;
    std::optional<std::string> sessionInfo;
};


class Ocra
{
public:
    explicit Ocra() = default;
    explicit Ocra(std::string suite);

    inline const OcraSuite& Suite() const { return m_suite; }
    Ocra& From(std::string suite);
    #ifdef OCRA_NO_THROW
    int Status() const { return m_status; }
    #endif

    std::string operator()(const OcraParameters& parameters);

private:
    bool InsertChallengeInputData(std::string value);
    bool InsertCounterInputData(std::string value);
    bool InsertPasswordInputData(std::string value);
    bool InsertSessionInputData(std::string value);
    bool InsertTimestampInputData(std::string value);

    std::size_t ConcatenateOcraSuite(uint8_t* message);
    std::size_t ConcatenateCounter(uint8_t* message, const OcraParameters& parameters);
    std::size_t ConcatenateQuestion(uint8_t* message, const OcraParameters& parameters);
    std::size_t ConcatenatePassword(uint8_t* message, const OcraParameters& parameters);
    std::size_t ConcatenateSessionInfo(uint8_t* message, const OcraParameters& parameters);
    std::size_t ConcatenateTimestamp(uint8_t* message, const OcraParameters& parameters);

    void StringHexToUint8(uint8_t* output, const char* input,
                          std::size_t length, bool isAlignRight = false);

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
    #ifdef OCRA_NO_THROW
    int m_status = {};
    #endif
};


namespace user_implemented
{
std::vector<uint8_t> ShaHashing(const std::vector<uint8_t>& data,
                                OcraSha shaType);

std::vector<uint8_t> HMACAlgorithm(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& key,
                                   OcraHmac hmacType);
}  // namespace user_implemented
}  // namespace ocra
