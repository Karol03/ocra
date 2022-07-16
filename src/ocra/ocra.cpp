#include "ocra.hpp"


namespace ocra
{

std::string OcraSuite::to_string() const
{
    auto result = std::string{};
    if (version == OcraVersion::OCRA_1)
        result += "OCRA-1";

    if (hotp == OcraHotp::HOTP_SHA1)
        result += ":HOTP-SHA1";
    else if (hotp == OcraHotp::HOTP_SHA256)
        result += ":HOTP-SHA256";
    else if (hotp == OcraHotp::HOTP_SHA512)
        result += ":HOTP-SHA512";

    switch (digits)
    {
        case OcraDigits::_0:
            result += "-0:";
            break;
        case OcraDigits::_4:
            result += "-4:";
            break;
        case OcraDigits::_5:
            result += "-5:";
            break;
        case OcraDigits::_6:
            result += "-6:";
            break;
        case OcraDigits::_7:
            result += "-7:";
            break;
        case OcraDigits::_8:
            result += "-8:";
            break;
        case OcraDigits::_9:
            result += "-9:";
            break;
        case OcraDigits::_10:
            result += "-10:";
            break;
        default: break;
    }

    auto it = dataInput.cbegin();
    if (it != dataInput.cend())
    {
        if (isupper(it->first))
            result += it->first + it->second;
        else
            result += it->second;
        ++it;
    }

    while (it != dataInput.cend())
    {
        if (isupper(it->first))
        {
            result += "-";
            result += it->first + it->second;
        }
        else
        {
            result += it->second;
        }
        ++it;
    }

    return result;
}


Ocra::Ocra(std::string suite)
    : m_suiteStr{std::move(suite)}
{
    Validate();
}

void Ocra::from(std::string suite)
{
    m_suiteStr = std::move(suite);
    Validate();
}

uint8_t* Ocra::operator()(std::function<uint8_t*(const uint8_t*)> sha,
                          std::function<uint8_t*(const uint8_t*)> hotp) const
{
    return {};
}

void Ocra::Validate()
{
    constexpr auto OCRA_SUITE_SIZE = 3u;
    auto [data, size] = split<3>(m_suiteStr, ':');
    if (size != OCRA_SUITE_SIZE)
        throw std::invalid_argument{"Invalid OCRA suite, pattern is: <Version>:<CryptoFunction>:<DataInput>, see RFC6287"};

    auto version = std::move(data[0]);
    auto function = std::move(data[1]);
    auto dataInput = std::move(data[2]);

    ValidateVersion(std::move(version));
    ValidateCryptoFunction(std::move(function));
    ValidateDataInput(std::move(dataInput));
}

void Ocra::ValidateVersion(std::string version)
{
    constexpr auto OCRA_V1 = "OCRA-1";
    if (version != OCRA_V1)
        throw std::invalid_argument{"Invalid OCRA version, supported version is 1"};

    m_suite.version = OcraVersion::OCRA_1;
}

void Ocra::ValidateCryptoFunction(std::string function)
{
    constexpr auto CRYPTO_FUNCTION_PARTS = 3u;
    auto [data, size] = split<4>(std::move(function), '-');
    auto algorithm = std::move(data[0]);
    auto hashFunc = std::move(data[1]);
    auto digits = std::move(data[2]);

    if (size != CRYPTO_FUNCTION_PARTS)
        throw std::invalid_argument{"Invalid OCRA CryptoFunction, pattern is HOTP-SHAx-t, x = {1, 256, 512}, t = {0, 4-10}"};
    
    if (algorithm != "HOTP")
        throw std::invalid_argument{"Invalid OCRA CryptoFunction, implementation supports only HOTP, pattern is HOTP-SHAx-t"};
    
    if (hashFunc == "SHA1")
        m_suite.hotp = OcraHotp::HOTP_SHA1;
    else if (hashFunc == "SHA256")
        m_suite.hotp = OcraHotp::HOTP_SHA256;
    else if (hashFunc == "SHA512")
        m_suite.hotp = OcraHotp::HOTP_SHA512;
    else
        throw std::invalid_argument{"Invalid OCRA CryptoFunction, implementation supports SHA1, SHA256 or SHA512, pattern is HOTP-SHAx-t"};

    if (digits == "0")
        m_suite.digits = OcraDigits::_0;
    else if (digits == "4")
        m_suite.digits = OcraDigits::_4;
    else if (digits == "5")
        m_suite.digits = OcraDigits::_5;
    else if (digits == "6")
        m_suite.digits = OcraDigits::_6;
    else if (digits == "7")
        m_suite.digits = OcraDigits::_7;
    else if (digits == "8")
        m_suite.digits = OcraDigits::_8;
    else if (digits == "9")
        m_suite.digits = OcraDigits::_9;
    else if (digits == "10")
        m_suite.digits = OcraDigits::_10;
    else
        throw std::invalid_argument{"Invalid OCRA CryptoFunction, t cannot be empty supports digits t = {0, 4-10}, pattern is HOTP-SHAx-t"};
}

std::pair<std::string, std::string> Ocra::ValidateDataInputChallenge(std::string challenge)
{
    challenge.erase(0, 1);

    if (challenge.size() != 3)
        throw std::invalid_argument{"Unsupported data input format, for challenge descriptor 'QFxx' unrecognized value of 'F', pattern is: Q[A|N|H][04-64]"};

    auto result = std::pair<std::string, std::string>{};
    auto coding = toupper(challenge.front());
    if (coding == 'A' || coding == 'N' || coding == 'H')
        result.first = coding;
    else
        throw std::invalid_argument{"Unsupported data input format, for challenge descriptor 'QFxx' unrecognized value 'F', pattern is: Q[A|N|H][04-64]"};

    challenge.erase(0, 1);
    auto size = atoi(challenge.c_str());
    if (size < 4 || 64 < size)
        throw std::invalid_argument{"Unsupported data input format, for challenge descriptor 'QFxx' value 'xx' is out of bound, pattern is: Q[A|N|H][04-64]"};

    result.second = std::move(challenge);
    return result;
}

std::string Ocra::ValidateDataInputPassword(std::string password)
{
    password.erase(0, 1);
    if (password == "SHA1" || password == "SHA256" || password == "SHA512")
        return password;
    else
        throw std::invalid_argument{"Unsupported data input format, invalid password descriptor 'PH', hash function must be SHA1, SHA256 or SHA512, pattern is: PSHA[1|256|512]"};
}

std::string Ocra::ValidateDataInputSession(std::string sessioninfo)
{
    sessioninfo.erase(0, 1);
    if (sessioninfo.size() != 3)
        throw std::invalid_argument{"Unsupported data input format, invalid session descriptor 'Snnn', pattern is: S[001-512]"};

    auto size = atoi(sessioninfo.c_str());
    if (size < 1 || 512 < size)
        throw std::invalid_argument{"Unsupported data input format, for session descriptor 'Snnn' value 'nnn' is out of bound, pattern is: S[001-512]"};

    return sessioninfo;
}

std::pair<std::string, std::string> Ocra::ValidateDataInputTimestamp(std::string timestamp)
{
    timestamp.erase(0, 1);
    if (timestamp.size() < 2 || 3 < timestamp.size())
        throw std::invalid_argument{"Unsupported data input format, invalid timestamp descriptor 'TG', pattern is: T[[1-59][S|M] | [0-48]H]"};

    auto result = std::pair<std::string, std::string>{};
    auto interval = toupper(timestamp.back());
    if (interval == 'S' || interval == 'M' || interval == 'H')
        result.second = interval;
    else
        throw std::invalid_argument{"Unsupported data input format, invalid timestamp descriptor 'TG', time-step must be S, M or H, pattern is: T[[1-59][S|M] | [0-48]H]"};

    timestamp.pop_back();
    auto time = atoi(timestamp.c_str());
    if ((interval == 'S' || interval == 'M') && (1 <= time && time <= 59))
        result.first = std::move(timestamp);
    else if ((interval == 'H') && (0 <= time && time <= 48))
        result.first = std::move(timestamp);
    else
        throw std::invalid_argument{"Unsupported data input format, for timestamp descriptor 'TG' value 'G' is out of bound, pattern is: T[[1-59][S|M] | [0-48]H]"};
    return result;
}

void Ocra::ValidateDataInput(std::string dataInput)
{
    if (dataInput.empty())
        throw std::invalid_argument("Unsupported empty data input, data input pattern is: [C]-QFxx-[PH|Snnn|TG], see RFC6287");

    constexpr auto NO_INPUT_DATA = 0u;
    constexpr char PARAMS[] = {'C', 'Q', 'P', 'S', 'T'};
    auto input = 0u;

    auto [data, size] = split<5>(std::move(dataInput), '-');
    if (size == NO_INPUT_DATA)
        throw std::invalid_argument("Unsupported data input, data input pattern is: [C]-QFxx-[PH|Snnn|TG], see RFC6287");

    if (data.empty())
        throw std::invalid_argument{"Data input has missing argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    else if (toupper(data[input][0]) == PARAMS[0])
    {
        m_suite.dataInput.push_back({'C', std::string{}});
        ++input;
    }

    if (data.empty())
        throw std::invalid_argument{"Data input has missing argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    else if (input < size && toupper(data[input][0]) == PARAMS[1])
    {
        auto [coding, length] = ValidateDataInputChallenge(std::move(data[input]));
        m_suite.dataInput.push_back({'Q', std::move(coding)});
        m_suite.dataInput.push_back({'q', std::move(length)});
        ++input;
    }
    else
        throw std::invalid_argument{"Unsupported data input format, missing challenge descriptor 'QFxx', data input pattern is: [C]-QFxx-[PH|Snnn|TG], see RFC6287"};

    if (data.empty())
        throw std::invalid_argument{"Data input has missing argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    else if (input < size && toupper(data[input][0]) == PARAMS[2])
    {
        auto password = ValidateDataInputPassword(std::move(data[input]));
        m_suite.dataInput.push_back({'P', std::move(password)});
        ++input;
    }

    if (data.empty())
        throw std::invalid_argument{"Data input has missing argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    else if (input < size && toupper(data[input][0]) == PARAMS[3])
    {
        auto sessioninfo = ValidateDataInputSession(std::move(data[input]));
        m_suite.dataInput.push_back({'S', std::move(sessioninfo)});
        ++input;
    }

    if (data.empty())
        throw std::invalid_argument{"Data input has missing argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    else if (input < size && toupper(data[input][0]) == PARAMS[4])
    {
        auto [timestamp, interval] = ValidateDataInputTimestamp(std::move(data[input]));
        m_suite.dataInput.push_back({'T', std::move(timestamp)});
        m_suite.dataInput.push_back({'t', std::move(interval)});
        ++input;
    }

    if (input != size)
        throw std::invalid_argument{"Unsupported data input format, parameters left, data input pattern is: [C]-QFxx-[PH]-[Snnn]-[TG], see RFC6287"};
}

}  // namespace ocra
