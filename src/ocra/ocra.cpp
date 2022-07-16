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

void Ocra::From(std::string suite)
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
    auto [data, size] = split<3>(std::move(function), '-');
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
        throw std::invalid_argument{"Unsupported data input format, for challenge data 'QFxx' wrong number of values, pattern is: Q[A|N|H][04-64]"};

    auto result = std::pair<std::string, std::string>{};
    auto coding = toupper(challenge.front());
    if (coding == 'A' || coding == 'N' || coding == 'H')
        result.first = coding;
    else
        throw std::invalid_argument{"Unsupported data input format, for challenge data 'QFxx' unrecognized value of 'F', pattern is: Q[A|N|H][04-64]"};

    challenge.erase(0, 1);
    auto size = atoi(challenge.c_str());
    if (size < 4 || 64 < size)
        throw std::invalid_argument{"Unsupported data input format, for challenge data 'QFxx' value 'xx' is out of bound, pattern is: Q[A|N|H][04-64]"};

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
        throw std::invalid_argument{"Unsupported data input format, invalid session data 'Snnn', pattern is: S[001-512]"};

    auto size = atoi(sessioninfo.c_str());
    if (size < 1 || 512 < size)
        throw std::invalid_argument{"Unsupported data input format, for session data 'Snnn' value 'nnn' is out of bound, pattern is: S[001-512]"};

    return sessioninfo;
}

std::pair<std::string, std::string> Ocra::ValidateDataInputTimestamp(std::string timestamp)
{
    timestamp.erase(0, 1);
    if (timestamp.size() < 2 || 3 < timestamp.size())
        throw std::invalid_argument{"Unsupported data input format, invalid timestamp data 'TG', pattern is: T[[1-59][S|M] | [0-48]H]"};

    auto result = std::pair<std::string, std::string>{};
    auto step = toupper(timestamp.back());
    if (step == 'S' || step == 'M' || step == 'H')
        result.second = step;
    else
        throw std::invalid_argument{"Unsupported data input format, invalid timestamp data 'TG', time-step must be S, M or H, pattern is: T[[1-59][S|M] | [0-48]H]"};

    timestamp.pop_back();
    auto time = atoi(timestamp.c_str());
    if ((step == 'S' || step == 'M') && (1 <= time && time <= 59))
        result.first = std::move(timestamp);
    else if ((step == 'H') && (0 <= time && time <= 48))
        result.first = std::move(timestamp);
    else
        throw std::invalid_argument{"Unsupported data input format, for timestamp data 'TG' value 'G' is out of bound, pattern is: T[[1-59][S|M] | [0-48]H]"};
    return result;
}

bool Ocra::InsertCounterInputData(std::string value)
{
    constexpr auto COUNTER_PARAM_CHAR = 'C';

    if (value.empty())
    {
        throw std::invalid_argument{"Data input has missing first argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    }
    else if (toupper(value[0]) == COUNTER_PARAM_CHAR)
    {
        m_suite.dataInput.push_back({COUNTER_PARAM_CHAR, std::string{}});
        return true;
    }
    return false;
}

bool Ocra::InsertChallengeInputData(std::string value)
{
    constexpr auto CHALLENGE_PARAM_CHAR = 'Q';
    constexpr auto CHALLENGE_LENGTH_CHAR = 'q';

    if (value.empty())
    {
        throw std::invalid_argument{"Data input has empty challenge argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    }
    else if (toupper(value[0]) == CHALLENGE_PARAM_CHAR)
    {
        auto [format, length] = ValidateDataInputChallenge(std::move(value));
        m_suite.dataInput.push_back({CHALLENGE_PARAM_CHAR, std::move(format)});
        m_suite.dataInput.push_back({CHALLENGE_LENGTH_CHAR, std::move(length)});
        return true;
    }
    else
    {
        throw std::invalid_argument{"Data input has missing challenge data 'QFxx', data input pattern is: [C]-QFxx-[PH|Snnn|TG]"};
    }
}

bool Ocra::InsertPasswordInputData(std::string value)
{
    constexpr auto PASSWORD_PARAM_CHAR = 'P';

    if (value.empty())
    {
        return false;
    }
    else if (toupper(value[0]) == PASSWORD_PARAM_CHAR)
    {
        auto password = ValidateDataInputPassword(std::move(value));
        m_suite.dataInput.push_back({PASSWORD_PARAM_CHAR, std::move(password)});
        return true;
    }
    return false;
}

bool Ocra::InsertSessionInputData(std::string value)
{
    constexpr auto SESSION_PARAM_CHAR = 'S';

    if (value.empty())
    {
        return false;
    }
    else if (toupper(value[0]) == SESSION_PARAM_CHAR)
    {
        auto sessioninfo = ValidateDataInputSession(std::move(value));
        m_suite.dataInput.push_back({SESSION_PARAM_CHAR, std::move(sessioninfo)});
        return true;
    }
    return false;
}

bool Ocra::InsertTimestampInputData(std::string value)
{
    constexpr auto TIMESTAMP_PARAM_CHAR = 'T';
    constexpr auto TIMESTAMP_STEP_PARAM_CHAR = 't';

    if (value.empty())
    {
        return false;
    }
    else if (toupper(value[0]) == TIMESTAMP_PARAM_CHAR)
    {
        auto [timestamp, step] = ValidateDataInputTimestamp(std::move(value));
        m_suite.dataInput.push_back({TIMESTAMP_PARAM_CHAR, std::move(timestamp)});
        m_suite.dataInput.push_back({TIMESTAMP_STEP_PARAM_CHAR, std::move(step)});
        return true;
    }
    return false;
}

void Ocra::ValidateDataInput(std::string dataInput)
{
    auto input = 0u;
    auto [data, size] = split<5>(std::move(dataInput), '-');

    input += InsertCounterInputData(data[input]);
    input += InsertChallengeInputData(std::move(data[input]));
    input += InsertPasswordInputData(data[input]);
    input += InsertSessionInputData(data[input]);
    input += InsertTimestampInputData(data[input]);

    if (input != size)
        throw std::invalid_argument{"Unsupported data input format, unexpected parameters left, data input pattern is: [C]-QFxx-[PH]-[Snnn]-[TG]"};
}

}  // namespace ocra
