#include "ocra.hpp"

#include <sstream>
#include <stdexcept>

#include <boost/multiprecision/cpp_int.hpp>


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

    if (isCounter)
        result += "C-";

    result += 'Q';
    result += challenge.format;
    result += ('0' + challenge.length / 10);
    result += ('0' + challenge.length % 10);

    if (passwordSha == OcraSha::SHA1)
        result += "-PSHA1";
    else if (passwordSha == OcraSha::SHA256)
        result += "-PSHA256";
    else if (passwordSha == OcraSha::SHA512)
        result += "-PSHA512";

    if (sessionLength > 0)
    {
        result += "-S";

        const auto digits = sessionLength % 10;
        const auto tens = (sessionLength % 100) / 10;
        const auto hundreds = sessionLength / 100;

        result += ('0' + hundreds);
        result += ('0' + tens);
        result += ('0' + digits);
    }

    if (timestamp.step != 0)
    {
        result += "-T";
        if (timestamp.time > 9)
            result += ('0' + timestamp.time / 10);
        result += ('0' + timestamp.time % 10);
        result += timestamp.step;
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

std::vector<uint8_t> Ocra::operator()(const uint8_t* key, const OcraParameters& parameters) const
{
    constexpr auto QUESTION_LENGTH = 128u;
    const auto PASSWORD_LENGTH =
        m_suite.passwordSha == OcraSha::None ? 0u :
        (m_suite.passwordSha == OcraSha::SHA1 ? 20u :
        (m_suite.passwordSha == OcraSha::SHA256 ? 32u : 64u));
    constexpr auto EMPTY_BYTE = 1u;

    std::vector<uint8_t> message(
        m_suiteStr.length() +
        (m_suite.isCounter ? 8 : 0) +
        QUESTION_LENGTH +
        PASSWORD_LENGTH +
        m_suite.sessionLength +
        (m_suite.timestamp.step ? 8 : 0) +
        EMPTY_BYTE);

    auto pos = ConcatenateOcraSuite(message.data());
    pos = ConcatenateCounter(message.data(), pos, parameters);
    pos = ConcatenateQuestion(message.data(), pos, parameters);
    pos = ConcatenatePassword(message.data(), pos, parameters);
    pos = ConcatenateSessionInfo(message.data(), pos, parameters);
    ConcatenateTimestamp(message.data(), pos, parameters);

    return {};
}

std::size_t Ocra::ConcatenateOcraSuite(uint8_t* message) const
{
    constexpr auto EMPTY_BYTE = 1u;
    memcpy(message, (uint8_t*)m_suiteStr.c_str(), m_suiteStr.length());
    return m_suiteStr.length() + EMPTY_BYTE;
}

std::size_t Ocra::ConcatenateCounter(uint8_t* message,
                                     std::size_t pos,
                                     const OcraParameters& parameters) const
{
    if (!m_suite.isCounter)
        return pos;
        
    if (!parameters.counter)
        throw std::invalid_argument("OCRA operator() failed, suite contains a counter, but no counter value in parameters");

    message[pos++] = (*parameters.counter >> 56) & 0xFF;
    message[pos++] = (*parameters.counter >> 48) & 0xFF;
    message[pos++] = (*parameters.counter >> 40) & 0xFF;
    message[pos++] = (*parameters.counter >> 32) & 0xFF;
    message[pos++] = (*parameters.counter >> 24) & 0xFF;
    message[pos++] = (*parameters.counter >> 16) & 0xFF;
    message[pos++] = (*parameters.counter >> 8) & 0xFF;
    message[pos++] = *parameters.counter & 0xFF;

    return pos + 8;
}

std::size_t Ocra::ConcatenateQuestion(uint8_t* message,
                                      std::size_t pos,
                                      const OcraParameters& parameters) const
{
    using namespace boost::multiprecision;

    constexpr auto QUESTION_LENGTH = 128u;

    if (!parameters.question)
        throw std::invalid_argument("OCRA operator() failed, missing parameter 'question'");
    else if (parameters.question->length() > m_suite.challenge.length)
        throw std::invalid_argument("OCRA operator() failed, invalid 'question' length, is too long");

    if (m_suite.challenge.format == 'A')
    {
        memcpy(&message[pos], (uint8_t*)parameters.question->c_str(), parameters.question->length());
    }
    else if (m_suite.challenge.format == 'H')
    {
        StringHexToUint8(message, parameters.question->c_str(), parameters.question->length());
    }
    else if (m_suite.challenge.format == 'N')
    {
        for (const auto& c : *parameters.question)
        {
            if (c < '0' || '9' < c)
                throw std::invalid_argument("OCRA operator() failed, question is Numeric, and must contains only digits '0' to '9'");
        }

        auto ui256 = uint256_t{*parameters.question};
        auto sstream = std::stringstream{};
        sstream << std::hex << ui256;
        auto question = sstream.str();
        StringHexToUint8(message, question.c_str(), question.length());
    }

    return pos + QUESTION_LENGTH;
}

std::size_t Ocra::ConcatenatePassword(uint8_t* message,
                                      std::size_t pos,
                                      const OcraParameters& parameters) const
{
    if (m_suite.passwordSha == OcraSha::None)
        return pos;

    if (!parameters.shaHashFunction)
        throw std::invalid_argument("OCRA operator() failed, no SHA functor for hash SHA password");

    auto passwordHash = parameters.shaHashFunction((uint8_t*)(parameters.password->c_str()),
                                                   m_suite.passwordSha);
    if (passwordHash.empty())
        throw std::invalid_argument("OCRA operator() failed, password hashing failed");

    const auto PASSWORD_LENGTH =
        m_suite.passwordSha == OcraSha::SHA1 ? 20u :
        (m_suite.passwordSha == OcraSha::SHA256 ? 32u : 64u);
    if (passwordHash.size() != PASSWORD_LENGTH)
        throw std::invalid_argument("OCRA operator() failed, invalid hashed password length, password hashing may failed");

    constexpr auto isAlignRight = true;
    StringHexToUint8(message, passwordHash.c_str(), passwordHash.length(), isAlignRight);
    return pos + PASSWORD_LENGTH;
}

std::size_t Ocra::ConcatenateSessionInfo(uint8_t* message,
                                         std::size_t pos,
                                         const OcraParameters& parameters) const
{
    if (m_suite.sessionLength == 0)
        return pos;

    if (!parameters.sessionInfo)
        throw std::invalid_argument("OCRA operator() failed, no session info provided");

    constexpr auto isAlignRight = true;
    if (parameters.sessionInfo->length() >= m_suite.sessionLength)
    {
        StringHexToUint8(message, parameters.sessionInfo->c_str(),
                         m_suite.sessionLength, isAlignRight);
    }
    else
    {
        const auto offset = m_suite.sessionLength - parameters.sessionInfo->length();
        StringHexToUint8(message + offset, parameters.sessionInfo->c_str(),
                         m_suite.sessionLength, isAlignRight);
    }
    return pos + m_suite.sessionLength;
}

std::size_t Ocra::ConcatenateTimestamp(uint8_t* message,
                                       std::size_t pos,
                                       const OcraParameters& parameters) const
{
    if (!m_suite.timestamp.step)
        return pos;
        
    if (!parameters.timestamp)
        throw std::invalid_argument("OCRA operator() failed, suite contains a timestamp, but no timestamp value in parameters");

    message[pos++] = (*parameters.timestamp >> 56) & 0xFF;
    message[pos++] = (*parameters.timestamp >> 48) & 0xFF;
    message[pos++] = (*parameters.timestamp >> 40) & 0xFF;
    message[pos++] = (*parameters.timestamp >> 32) & 0xFF;
    message[pos++] = (*parameters.timestamp >> 24) & 0xFF;
    message[pos++] = (*parameters.timestamp >> 16) & 0xFF;
    message[pos++] = (*parameters.timestamp >> 8) & 0xFF;
    message[pos++] = *parameters.timestamp & 0xFF;

    return pos + 8;
}

void Ocra::StringHexToUint8(uint8_t* output,
                            const char* input,
                            std::size_t length,
                            bool isAlignRight) const
{
    auto relativePos = std::size_t{(length % 2) && isAlignRight};

    for (auto i = 0u; i < length; ++i)
    {
        const auto& c = input[i];

        if (relativePos % 2 == 1)
            output[relativePos] <<= 4;

        if ('0' <= c  && c <= '9')
            output[relativePos++] |= (c - '0');
        else if ('a' <= c  && c <= 'f')
            output[relativePos++] |= (10 + c - 'a');
        else if ('A' <= c  && c <= 'F')
            output[relativePos++] |= (10 + c - 'A');
        else
            throw std::invalid_argument("OCRA operator() failed, question is Hexadecimal, and must contains values [0-9][a-f][A-F]");
    }

    if (relativePos % 2 == 1)
        output[relativePos] <<= 4;
}

void Ocra::Validate()
{
    for (auto& c : m_suiteStr)
        c = toupper(c);

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

void Ocra::ValidateDataInputChallenge(std::string challenge)
{
    challenge.erase(0, 1);

    if (challenge.size() != 3)
        throw std::invalid_argument{"Unsupported data input format, for challenge data 'QFxx' wrong number of values, pattern is: Q[A|N|H][04-64]"};

    auto& format = m_suite.challenge.format;
    auto& length = m_suite.challenge.length;
    format = challenge.front();

    if (format != 'A' && format != 'N' && format != 'H')
        throw std::invalid_argument{"Unsupported data input format, for challenge data 'QFxx' unrecognized value of 'F', pattern is: Q[A|N|H][04-64]"};

    challenge.erase(0, 1);
    length = atoi(challenge.c_str());
    if (length < 4 || 64 < length)
        throw std::invalid_argument{"Unsupported data input format, for challenge data 'QFxx' value 'xx' is out of bound, pattern is: Q[A|N|H][04-64]"};
}

void Ocra::ValidateDataInputPassword(std::string password)
{
    password.erase(0, 1);
    if (password == "SHA1")
        m_suite.passwordSha = OcraSha::SHA1;
    else if (password == "SHA256")
        m_suite.passwordSha = OcraSha::SHA256;
    else if (password == "SHA512")
        m_suite.passwordSha = OcraSha::SHA512;
    else
        throw std::invalid_argument{"Unsupported data input format, invalid password descriptor 'PH', hash function must be SHA1, SHA256 or SHA512, pattern is: PSHA[1|256|512]"};
}

void Ocra::ValidateDataInputSession(std::string sessioninfo)
{
    sessioninfo.erase(0, 1);
    if (sessioninfo.size() != 3)
        throw std::invalid_argument{"Unsupported data input format, invalid session data 'Snnn', pattern is: S[001-512]"};

    m_suite.sessionLength = atoi(sessioninfo.c_str());
    if (m_suite.sessionLength < 1 || 512 < m_suite.sessionLength)
        throw std::invalid_argument{"Unsupported data input format, for session data 'Snnn' value 'nnn' is out of bound, pattern is: S[001-512]"};
}

void Ocra::ValidateDataInputTimestamp(std::string timestamp)
{
    timestamp.erase(0, 1);
    if (timestamp.size() < 2 || 3 < timestamp.size())
        throw std::invalid_argument{"Unsupported data input format, invalid timestamp data 'TG', pattern is: T[[1-59][S|M] | [0-48]H]"};

    auto& step = m_suite.timestamp.step;
    auto& time = m_suite.timestamp.time;

    step = timestamp.back();
    if (step != 'S' && step != 'M' && step != 'H')
        throw std::invalid_argument{"Unsupported data input format, invalid timestamp data 'TG', time-step must be S, M or H, pattern is: T[[1-59][S|M] | [0-48]H]"};

    timestamp.pop_back();
    time = atoi(timestamp.c_str());

    if (((step == 'S' || step == 'M') && (time < 1 || 59 < time)) || (time < 0 && 48 < time))
        throw std::invalid_argument{"Unsupported data input format, for timestamp data 'TG' value 'G' is out of bound, pattern is: T[[1-59][S|M] | [0-48]H]"};
}

bool Ocra::InsertCounterInputData(std::string value)
{
    constexpr auto COUNTER_PARAM_CHAR = 'C';

    if (value.empty())
    {
        throw std::invalid_argument{"Data input has missing first argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    }
    else if (value[0] == COUNTER_PARAM_CHAR)
    {
        m_suite.isCounter = true;
        return true;
    }
    return false;
}

bool Ocra::InsertChallengeInputData(std::string value)
{
    constexpr auto CHALLENGE_PARAM_CHAR = 'Q';

    if (value.empty())
    {
        throw std::invalid_argument{"Data input has empty challenge argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]"};
    }
    else if (value[0] == CHALLENGE_PARAM_CHAR)
    {
        ValidateDataInputChallenge(std::move(value));
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
    else if (value[0] == PASSWORD_PARAM_CHAR)
    {
        ValidateDataInputPassword(std::move(value));
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
    else if (value[0] == SESSION_PARAM_CHAR)
    {
        ValidateDataInputSession(std::move(value));
        return true;
    }
    return false;
}

bool Ocra::InsertTimestampInputData(std::string value)
{
    constexpr auto TIMESTAMP_PARAM_CHAR = 'T';

    if (value.empty())
    {
        return false;
    }
    else if (value[0] == TIMESTAMP_PARAM_CHAR)
    {
        ValidateDataInputTimestamp(std::move(value));
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
