#include "ocra.hpp"


#ifdef OCRA_NO_THROW
#define THROW(code, message) \
    do { m_status = code; return; } while(0)
#define THROW_RETURN(code, message) \
    do { m_status = code; return {}; } while(0)
#define EXIT_WITH_STATUS() \
    do { if (m_status) return; } while(0)
#define EXIT_WITH_STATUS_RETURN() \
    do { if (m_status) return {}; } while(0)
#else
#include <stdexcept>

#define THROW(code, message) \
    throw std::invalid_argument(message)
#define THROW_RETURN(code, message) \
    throw std::invalid_argument(message)
#endif


namespace ocra
{

std::string uint256DecToHex(const std::string& decimal)
{
    std::string result;
    result.resize(65);

    char* resultPtr = result.data();
    char const* decimalPtr = decimal.data();

    char x[64] = {};
    int l = 0;
    while (*decimalPtr)
    {
        div_t d = { .quot = *decimalPtr++ - '0' };
        for (int i = 0; i < l; ++i)
        {
            d = div(x[i]*10 + d.quot, 16);
            x[i] = d.rem;
        }

        if (d.quot)
            x[l++] = d.quot;
    }
    
    while (l--)
        *resultPtr++ = x[l] + (10 <= x[l] ? 'A' - 10 : '0');
    *resultPtr = 0;
    return result;
}


std::string OcraSuite::to_string() const
{
    auto result = std::string{};
    if (version == OcraVersion::OCRA_1)
        result += "OCRA-1";

    if (hmac == OcraHmac::HOTP_SHA1)
        result += ":HOTP-SHA1";
    else if (hmac == OcraHmac::HOTP_SHA256)
        result += ":HOTP-SHA256";
    else if (hmac == OcraHmac::HOTP_SHA512)
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

Ocra& Ocra::From(std::string suite)
{
    m_suiteStr = std::move(suite);
    Validate();
    return *this;
}

std::string Ocra::operator()(const OcraParameters& parameters)
{
    if (parameters.key.empty())
        THROW_RETURN(0x10, "OCRA operator() failed, missing parameter 'key', required for HMAC");

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
    #ifdef OCRA_NO_THROW
    pos += ConcatenateCounter(message.data() + pos, parameters);     EXIT_WITH_STATUS_RETURN();
    pos += ConcatenateQuestion(message.data() + pos, parameters);    EXIT_WITH_STATUS_RETURN();
    pos += ConcatenatePassword(message.data() + pos, parameters);    EXIT_WITH_STATUS_RETURN();
    pos += ConcatenateSessionInfo(message.data() + pos, parameters); EXIT_WITH_STATUS_RETURN();
    ConcatenateTimestamp(message.data() + pos, parameters);         EXIT_WITH_STATUS_RETURN();
    #else
    pos += ConcatenateCounter(message.data() + pos, parameters);
    pos += ConcatenateQuestion(message.data() + pos, parameters);
    pos += ConcatenatePassword(message.data() + pos, parameters);
    pos += ConcatenateSessionInfo(message.data() + pos, parameters);
    ConcatenateTimestamp(message.data() + pos, parameters);
    #endif

    const auto hash = user_implemented::HMACAlgorithm(message, parameters.key, m_suite.hmac);
    if ((m_suite.hmac == OcraHmac::HOTP_SHA1 && hash.size() != 20u) ||
        (m_suite.hmac == OcraHmac::HOTP_SHA256 && hash.size() != 32u) ||
        (m_suite.hmac == OcraHmac::HOTP_SHA512 && hash.size() != 64u))
        THROW_RETURN(0x11, "OCRA operator() failed, invalid HMAC result size, please check user defined HMACAlgorithm function");

    const auto offset = hash[hash.size() - 1] & 0xf;
    const auto binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    constexpr int32_t DIGITS[] = {1,      0,       0,        0,
                                  10000,  100000,  1000000,  10000000,
                                  100000000, 1000000000, INT32_MAX};

    const auto digits = static_cast<int>(m_suite.digits);
    auto otp = binary % DIGITS[digits];
    auto result = std::string((digits ? digits : 10), '0');

    int i = digits - 1;
    for (; i >= 0 && otp; --i)
    {
        result[i] = '0' + (otp % 10);
        otp /= 10;
    }
    return digits ? result : result.substr(i);
}

std::size_t Ocra::ConcatenateOcraSuite(uint8_t* message)
{
    constexpr auto EMPTY_BYTE = 1u;
    memcpy(message, (uint8_t*)m_suiteStr.c_str(), m_suiteStr.length());
    return m_suiteStr.size() + EMPTY_BYTE;
}

std::size_t Ocra::ConcatenateCounter(uint8_t* message,
                                     const OcraParameters& parameters)
{
    constexpr auto NO_COUNTER_VALUE = 0u;
    constexpr auto COUNTER_VALUE_AVAILABLE = 8u;

    if (!m_suite.isCounter)
        return NO_COUNTER_VALUE;
        
    if (!parameters.counter)
        THROW_RETURN(0x12, "OCRA operator() failed, suite contains a counter, but no counter value in parameters");

    message[0] = (*parameters.counter >> 56) & 0xFF;
    message[1] = (*parameters.counter >> 48) & 0xFF;
    message[2] = (*parameters.counter >> 40) & 0xFF;
    message[3] = (*parameters.counter >> 32) & 0xFF;
    message[4] = (*parameters.counter >> 24) & 0xFF;
    message[5] = (*parameters.counter >> 16) & 0xFF;
    message[6] = (*parameters.counter >> 8) & 0xFF;
    message[7] = *parameters.counter & 0xFF;

    return COUNTER_VALUE_AVAILABLE;
}

std::size_t Ocra::ConcatenateQuestion(uint8_t* message,
                                      const OcraParameters& parameters)
{
    constexpr auto QUESTION_LENGTH = 128u;

    if (!parameters.question)
        THROW_RETURN(0x13, "OCRA operator() failed, missing parameter 'question'");

    if (m_suite.challenge.format == 'A')
    {
        memcpy(message, (uint8_t*)parameters.question->c_str(), parameters.question->length());
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
                THROW_RETURN(0x15, "OCRA operator() failed, question is Numeric, and must contains only digits '0' to '9'");
        }

        const auto questionHex = uint256DecToHex(*parameters.question);
        StringHexToUint8(message, questionHex.c_str(), questionHex.length());
    }

    return QUESTION_LENGTH;
}

std::size_t Ocra::ConcatenatePassword(uint8_t* message,
                                      const OcraParameters& parameters)
{
    constexpr auto NO_PASSWORD_VALUE = 0u;
    const auto PASSWORD_LENGTH =
        m_suite.passwordSha == OcraSha::SHA1 ? 20u :
        (m_suite.passwordSha == OcraSha::SHA256 ? 32u : 64u);

    if (m_suite.passwordSha == OcraSha::None)
        return NO_PASSWORD_VALUE;

    if (!parameters.password)
        THROW_RETURN(0x16, "OCRA operator() failed, missing 'password' value");

    const auto password = *parameters.password;
    auto passwordVec = std::vector<uint8_t>(password.size());
    memcpy((void*)passwordVec.data(), (void*)password.data(), password.size());

    auto passwordHash = user_implemented::ShaHashing(passwordVec, m_suite.passwordSha);
    if (passwordHash.size() != PASSWORD_LENGTH)
        THROW_RETURN(0x17, "OCRA operator() failed, password hashing failed, check user defined ShaHashing function");

    memcpy(message, passwordHash.data(), PASSWORD_LENGTH);
    return PASSWORD_LENGTH;
}

std::size_t Ocra::ConcatenateSessionInfo(uint8_t* message,
                                         const OcraParameters& parameters)
{
    constexpr auto NO_SESSION_VALUE = 0u;
    const auto SESSION_LENGTH = m_suite.sessionLength;

    if (SESSION_LENGTH == 0)
        return NO_SESSION_VALUE;

    if (!parameters.sessionInfo)
        THROW_RETURN(0x18, "OCRA operator() failed, no session info provided");

    constexpr auto isAlignRight = true;
    if (parameters.sessionInfo->length() >= SESSION_LENGTH)
    {
        StringHexToUint8(message, parameters.sessionInfo->c_str(),
                         SESSION_LENGTH, isAlignRight);
    }
    else
    {
        const auto offset = SESSION_LENGTH - parameters.sessionInfo->length();
        StringHexToUint8(message + offset, parameters.sessionInfo->c_str(),
                         SESSION_LENGTH, isAlignRight);
    }
    return SESSION_LENGTH;
}

std::size_t Ocra::ConcatenateTimestamp(uint8_t* message,
                                       const OcraParameters& parameters)
{
    constexpr auto NO_TIMESTAMP_VALUE = 0u;
    constexpr auto TIMESTAMP_AVAILABLE = 8u;

    if (!m_suite.timestamp.step)
        return NO_TIMESTAMP_VALUE;
        
    if (!parameters.timestamp)
        THROW_RETURN(0x19, "OCRA operator() failed, suite contains a timestamp, but no timestamp value in parameters");

    message[0] = (*parameters.timestamp >> 56) & 0xFF;
    message[1] = (*parameters.timestamp >> 48) & 0xFF;
    message[2] = (*parameters.timestamp >> 40) & 0xFF;
    message[3] = (*parameters.timestamp >> 32) & 0xFF;
    message[4] = (*parameters.timestamp >> 24) & 0xFF;
    message[5] = (*parameters.timestamp >> 16) & 0xFF;
    message[6] = (*parameters.timestamp >> 8) & 0xFF;
    message[7] = *parameters.timestamp & 0xFF;

    return TIMESTAMP_AVAILABLE;
}

void Ocra::StringHexToUint8(uint8_t* output,
                            const char* input,
                            std::size_t length,
                            bool isAlignRight)
{
    if (length > 2 && input[1] == 'x')
    {
        length -= 2;
        input += 2;
    }

    auto relativePos = std::size_t{(length % 2) && isAlignRight};

    for (auto i = 0u; i < length; ++i)
    {
        const auto& c = toupper(input[i]);

        if ('0' <= c  && c <= '9')
            output[relativePos] |= (c - '0');
        else if ('A' <= c  && c <= 'F')
            output[relativePos] |= (10 + c - 'A');
        else
            THROW(0x1A, "OCRA operator() failed, question is Hexadecimal, and must contains values [0-9][a-f][A-F]");

        if (i % 2)
            ++relativePos;
        else
            output[relativePos] <<= 4;
    }
}

void Ocra::Validate()
{
    for (auto& c : m_suiteStr)
        c = toupper(c);

    constexpr auto OCRA_SUITE_SIZE = 3u;
    auto [data, size] = split<3>(m_suiteStr, ':');
    if (size != OCRA_SUITE_SIZE)
        THROW(0x01, "Invalid OCRA suite, pattern is: <Version>:<CryptoFunction>:<DataInput>, see RFC6287");

    auto version = std::move(data[0]);
    auto function = std::move(data[1]);
    auto dataInput = std::move(data[2]);

    #ifdef OCRA_NO_THROW
    ValidateVersion(std::move(version));            EXIT_WITH_STATUS();
    ValidateCryptoFunction(std::move(function));    EXIT_WITH_STATUS();
    ValidateDataInput(std::move(dataInput));        EXIT_WITH_STATUS();
    #else
    ValidateVersion(std::move(version));
    ValidateCryptoFunction(std::move(function));
    ValidateDataInput(std::move(dataInput));
    #endif
}

void Ocra::ValidateVersion(std::string version)
{
    constexpr auto OCRA_V1 = "OCRA-1";
    if (version != OCRA_V1)
        THROW(0x02, "Invalid OCRA version, supported version is 1");

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
        THROW(0x03, "Invalid OCRA CryptoFunction, pattern is HOTP-SHAx-t, x = {1, 256, 512}, t = {0, 4-10}");
    
    if (algorithm != "HOTP")
        THROW(0x04, "Invalid OCRA CryptoFunction, implementation supports only HOTP, pattern is HOTP-SHAx-t");
    
    if (hashFunc == "SHA1")
        m_suite.hmac = OcraHmac::HOTP_SHA1;
    else if (hashFunc == "SHA256")
        m_suite.hmac = OcraHmac::HOTP_SHA256;
    else if (hashFunc == "SHA512")
        m_suite.hmac = OcraHmac::HOTP_SHA512;
    else
        THROW(0x05, "Invalid OCRA CryptoFunction, implementation supports SHA1, SHA256 or SHA512, pattern is HOTP-SHAx-t");

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
        THROW(0x06, "Invalid OCRA CryptoFunction, invalid 't' value, supported digits t = {0, 4-10}, pattern is HOTP-SHAx-t");
}

void Ocra::ValidateDataInputChallenge(std::string challenge)
{
    challenge.erase(0, 1);

    if (challenge.size() != 3)
        THROW(0x07, "Unsupported data input format, for challenge data 'QFxx' wrong number of values, pattern is: Q[A|N|H][04-64]");

    auto& format = m_suite.challenge.format;
    auto& length = m_suite.challenge.length;
    format = challenge.front();

    if (format != 'A' && format != 'N' && format != 'H')
        THROW(0x08, "Unsupported data input format, for challenge data 'QFxx' unrecognized value of 'F', pattern is: Q[A|N|H][04-64]");

    challenge.erase(0, 1);
    length = atoi(challenge.c_str());
    if (length < 4 || 64 < length)
        THROW(0x09, "Unsupported data input format, for challenge data 'QFxx' value 'xx' is out of bound, pattern is: Q[A|N|H][04-64]");
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
        THROW(0x0A, "Unsupported data input format, invalid password descriptor 'PH', hash function must be SHA1, SHA256 or SHA512, pattern is: PSHA[1|256|512]");
}

void Ocra::ValidateDataInputSession(std::string sessioninfo)
{
    sessioninfo.erase(0, 1);
    if (sessioninfo.size() != 3)
        THROW(0x0B, "Unsupported data input format, invalid session data 'Snnn', pattern is: S[001-512]");

    m_suite.sessionLength = atoi(sessioninfo.c_str());
    if (m_suite.sessionLength < 1 || 512 < m_suite.sessionLength)
        THROW(0x0C, "Unsupported data input format, for session data 'Snnn' value 'nnn' is out of bound, pattern is: S[001-512]");
}

void Ocra::ValidateDataInputTimestamp(std::string timestamp)
{
    timestamp.erase(0, 1);
    if (timestamp.size() < 2 || 3 < timestamp.size())
        THROW(0x0D, "Unsupported data input format, invalid timestamp data 'TG', pattern is: T[[1-59][S|M] | [0-48]H]");

    auto& step = m_suite.timestamp.step;
    auto& time = m_suite.timestamp.time;

    step = timestamp.back();
    if (step != 'S' && step != 'M' && step != 'H')
        THROW(0x0E, "Unsupported data input format, invalid timestamp data 'TG', time-step must be S, M or H, pattern is: T[[1-59][S|M] | [0-48]H]");

    timestamp.pop_back();
    time = atoi(timestamp.c_str());

    if (((step == 'S' || step == 'M') && (time < 1 || 59 < time)) || (time < 0 && 48 < time))
        THROW(0x0F, "Unsupported data input format, for timestamp data 'TG' value 'G' is out of bound, pattern is: T[[1-59][S|M] | [0-48]H]");
}

bool Ocra::InsertCounterInputData(std::string value)
{
    constexpr auto COUNTER_PARAM_CHAR = 'C';

    if (value.empty())
    {
        THROW_RETURN(0x1B, "Data input has missing first argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]");
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
        THROW_RETURN(0x1C, "Data input has empty challenge argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]");
    }
    else if (value[0] == CHALLENGE_PARAM_CHAR)
    {
        ValidateDataInputChallenge(std::move(value));
        return true;
    }
    else
    {
        THROW_RETURN(0x1D, "Data input has missing challenge data 'QFxx', data input pattern is: [C]-QFxx-[PH|Snnn|TG]");
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

    #ifdef OCRA_NO_THROW
    input += InsertCounterInputData(data[input]);               EXIT_WITH_STATUS();
    input += InsertChallengeInputData(std::move(data[input]));  EXIT_WITH_STATUS();
    input += InsertPasswordInputData(data[input]);              EXIT_WITH_STATUS();
    input += InsertSessionInputData(data[input]);               EXIT_WITH_STATUS();
    input += InsertTimestampInputData(data[input]);             EXIT_WITH_STATUS();
    #else
    input += InsertCounterInputData(data[input]);
    input += InsertChallengeInputData(std::move(data[input]));
    input += InsertPasswordInputData(data[input]);
    input += InsertSessionInputData(data[input]);
    input += InsertTimestampInputData(data[input]);
    #endif

    if (input != size)
        THROW(0x1E, "Unsupported data input format, unexpected parameters left, data input pattern is: [C]-QFxx-[PH]-[Snnn]-[TG]");
}

}  // namespace ocra
