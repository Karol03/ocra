#include <gtest/gtest.h>

#include "ocra/ocra.hpp"
#include "exception.hpp"


TEST(OcraDataInputParseTest, ShouldThrowExceptionOnEmptyDataInput)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Data input has missing first argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnMissingFirstDataInput)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:-"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Data input has missing first argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnMissingChallengeDataInput)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:C--"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Data input has empty challenge argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnMissingChallengeData)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:C-PSHA256"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Data input has missing challenge data 'QFxx', data input pattern is: [C]-QFxx-[PH|Snnn|TG]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnInvalidChallengeDataLength)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA4"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, for challenge data 'QFxx' wrong number of values, pattern is: Q[A|N|H][04-64]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnInvalidChallengeFormat)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QI04"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, for challenge data 'QFxx' unrecognized value of 'F', pattern is: Q[A|N|H][04-64]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnInvalidChallengeLength)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA03"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, for challenge data 'QFxx' value 'xx' is out of bound, pattern is: Q[A|N|H][04-64]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnUnsupportedPasswordAlgorithm)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA04-PSHA224"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, invalid password descriptor 'PH', hash function must be SHA1, SHA256 or SHA512, pattern is: PSHA[1|256|512]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnInvalidSessionData)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA64-S64"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, invalid session data 'Snnn', pattern is: S[001-512]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnUnsupportedSessionSize)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA04-S513"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, for session data 'Snnn' value 'nnn' is out of bound, pattern is: S[001-512]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnInvalidTimestampValue)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA04-TG"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, invalid timestamp data 'TG', pattern is: T[[1-59][S|M] | [0-48]H]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnInvalidTimestampStep)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA04-T1G"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, invalid timestamp data 'TG', time-step must be S, M or H, pattern is: T[[1-59][S|M] | [0-48]H]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnTimestampValueOutOfBound)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA04-T60M"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, for timestamp data 'TG' value 'G' is out of bound, pattern is: T[[1-59][S|M] | [0-48]H]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnInvalidParametersOrder)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA04-T59S-S512"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, unexpected parameters left, data input pattern is: [C]-QFxx-[PH]-[Snnn]-[TG]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnUnexpectedParametersAdded)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA04-PSHA256-T48H-"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, unexpected parameters left, data input pattern is: [C]-QFxx-[PH]-[Snnn]-[TG]");
}

TEST(OcraDataInputParseTest, ShouldThrowExceptionOnDuplicateParameter)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-8:QA04-QA04"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Unsupported data input format, unexpected parameters left, data input pattern is: [C]-QFxx-[PH]-[Snnn]-[TG]");
}
