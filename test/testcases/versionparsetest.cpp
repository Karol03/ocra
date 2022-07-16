#include <gtest/gtest.h>

#include "ocra/ocra.hpp"
#include "exception.hpp"


class OcraVersionParseTest : public ::testing::TestWithParam<std::string> { };

INSTANTIATE_TEST_CASE_P(TestSuite, OcraVersionParseTest, ::testing::Values(
    std::string{":a:a"},
    std::string{"OCR:a:a"},
    std::string{"ORCA:a:a"},
    std::string{"OCRA1:a:a"},
    std::string{"OCRA2:a:a"},
    std::string{"OCRA-2:a:a"},
    std::string{"OCRA-11:a:a"},
    std::string{"OCRA-:a:a"}
));

TEST_P(OcraVersionParseTest, ShouldThrowExceptionOnNotOCRA1Version)
{
    auto ocraSuite = GetParam();
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Invalid OCRA version, supported version is 1");
}

TEST(OcraParseTest, ShouldThrowExceptionOnEmptySuite)
{
    auto ocraSuite = std::string{""};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Invalid OCRA suite, pattern is: <Version>:<CryptoFunction>:<DataInput>, see RFC6287");
}

TEST(OcraParseTest, ShouldThrowExceptionOnInvalidSuite)
{
    auto ocraSuite = std::string{":::"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
                         std::invalid_argument,
                         "Invalid OCRA suite, pattern is: <Version>:<CryptoFunction>:<DataInput>, see RFC6287");
}
