#include <gtest/gtest.h>

#include "ocra/ocra.hpp"
#include "exception.hpp"


TEST(OcraCryptoFunctionParseTest, ShouldThrowExceptionOnMissingCryptoFunctionParams)
{
    auto ocraSuite = std::string{"OCRA-1:-:a"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
        std::invalid_argument,
        "Invalid OCRA CryptoFunction, pattern is HOTP-SHAx-t, x = {1, 256, 512}, t = {0, 4-10}");
}

TEST(OcraCryptoFunctionParseTest, ShouldThrowExceptionOnAdditionalCryptoFunction)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA1-0-0:a"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
        std::invalid_argument,
        "Invalid OCRA CryptoFunction, pattern is HOTP-SHAx-t, x = {1, 256, 512}, t = {0, 4-10}");
}

TEST(OcraCryptoFunctionParseTest, ShouldThrowExceptionOnInvalidCryptoFunction)
{
    auto ocraSuite = std::string{"OCRA-1:HTOP-SHA1-0:a"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
        std::invalid_argument,
        "Invalid OCRA CryptoFunction, implementation supports only HOTP, pattern is HOTP-SHAx-t");
}

TEST(OcraCryptoFunctionParseTest, ShouldThrowExceptionOnInvalidHashFunction)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA224-0:a"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
        std::invalid_argument,
        "Invalid OCRA CryptoFunction, implementation supports SHA1, SHA256 or SHA512, pattern is HOTP-SHAx-t");
}

TEST(OcraCryptoFunctionParseTest, ShouldThrowExceptionOnInvalidDigitNumber)
{
    auto ocraSuite = std::string{"OCRA-1:HOTP-SHA256-2:a"};
    ASSERT_THROW_MESSAGE(ocra::Ocra(std::move(ocraSuite)),
        std::invalid_argument,
        "Invalid OCRA CryptoFunction, t cannot be empty supports digits t = {0, 4-10}, pattern is HOTP-SHAx-t");
}
