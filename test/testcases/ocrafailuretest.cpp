#include <gtest/gtest.h>

#include "ocra/ocra.hpp"
#include "exception.hpp"


class OcraFailureTestFixture : public ::testing::Test
{
public:
    auto Get(std::string suite, ocra::OcraParameters params)
    {
        auto ocra = ocra::Ocra(std::move(suite));
        ocra(std::move(params));
        return ocra;
    }
};


TEST_F(OcraFailureTestFixture, ShouldFailGenerationWithEmptyKey)
{
    auto ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08";
    auto ocraParams = ocra::OcraParameters{};

    ASSERT_THROW_MESSAGE(Get(std::move(ocraSuite), std::move(ocraParams)),
                         "OCRA operator() failed, missing parameter 'key', required for HMAC");
    ASSERT_RETURN_STATUS(Get(std::move(ocraSuite), std::move(ocraParams)), 0x10);
}

TEST_F(OcraFailureTestFixture, ShouldFailOnConcatenateCounterIfMissing)
{
    auto ocraSuite = "OCRA-1:HOTP-SHA256-8:C-QA08";
    auto ocraParams = ocra::OcraParameters{};
    ocraParams.key = std::vector<uint8_t>{0x1, 0xff, 0x4};

    ASSERT_THROW_MESSAGE(Get(std::move(ocraSuite), std::move(ocraParams)),
                         "OCRA operator() failed, suite contains a counter, but no counter value in parameters");
    ASSERT_RETURN_STATUS(Get(std::move(ocraSuite), std::move(ocraParams)), 0x12);
}

TEST_F(OcraFailureTestFixture, ShouldFailOnConcatenateQuestionIfMissing)
{
    auto ocraSuite = "OCRA-1:HOTP-SHA256-8:C-QA08";
    auto ocraParams = ocra::OcraParameters{};
    ocraParams.key = std::vector<uint8_t>{0x1, 0xff, 0x4};
    ocraParams.counter = 0x0;

    ASSERT_THROW_MESSAGE(Get(std::move(ocraSuite), std::move(ocraParams)),
                         "OCRA operator() failed, missing parameter 'question'");
    ASSERT_RETURN_STATUS(Get(std::move(ocraSuite), std::move(ocraParams)), 0x13);
}

TEST_F(OcraFailureTestFixture, ShouldFailOnConcatenateQuestionIfInvalidCharInNumeric)
{
    auto ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08";
    auto ocraParams = ocra::OcraParameters{};
    ocraParams.key = std::vector<uint8_t>{0x1, 0xff, 0x4};
    ocraParams.question = "3215j";

    ASSERT_THROW_MESSAGE(Get(std::move(ocraSuite), std::move(ocraParams)),
                         "OCRA operator() failed, question is Numeric, and must contains only digits '0' to '9'");
    ASSERT_RETURN_STATUS(Get(std::move(ocraSuite), std::move(ocraParams)), 0x15);
}

TEST_F(OcraFailureTestFixture, ShouldFailOnConcatenatePasswordIfIsMissing)
{
    auto ocraSuite = "OCRA-1:HOTP-SHA256-8:C-QA08-PSHA1";
    auto ocraParams = ocra::OcraParameters{};
    ocraParams.key = std::vector<uint8_t>{0x1, 0xff, 0x4};
    ocraParams.counter = 0x0;
    ocraParams.question = "hello";

    ASSERT_THROW_MESSAGE(Get(std::move(ocraSuite), std::move(ocraParams)),
                         "OCRA operator() failed, missing 'password' value");
    ASSERT_RETURN_STATUS(Get(std::move(ocraSuite), std::move(ocraParams)), 0x16);
}

TEST_F(OcraFailureTestFixture, ShouldFailOnConcatenatePasswordIfUserDefinedShaReturnValeIsIncorrect)
{
    auto ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08-PSHA1";
    auto ocraParams = ocra::OcraParameters{};
    ocraParams.key = std::vector<uint8_t>{0x1, 0xff, 0x4};
    ocraParams.question = "hello";
    ocraParams.password = "PASSWORD";

    ASSERT_THROW_MESSAGE(Get(std::move(ocraSuite), std::move(ocraParams)),
                         "OCRA operator() failed, password hashing failed, check user defined ShaHashing function");
    ASSERT_RETURN_STATUS(Get(std::move(ocraSuite), std::move(ocraParams)), 0x17);
}

TEST_F(OcraFailureTestFixture, ShouldFailOnConcatenateSessionIfIsMissing)
{
    auto ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08-S064";
    auto ocraParams = ocra::OcraParameters{};
    ocraParams.key = std::vector<uint8_t>{0x1, 0xff, 0x4};
    ocraParams.question = "hello";

    ASSERT_THROW_MESSAGE(Get(std::move(ocraSuite), std::move(ocraParams)),
                         "OCRA operator() failed, no session info provided");
    ASSERT_RETURN_STATUS(Get(std::move(ocraSuite), std::move(ocraParams)), 0x18);
}

TEST_F(OcraFailureTestFixture, ShouldFailOnConcatenateTimestampIfIsMissing)
{
    auto ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08-T30S";
    auto ocraParams = ocra::OcraParameters{};
    ocraParams.key = std::vector<uint8_t>{0x1, 0xff, 0x4};
    ocraParams.question = "hello";

    ASSERT_THROW_MESSAGE(Get(std::move(ocraSuite), std::move(ocraParams)),
                         "OCRA operator() failed, suite contains a timestamp, but no timestamp value in parameters");
    ASSERT_RETURN_STATUS(Get(std::move(ocraSuite), std::move(ocraParams)), 0x19);
}
