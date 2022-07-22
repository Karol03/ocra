#include <gtest/gtest.h>

#include "ocra/ocra.hpp"
#include "exception.hpp"


struct OcraTestParams
{
    std::string suite;
    ocra::OcraParameters parameters;
    std::string result;
};

class OcraTest : public ::testing::TestWithParam<OcraTestParams> { };

INSTANTIATE_TEST_CASE_P(TestSuite, OcraTest, ::testing::Values(
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08",
        ocra::OcraParameters{}}
    // OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1",}
    // OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08",}
    // OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08",}
    // OcraTestParams{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1",}
    // OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08",}
    // OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08-PSHA1",}
    // OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08",}
    // OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA10-T1M",}
    // OcraTestParams{"OCRA-1:HOTP-SHA512-8:QN08-T1M",}
));

TEST_P(OcraTest, ShouldGenerateProperValues)
{
    // std::string value = ocra::Ocra(GetParam().suite)(GetParam().parameters);
    // ASSERT_EQ(value, GetParam().result);
}