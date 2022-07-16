#include <vector>
#include <string>
#include <sstream>

#include <gtest/gtest.h>

#include "ocra/ocra.hpp"
#include "exception.hpp"


std::vector<std::string> supportedVersions{"OCRA-1"};
std::vector<std::string> supportedCryptoFunction{"HOTP-SHA1", "hotp-sha256", "HOTP-SHA512"};
std::vector<std::string> supportedTruncation{"0", "4", "6", "8", "10"};
std::vector<std::string> supportedFirstDataInput{"C-", "", "c-"};
std::vector<std::string> supportedSecondDataInputPart1{"Q"};
std::vector<std::string> supportedSecondDataInputPart2{"A", "N", "H", "a"};
std::vector<std::string> supportedSecondDataInputPart3{"04", "64"};
std::vector<std::string> supportedThirdDataInput{
    "", "-PSHA1", "-psha256", "-PshA512"};
std::vector<std::string> supportedFourthDataInput{
    "", "-S001", "-s064", "-S512"};
std::vector<std::string> supportedFifthDataInput{
    "" "", "-T1S", "-t59m", "-T0h", "-T48H"};


class OcraValidSuiteParseTest :
    public ::testing::TestWithParam<std::tuple<
        std::string, std::string, std::string, std::string,
        std::string, std::string, std::string, std::string,
        std::string, std::string>>
{};


INSTANTIATE_TEST_CASE_P(ValidOcraSuitCombinations,
                        OcraValidSuiteParseTest,
                        ::testing::Combine(::testing::ValuesIn(supportedVersions),
                                           ::testing::ValuesIn(supportedCryptoFunction),
                                           ::testing::ValuesIn(supportedTruncation),
                                           ::testing::ValuesIn(supportedFirstDataInput),
                                           ::testing::ValuesIn(supportedSecondDataInputPart1),
                                           ::testing::ValuesIn(supportedSecondDataInputPart2),
                                           ::testing::ValuesIn(supportedSecondDataInputPart3),
                                           ::testing::ValuesIn(supportedThirdDataInput),
                                           ::testing::ValuesIn(supportedFourthDataInput),
                                           ::testing::ValuesIn(supportedFifthDataInput)));

TEST_P(OcraValidSuiteParseTest, ShouldParseAndReturnTheSameSuite)
{
    auto version = std::get<0>(GetParam());
    auto cryptoFunction = std::get<1>(GetParam());
    auto truncation = std::get<2>(GetParam());
    auto firstDataInput = std::get<3>(GetParam());
    auto secondDataInputPart1 = std::get<4>(GetParam());
    auto secondDataInputPart2 = std::get<5>(GetParam());
    auto secondDataInputPart3 = std::get<6>(GetParam());
    auto thirdDataInput = std::get<7>(GetParam());
    auto fourthDataInput = std::get<8>(GetParam());
    auto fifthDataInput = std::get<9>(GetParam());

    auto ocraSuiteStream = std::stringstream{};
    ocraSuiteStream << version << ':' << cryptoFunction << '-' << truncation << ':'
                    << firstDataInput << secondDataInputPart1 << secondDataInputPart2
                    << secondDataInputPart3 << thirdDataInput << fourthDataInput
                    << fifthDataInput;

    auto ocraSuite = ocraSuiteStream.str();
    auto ocra = ocra::Ocra{ocraSuite};

    for (auto& c : ocraSuite)
        c = toupper(c);

    ASSERT_EQ(ocra.Suite().to_string(), ocraSuite);
}
