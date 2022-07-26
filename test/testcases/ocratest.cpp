#include <gtest/gtest.h>

#include "ocra/ocra.hpp"
#include "exception.hpp"
#include "hashfunctions.hpp"


struct OcraTestParams
{
    std::string suite;
    ocra::OcraParameters parameters;
    std::string result;
};

class Params
{
public:
    auto& AddKey(std::string value)
    {
        const int HexToInt[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                                0, 0, 0, 0, 0, 0, 0,
                                10, 11, 12, 13, 14, 15};
        uint8_t v = 0;
        for (auto i = 0u; i < value.size(); ++i)
        {
            const int c = toupper(value[i]) - '0';
            if (c < 0 || (10 < c && c < 17) || c > 22)
                return *this;
            v <<= 4;
            v |= HexToInt[c];

            if (i % 2)
            {
                m_params.key.push_back(v);
                v = 0;
            }
        }
        return *this;
    }
    auto& AddCounter(uint64_t value) { m_params.counter = std::move(value); return *this; }
    auto& AddTimestamp(uint64_t value) { m_params.timestamp = std::move(value); return *this; }
    auto& AddPassword(std::string password) { m_params.password = std::move(password); return *this; }
    auto& AddChallenge(std::string value) { m_params.question = std::move(value); return *this; }
    auto& AddSessionInfo(std::string value) { m_params.sessionInfo = std::move(value); return *this; }

    operator ocra::OcraParameters() { return std::move(m_params); }

private:
    ocra::OcraParameters m_params;
};


class OcraTest : public ::testing::TestWithParam<OcraTestParams>
{
public:
    void SetUp() override
    {
        mock::OcraHashFunction().SetAvailableHmacAlgorithm({
            ocra::OcraHmac::HOTP_SHA1,
            ocra::OcraHmac::HOTP_SHA256,
            ocra::OcraHmac::HOTP_SHA512});
        mock::OcraHashFunction().SetAvailableShaAlgorithm({
            ocra::OcraSha::SHA1});
    }

    void TearDown() override
    {
        mock::OcraHashFunction().SetAvailableHmacAlgorithm({});
        mock::OcraHashFunction().SetAvailableShaAlgorithm({});
    }
};


constexpr auto _20_BYTES_KEY_CST = "3132333435363738393031323334353637383930";
constexpr auto _32_BYTES_KEY_CST = "31323334353637383930313233343536373839"
                                   "30313233343536373839303132";
constexpr auto _64_BYTES_KEY_CST = "31323334353637383930313233343536373839"
                                   "3031323334353637383930313233343536373839"
                                   "3031323334353637383930313233343536373839"
                                   "3031323334";

const auto _20_BYTES_KEY = [](auto challenge) { return  Params().AddKey(_20_BYTES_KEY_CST).AddChallenge(challenge); };
const auto _32_BYTES_KEY = [](auto challenge) { return Params().AddKey(_32_BYTES_KEY_CST).AddChallenge(challenge); };
const auto _32_BYTES_KEY_PASS = [](auto challenge) { return Params().AddKey(_32_BYTES_KEY_CST).AddChallenge(challenge).AddPassword("1234"); };
const auto _32_BYTES_KEY_CTR_PASS = [](auto counter, auto challenge) { return Params().AddKey(_32_BYTES_KEY_CST).AddChallenge(challenge).AddPassword("1234").AddCounter(counter); };
const auto _64_BYTES_KEY = [](auto challenge) { return Params().AddKey(_64_BYTES_KEY_CST).AddChallenge(challenge); };
const auto _64_BYTES_KEY_PASS = [](auto challenge) { return Params().AddKey(_64_BYTES_KEY_CST).AddChallenge(challenge).AddPassword("1234"); };
const auto _64_BYTES_KEY_CTR = [](auto counter, auto challenge) { return Params().AddKey(_64_BYTES_KEY_CST).AddChallenge(challenge).AddCounter(counter); };
const auto _64_BYTES_KEY_TSTP = [](auto challenge, auto timestamp) { return Params().AddKey(_64_BYTES_KEY_CST).AddChallenge(challenge).AddTimestamp(timestamp); };

INSTANTIATE_TEST_CASE_P(TestSuite, OcraTest, ::testing::Values(
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("00000000"), "237653"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("11111111"), "243178"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("22222222"), "653583"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("33333333"), "740991"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("44444444"), "608993"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("55555555"), "388898"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("66666666"), "816933"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("77777777"), "224598"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("88888888"), "750600"},
    OcraTestParams{"OCRA-1:HOTP-SHA1-6:QN08", _20_BYTES_KEY("99999999"), "294470"},

    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(0, "12345678"), "65347737"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(1, "12345678"), "86775851"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(2, "12345678"), "78192410"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(3, "12345678"), "71565254"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(4, "12345678"), "10104329"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(5, "12345678"), "65983500"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(6, "12345678"), "70069104"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(7, "12345678"), "91771096"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(8, "12345678"), "75011558"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", _32_BYTES_KEY_CTR_PASS(9, "12345678"), "08522129"},

    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", _32_BYTES_KEY_PASS("00000000"), "83238735"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", _32_BYTES_KEY_PASS("11111111"), "01501458"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", _32_BYTES_KEY_PASS("22222222"), "17957585"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", _32_BYTES_KEY_PASS("33333333"), "86776967"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", _32_BYTES_KEY_PASS("44444444"), "86807031"},

    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(0, "00000000"), "07016083"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(1, "11111111"), "63947962"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(2, "22222222"), "70123924"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(3, "33333333"), "25341727"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(4, "44444444"), "33203315"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(5, "55555555"), "34205738"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(6, "66666666"), "44343969"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(7, "77777777"), "51946085"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(8, "88888888"), "20403879"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:C-QN08", _64_BYTES_KEY_CTR(9, "99999999"), "31409299"},

    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QN08-T1M", _64_BYTES_KEY_TSTP("00000000", 0x132d0b6), "95209754"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QN08-T1M", _64_BYTES_KEY_TSTP("11111111", 0x132d0b6), "55907591"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QN08-T1M", _64_BYTES_KEY_TSTP("22222222", 0x132d0b6), "22048402"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QN08-T1M", _64_BYTES_KEY_TSTP("33333333", 0x132d0b6), "24218844"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QN08-T1M", _64_BYTES_KEY_TSTP("44444444", 0x132d0b6), "36209546"},

    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("CLI22220SRV11110"), "28247970"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("CLI22221SRV11111"), "01984843"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("CLI22222SRV11112"), "65387857"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("CLI22223SRV11113"), "03351211"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("CLI22224SRV11114"), "83412541"},

    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SRV11110CLI22220"), "15510767"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SRV11111CLI22221"), "90175646"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SRV11112CLI22222"), "33777207"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SRV11113CLI22223"), "95285278"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SRV11114CLI22224"), "28934924"},

    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08", _64_BYTES_KEY("CLI22220SRV11110"), "79496648"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08", _64_BYTES_KEY("CLI22221SRV11111"), "76831980"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08", _64_BYTES_KEY("CLI22222SRV11112"), "12250499"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08", _64_BYTES_KEY("CLI22223SRV11113"), "90856481"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08", _64_BYTES_KEY("CLI22224SRV11114"), "12761449"},
    
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08-PSHA1", _64_BYTES_KEY_PASS("SRV11110CLI22220"), "18806276"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08-PSHA1", _64_BYTES_KEY_PASS("SRV11111CLI22221"), "70020315"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08-PSHA1", _64_BYTES_KEY_PASS("SRV11112CLI22222"), "01600026"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08-PSHA1", _64_BYTES_KEY_PASS("SRV11113CLI22223"), "18951020"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA08-PSHA1", _64_BYTES_KEY_PASS("SRV11114CLI22224"), "32528969"},

    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SIG10000"), "53095496"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SIG11000"), "04110475"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SIG12000"), "31331128"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SIG13000"), "76028668"},
    OcraTestParams{"OCRA-1:HOTP-SHA256-8:QA08", _32_BYTES_KEY("SIG14000"), "46554205"},

    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA10-T1M", _64_BYTES_KEY_TSTP("SIG1000000", 0x132d0b6), "77537423"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA10-T1M", _64_BYTES_KEY_TSTP("SIG1100000", 0x132d0b6), "31970405"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA10-T1M", _64_BYTES_KEY_TSTP("SIG1200000", 0x132d0b6), "10235557"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA10-T1M", _64_BYTES_KEY_TSTP("SIG1300000", 0x132d0b6), "95213541"},
    OcraTestParams{"OCRA-1:HOTP-SHA512-8:QA10-T1M", _64_BYTES_KEY_TSTP("SIG1400000", 0x132d0b6), "65360607"}
));

TEST_P(OcraTest, ShouldGenerateProperValues)
{
    std::string value = ocra::Ocra(GetParam().suite)(GetParam().parameters);
    ASSERT_EQ(value, GetParam().result);
}