#include "hashfunctions.hpp"

#include <crypto++/hmac.h>
#include <crypto++/sha.h>


namespace ocra::user_implemented
{
std::vector<uint8_t> ShaHashing(const std::vector<uint8_t>& data,
                                ocra::OcraSha shaType)
{
    return mock::OcraHashFunction::Sha(data, shaType);
}

std::vector<uint8_t> HMACAlgorithm(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& key,
                                   ocra::OcraHmac hmacType)
{
    return mock::OcraHashFunction::Hmac(data, key.data(), key.size(), hmacType);
}
}  // ocra::user_implemented


namespace mock
{
std::vector<uint8_t> OcraHashFunction::Sha(const std::vector<uint8_t>& data,
                                           ocra::OcraSha shaType)
{
    if (!(static_cast<uint16_t>(shaType) & m_availableSha))
        return {};
    if (shaType == ocra::OcraSha::SHA1)
        return {0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x06, 0x2a, 0xa5, 0xe4, 0xa3,
                0x90, 0xb0, 0xa5, 0x72, 0xac, 0x0d, 0x2c, 0x02, 0x20};
    else
        return {};
}

std::vector<uint8_t> OcraHashFunction::Hmac(const std::vector<uint8_t>& data,
                                            const uint8_t* key,
                                            std::size_t keySize,
                                            ocra::OcraHmac hmacType)
{
    if (!(static_cast<uint16_t>(hmacType) & m_availableHmac))
        return {};
    
    if (hmacType == ocra::OcraHmac::HOTP_SHA1)
    {
        CryptoPP::HMAC<CryptoPP::SHA1> hmac(key, keySize);
        hmac.Update(data.data(), data.size());
        std::vector<uint8_t> result(CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE);
        hmac.Final(result.data());
        return result;
    }
    else if (hmacType == ocra::OcraHmac::HOTP_SHA256)
    {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, keySize);
        hmac.Update(data.data(), data.size());
        std::vector<uint8_t> result(CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE);
        hmac.Final(result.data());
        return result;
    }
    else if (hmacType == ocra::OcraHmac::HOTP_SHA512)
    {
        CryptoPP::HMAC<CryptoPP::SHA512> hmac(key, keySize);
        hmac.Update(data.data(), data.size());
        std::vector<uint8_t> result(CryptoPP::HMAC<CryptoPP::SHA512>::DIGESTSIZE);
        hmac.Final(result.data());
        return result;
    }
    else
        return {};
}
} // namespace mock
