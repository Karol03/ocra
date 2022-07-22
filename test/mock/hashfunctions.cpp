#include "hashfunctions.hpp"


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
        return {0x43, 0x47, 0xd0, 0xf8, 0xba, 0x66, 0x12, 0x34, 0xa8, 0xea,
                0xdc, 0x00, 0x5e, 0x2e, 0x1d, 0x1b, 0x64, 0x6c, 0x96, 0x82};
    else if (shaType == ocra::OcraSha::SHA256)
        return {0x60, 0xa5, 0xd3, 0xe4, 0x10, 0x0f, 0xe8, 0xaf, 0xa5, 0xee, 0x01,
                0x03, 0x73, 0x9a, 0x45, 0x71, 0x1d, 0x50, 0xd7, 0xf3, 0xba, 0x72, 
                0x80, 0xd8, 0xa9, 0x5b, 0x51, 0xf5, 0xd0, 0x4a, 0xa4, 0xb8};
    else if (shaType == ocra::OcraSha::SHA512)
        return {0xec, 0xbc, 0x63, 0x07, 0x0b, 0x21, 0x96, 0x5c, 0x18, 0xdd, 0x89,
                0x0b, 0x83, 0xca, 0x2d, 0xa8, 0x27, 0x95, 0x15, 0x36, 0x12, 0x85,
                0x91, 0xdc, 0xff, 0x35, 0x7e, 0x2b, 0xf7, 0x50, 0x52, 0x22, 0x8c,
                0x04, 0x25, 0x7d, 0xcc, 0x82, 0x71, 0xb6, 0xcc, 0xf8, 0x96, 0x76,
                0x3b, 0x98, 0x45, 0xe6, 0x02, 0x98, 0x11, 0x03, 0x8a, 0xee, 0x55,
                0xff, 0xab, 0xd1, 0xde, 0x8b, 0x8f, 0x99, 0xfc, 0xfc};
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
        return {};
    else if (hmacType == ocra::OcraHmac::HOTP_SHA256)
        return {};
    else if (hmacType == ocra::OcraHmac::HOTP_SHA512)
        return {};
    else
        return {};
}
} // namespace mock
