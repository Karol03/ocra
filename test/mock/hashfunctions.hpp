#pragma once

#include "ocra/ocra.hpp"


namespace mock
{

class OcraHashFunction
{
public:
    void SetAvailableShaAlgorithm(std::vector<ocra::OcraSha> shas)
    {
        m_availableSha = 0u;
        for (const auto& sha : shas)
            m_availableSha |= static_cast<uint16_t>(sha);
    }

    void SetAvailableHmacAlgorithm(std::vector<ocra::OcraHmac> hmacs)
    {
        m_availableHmac = 0u;
        for (const auto& hmac : hmacs)
            m_availableHmac |= static_cast<uint16_t>(hmac);
    }

    static std::vector<uint8_t> Sha(const std::vector<uint8_t>& data, ocra::OcraSha shaType);
    static std::vector<uint8_t> Hmac(const std::vector<uint8_t>& data,
                                     const uint8_t* key,
                                     std::size_t keySize,
                                     ocra::OcraHmac hmacType);

private:
    inline static uint16_t m_availableSha = {};
    inline static uint16_t m_availableHmac = {};
};

}  // namespace mock
