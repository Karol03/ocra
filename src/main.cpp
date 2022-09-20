#include "ocra/ocra.hpp"

#include <iostream>


namespace ocra::user_implemented
{
std::vector<uint8_t> ShaHashing(const std::vector<uint8_t>& data,
                                OcraSha shaType) { return {}; }

std::vector<uint8_t> HMACAlgorithm(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& key,
                                   OcraHmac hmacType) { return {0x05, 0xAB, 0xAC, 0x01, 0x89, 0x94}; }
} // namespace ocra::user_implemented


int main()
{
    std::string data;
    std::cin >> data;
    ocra::OcraParameters params;
    params.key = {0x05, 0xAB, 0xAC, 0x01, 0x89, 0x94};
    params.question = data;
    std::cout << (ocra::Ocra("OCRA-1:HOTP-SHA256-8:QA08"))(params);
}