<h1>OCRA: Challenge-response Algorithm</h1>
<h2>1. Description</h2>
<h3>About the project</h3>
This project is C++17 implementation of OCRA challenge-response algorithm. </br>
The project realizes <a href="https://datatracker.ietf.org/doc/html/rfc6287#section-5.1">RFC6287</a></br>
<h3>Building</h3>
The implementation contains only two files 'ocra.hpp' and 'ocra.cpp'. To build the project or the tests use 'ocra.sh' script (tested on Ubuntu), use the './ocra.sh -h' for more details. </br>
<h3>Using</h3>
To use OCRA algorithm create OCRA object with proper suite (see RFC6287 for more), and use function call operator with provided arguments. An example:

```cpp
#include "ocra/ocra.hpp"
// ...
{
    // ...
    auto ocra = ocra::Ocra{"OCRA-1:HOTP-SHA1-6:QN08"};
    auto params = ocra::OcraParameters();
    params.key = { /* key, for safety reasons it should be at least
        20 bytes length - for SHA1, 32 bytes length - for SHA256, 64 bytes length - for SHA512 */};
    auto ocraResultCode = ocra(params);
    // ...
}
```

<h2>2. Testcases</h2>
The tests scenarios consider all testcases from the 'RFC6287' and some additional tests for failures. Run the tests using 'ocra.sh' script and the falg '-t'. </br>
Due to the large number of tests, successful cases are truncated, and the test run is presented only for failed tests. </br>

<h2>3. User defined functions</h2>
Implementation requires from user to define own SHA and HMAC algoritm functions (see end of the 'ocra.hpp' file). This helped reduce external dependencies in the project and allows the user to take advantage of the hardware accelerated SHA/HMAC functions. </br>
Notice: Don't forget to implement all 'OcraSha' and 'OcraHmac' types. If there is no implementation, the code 0x17 or 0x11 will be returned (see 4. Validations and failures). <br/> </br>
To provide your own implementation use function signatures: </br>

```cpp
namespace ocra::user_implemented
{
std::vector<uint8_t> ShaHashing(const std::vector<uint8_t>& data,
                                OcraSha shaType);
std::vector<uint8_t> HMACAlgorithm(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& key,
                                   OcraHmac hmacType);
}  // namespace ocra::user_implemented
```
</br>

<h2>4. Validations and failures</h2>
<h3>Validations</h3>
In addition to the standard OCRA algorithm, the implementation also includes validation when calculating values. If the 'OCRA suite' is invalid, or the correct value is missing for calculating the result, an adequate status will be reported. </br>
The implementation of OCRA algorithm have exceptions enabled by default. However, it is possible to compile the project with no-exception state and use status codes, 'OCRA_NO_THROW' flag. </br>
When exceptions are disabled all failures are recorded by a set of equivalent codes and can be obtained by using the 'Ocra{}.Status()' method. </br>

<h3>Excepiton-code list</h3>
Below are presented codes, the equivalent exception and the meaning of them:
<table>
    <tr><th>Code (HEX)</th><th>Exception message</th><th>Meaning</th></tr>
    <tr><td>0x00</td><td>-</td><td>OK, no exception</td></tr>
    <tr>
        <td>0x01</td>
        <td>Invalid OCRA suite, pattern is: <Version>:<CryptoFunction>:<DataInput>, see RFC6287
        </td>
        <td>
            Ocra suite has invalid format, make sure that the format is as presented in excepion and RFC6287 document.
        </td>
    </tr>
    <tr>
        <td>0x02</td>
        <td>Invalid OCRA version, supported version is 1</td>
        <td>Version part is incorrect, only 'OCRA-1' version is supported</td>
    </tr>
    <tr>
        <td>0x03</td>
        <td>Invalid OCRA CryptoFunction, pattern is HOTP-SHAx-t, x = {1, 256, 512}, t = {0, 4-10}</td>
        <td>CryptoFunction part is incorrect, make sure it has a structure like the one shown in the pattern</td>
    </tr>
    <tr>
        <td>0x04</td>
        <td>Invalid OCRA CryptoFunction, implementation supports only HOTP, pattern is HOTP-SHAx-t</td>
        <td>CryptoFunction part is incorrect, make sure it starts from HOTP, other algorithms are not supported</td>
    </tr>
    <tr>
        <td>0x05</td>
        <td>Invalid OCRA CryptoFunction, implementation supports SHA1, SHA256 or SHA512, pattern is HOTP-SHAx-t</td>
        <td>CryptoFunction part is incorrect, make sure you using SHA1, SHA256 or SHA512, other hashing algorithms are not supported</td>
    </tr>
    <tr>
        <td>0x06</td>
        <td>Invalid OCRA CryptoFunction, invalid 't' value, supported digits t = {0, 4-10}, pattern is HOTP-SHAx-t</td>
        <td>CryptoFunction part is incorrect, make sure truncation 't' value is equal to 0 or in range 4-10</td>
    </tr>
    <tr>
        <td>0x07</td>
        <td>Unsupported data input format, for challenge data 'QFxx' wrong number of values, pattern is: Q[A|N|H][04-64]</td>
        <td>DataInput part is incorrect, make sure the challeng related flag has proper structure - starts with 'Q' than one of the supported format types [A|N|H], and two chars with length [04-64] (notice the leading zero)</td>
    </tr>
    <tr>
        <td>0x08</td>
        <td>Unsupported data input format, for challenge data 'QFxx' unrecognized value of 'F', pattern is: Q[A|N|H][04-64]</td>
        <td>DataInput part is incorrect, you used incorrect format value, only 'A' - alphanumeric, 'N' - numeric(decimal) and 'H' - hexadecimal are supported</td>
    </tr>
    <tr>
        <td>0x09</td>
        <td>Unsupported data input format, for challenge data 'QFxx' value 'xx' is out of bound, pattern is: Q[A|N|H][04-64]</td>
        <td>DataInput part is incorrect, length has incorrect value outisde the boundaries <4, 64></td>
    </tr>
    <tr>
        <td>0x0A</td>
        <td>"Unsupported data input format, invalid password descriptor 'PH', hash function must be SHA1, SHA256 or SHA512, pattern is: PSHA[1|256|512]"</td>
        <td>DataInput part is incorrect, if you use password, make sure use using one of the supported hashing algorithms 'SHA1', 'SHA256' or 'SHA512'</td>
    </tr>
    <tr>
        <td>0x0B</td>
        <td>Unsupported data input format, invalid session data 'Snnn', pattern is: S[001-512]</td>
        <td>DataInput part is incorrect, session info length should be 001 to 512 (notice leading zeros)</td>
    </tr>
    <tr>
        <td>0x0C</td>
        <td>Unsupported data input format, for session data 'Snnn' value 'nnn' is out of bound, pattern is: S[001-512]</td>
        <td>DataInput part is incorrect, session info length has incorrect value outisde the boundaries <1, 512></td>
    </tr>
    <tr>
        <td>0x0D</td>
        <td>Unsupported data input format, invalid timestamp data 'TG', pattern is: T[[1-59][S|M] | [0-48]H]</td>
        <td>DataInput part is incorrect, timestamp has incorrect format, make sure it has a structure like the one shown in the pattern</td>
    </tr>
    <tr>
        <td>0x0E</td>
        <td>Unsupported data input format, invalid timestamp data 'TG', time-step must be S, M or H, pattern is: T[[1-59][S|M] | [0-48]H]</td>
        <td>DataInput part is incorrect, timestamp has incorrect step it should be 'S' - seconds, 'M' - minutes or 'H' - hours</td>
    </tr>
    <tr>
        <td>0x0F</td>
        <td>Unsupported data input format, for timestamp data 'TG' value 'G' is out of bound, pattern is: T[[1-59][S|M] | [0-48]H]</td>
        <td>DataInput part is incorrect, timestamp has incorrect value, for seconds/minutes it should be 1-59, for hours 0-48 (notice *no* leading zero)</td>
    </tr>
    <tr>
        <td>0x10</td>
        <td>OCRA operator() failed, missing parameter 'key', required for HMAC</td>
        <td>OcraParameters has missing 'key' value, the key is required for all OCRA suites</td>
    </tr>
    <tr>
        <td>0x11</td>
        <td>OCRA operator() failed, invalid HMAC result size, please check user defined HMACAlgorithm function</td>
        <td>The user implementation of HMAC algorithm is incorrect, the returned value has invalid length</td>
    </tr>
    <tr>
        <td>0x12</td>
        <td>OCRA operator() failed, suite contains a counter, but no counter value in parameters</td>
        <td>OcraParameters has missing 'counter' value but ocra suite used for object cration contained counter flag '-C'</td>
    </tr>
    <tr>
        <td>0x13</td>
        <td>OCRA operator() failed, missing parameter 'question'</td>
        <td>OcraParameters missing 'question' value, 'question' is the same as 'challenge', for OCRA calculations 'challenge' is always required</td>
    </tr>
    <tr>
        <td>0x15</td>
        <td>OCRA operator() failed, question is Numeric, and must contains only digits '0' to '9'</td>
        <td>OcraParameters invalid 'question' value, numeric 'question' format ('QNxx') was selected but 'question' value does not contain only values between '0'-'9'</td>
    </tr>
    <tr>
        <td>0x16</td>
        <td>OCRA operator() failed, missing 'password' value</td>
        <td>OcraParameters missing 'password' value, you used password for create the OCRA object ('-PSHAx'), but OcraParameters doesn't contain 'password' value</td>
    </tr>
    <tr>
        <td>0x17</td>
        <td>OCRA operator() failed, password hashing failed, check user defined ShaHashing function</td>
        <td>The user implementation of SHA algorithm is incorrect, the returned value has invalid length</td>
    </tr>
    <tr>
        <td>0x18</td>
        <td>OCRA operator() failed, no session info provided</td>
        <td>OcraParameters missing 'sessionInfo' value, you used session info for create the OCRA object ('-Snnn'), but OcraParameters doesn't contain 'sessionInfo' value</td>
    </tr>
    <tr>
        <td>0x19</td>
        <td>OCRA operator() failed, suite contains a timestamp, but no timestamp value in parameters</td>
        <td>OcraParameters missing 'timestamp' value, you used timestamp for create the OCRA object ('-TG'), but OcraParameters doesn't contain 'timestamp' value</td>
    </tr>
    <tr>
        <td>0x1A</td>
        <td>OCRA operator() failed, question is Hexadecimal, and must contains values [0-9][a-f][A-F]</td>
        <td>OcraParameters contains invalid value of 'sessionInfo' or 'question', 'sessionInfo' should be HEX encoded, or you try to use HEX question ('-QHxx') with non HEX value</td>
    </tr>
    <tr>
        <td>0x1B</td>
        <td>Data input has missing first argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]</td>
        <td>DataInput is incorrect, make sure you add at least one flag (QFxx)</td>
    </tr>
    <tr>
        <td>0x1B</td>
        <td>Data input has empty challenge argument, please specify argument following the pattern: [C]-QFxx-[PH|Snnn|TG]</td>
        <td>DataInput is incorrect, make sure you add challenge flag (QFxx) which is required</td>
    </tr>
    <tr>
        <td>0x1D</td>
        <td>Data input has missing challenge data 'QFxx', data input pattern is: [C]-QFxx-[PH|Snnn|TG]</td>
        <td>DataInput is incorrect, make sure you add challenge flag (QFxx) properly (using 'Q' prefix)</td>
    </tr>
    <tr>
        <td>0x1E</td>
        <td>Unsupported data input format, unexpected parameters left, data input pattern is: [C]-QFxx-[PH]-[Snnn]-[TG]</td>
        <td>DataInput is incorrect, make sure that the order of the flags is the same as shown above and that no flag is repeated.</td>
    </tr>
</table>

<h2>Requirements</h2>
C++17 </br>
Boost </br>
Crypto++ (for test only)
