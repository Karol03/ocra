#pragma once

#include <iostream>
#include <stdexcept>

#include <gtest/gtest.h>


#ifdef OCRA_NO_THROW
#define ASSERT_RETURN_STATUS(statement, _code) \
    do { \
        int expected_code = _code; \
        ASSERT_EQ((statement).Status(), expected_code); \
    } while (0)
#define ASSERT_THROW_MESSAGE(...) do { } while(0)
#else
#define ASSERT_RETURN_STATUS(...) do {} while(0)
#define ASSERT_THROW_MESSAGE(statement, _message) \
    ASSERT_THROW([&]() { \
        try { \
            statement; \
        } catch (std::invalid_argument& e) { \
            const auto expected_message = std::string{_message}; \
            const auto exception_message = std::string{e.what()}; \
            ASSERT_EQ(expected_message, exception_message); \
            throw; \
        } catch (std::exception& e) { \
            std::cerr << "Exception thrown: " << e.what() << '\n'; \
            throw; \
        } \
    }(), std::invalid_argument)
#endif



