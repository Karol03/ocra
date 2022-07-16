#pragma once

#include <iostream>
#include <stdexcept>

#include <gtest/gtest.h>


#define ASSERT_THROW_MESSAGE(statement, _expected_exception, _message) \
    ASSERT_THROW([&]() { \
        try { \
            statement; \
        } catch (_expected_exception& e) { \
            const auto expected_message = std::string{_message}; \
            const auto exception_message = std::string{e.what()}; \
            ASSERT_EQ(expected_message, exception_message); \
            throw; \
        } catch (std::exception& e) { \
            std::cerr << "Exception thrown: " << e.what() << '\n'; \
            throw; \
        } \
    }(), _expected_exception);

