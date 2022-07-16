#include <gtest/gtest.h>

#include "listener/listener.hpp"


int main(int argc, char* argv[])
{
    ::testing::InitGoogleTest(&argc, argv);

    ::testing::TestEventListeners& listeners =
        ::testing::UnitTest::GetInstance()->listeners();

    auto default_printer = listeners.Release(listeners.default_result_printer());
    listeners.Append(new SummaryAndFailurePrinter(default_printer));

    return RUN_ALL_TESTS();
}
