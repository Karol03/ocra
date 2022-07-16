#pragma once

#include <gtest/gtest.h>


class TestEventListenerProxy : public ::testing::TestEventListener 
{
public:
    explicit TestEventListenerProxy(::testing::TestEventListener* event_listener)
    {
        listener = event_listener;
    }

    virtual ~TestEventListenerProxy()
    {
        if (listener)
            delete listener;
        listener = nullptr;
    }

    virtual void OnTestProgramStart(const ::testing::UnitTest& unit_test) { listener->OnTestProgramStart(unit_test); }
    virtual void OnTestIterationStart(const ::testing::UnitTest& unit_test, int iteration) { listener->OnTestIterationStart(unit_test, iteration); }
    virtual void OnEnvironmentsSetUpStart(const ::testing::UnitTest& unit_test) { listener->OnEnvironmentsSetUpStart(unit_test); }
    virtual void OnEnvironmentsSetUpEnd(const ::testing::UnitTest& unit_test) { listener->OnEnvironmentsSetUpEnd(unit_test); }
    virtual void OnTestCaseStart(const ::testing::TestCase& test_case) { listener->OnTestCaseStart(test_case); }
    virtual void OnTestStart(const ::testing::TestInfo& test_info) { listener->OnTestStart(test_info); }
    virtual void OnTestPartResult(const ::testing::TestPartResult& result) { listener->OnTestPartResult(result); }
    virtual void OnTestEnd(const ::testing::TestInfo& test_info) { listener->OnTestEnd(test_info); }
    virtual void OnTestCaseEnd(const ::testing::TestCase& test_case) { listener->OnTestCaseEnd(test_case); }
    virtual void OnEnvironmentsTearDownStart(const ::testing::UnitTest& unit_test) { listener->OnEnvironmentsTearDownStart(unit_test); }
    virtual void OnEnvironmentsTearDownEnd(const ::testing::UnitTest& unit_test) { listener->OnEnvironmentsTearDownEnd(unit_test); }
    virtual void OnTestIterationEnd(const ::testing::UnitTest& unit_test, int iteration) { listener->OnTestIterationEnd(unit_test, iteration); }
    virtual void OnTestProgramEnd(const ::testing::UnitTest& unit_test) { listener->OnTestProgramEnd(unit_test); }

protected:
    ::testing::TestEventListener* listener;
};


class CaseSummaryAndFailurePrinter : public TestEventListenerProxy
{
public:
    explicit CaseSummaryAndFailurePrinter(::testing::TestEventListener* default_printer)
        : TestEventListenerProxy(default_printer)
    {}

    virtual void OnEnvironmentsTearDownStart(const ::testing::UnitTest& /*unit_test*/) { }
    virtual void OnEnvironmentsSetUpStart(const ::testing::UnitTest& /*unit_test*/) { }
    virtual void OnTestStart(const ::testing::TestInfo& /*test_info*/) { }

    virtual void OnTestEnd(const ::testing::TestInfo& test_info) {
        if (test_info.result()->Failed())
            listener->OnTestEnd(test_info);
    }
};


class SummaryAndFailurePrinter : public CaseSummaryAndFailurePrinter
{
public:
    explicit SummaryAndFailurePrinter(::testing::TestEventListener* default_printer)
        : CaseSummaryAndFailurePrinter(default_printer)
    {
    }

    virtual void OnTestCaseStart(const ::testing::TestCase& /*test_case*/) { }
    virtual void OnTestCaseEnd(const ::testing::TestCase& /*test_case*/) { }
};
