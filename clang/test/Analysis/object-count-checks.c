// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.unix.ObjectCount -verify %s

#include "object-header.h"
#include <stddef.h>

// Cannot return consumed header.
__OBJECT_CONSUMED header_t* test_attribute_consumed_function_fail(void); // expected-warning {{'object_consumed' attribute only applies to parameters}}

// Current we cannot add returns acquired from parameters.
void test_attribute_returns_acquired_out_param_fail(__OBJECT_RETURN_ACQUIRED header_t** out_header); // expected-warning {{'object_returns_acquired' attribute only applies to functions}}


// Do not allow return an acquired for an in param.
void test_attribute_returns_acquired_in_param_fail(__OBJECT_RETURN_ACQUIRED header_t* header); // expected-warning {{'object_returns_acquired' attribute only applies to functions}}

// Currently do not validate that the parameters are indeed objects.
__OBJECT_RETURN_ACQUIRED int test_attribute_arbitrary(
    __OBJECT_CONSUMED int header);

// Do not error saying that we did not consume the header since there is no analysis.
__OBJECT_NO_ANALYSIS void test_no_leak_error(__OBJECT_CONSUMED header_t* header) {
};

// Do not error saying that we didn't return acquired reference since there is no analysis.
__OBJECT_NO_ANALYSIS __OBJECT_RETURN_ACQUIRED header_t* test_no_return_acquired_error() {
  return NULL;
};

// Test a variety of parameters to ensure it does not crash.
void test_arbtirary_parameters(int test1, void* test, header_t* test2, header_t** test3, __OBJECT_CONSUMED header_t* test4) {
  object_release(test4);
}
