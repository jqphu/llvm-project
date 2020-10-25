// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.unix.ObjectCount -verify %s

#include "object-header.h"

// Cannot return consumed header.
__OBJECT_CONSUMED header_t* test_attribute_consumed_function_fail(void); // expected-warning {{'object_consumed' attribute only applies to parameters}}

// Current we cannot add returns acquired from parameters.
void test_attribute_returns_acquired_out_param_fail(__OBJECT_RETURN_ACQUIRED header_t** out_header); // expected-warning {{'object_returns_acquired' attribute only applies to functions}}


// Do not allow return an acquired for an in param.
void test_attribute_returns_acquired_in_param_fail(__OBJECT_RETURN_ACQUIRED header_t* header); // expected-warning {{'object_returns_acquired' attribute only applies to functions}}

// Currently do not validate that the parameters are indeed objects.
__OBJECT_RETURN_ACQUIRED int test_attribute_arbitrary(
    __OBJECT_CONSUMED int header);
