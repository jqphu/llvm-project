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

// Do not error saying that we did not consume the header since there is no analysis.
__OBJECT_NO_ANALYSIS void test_no_leak_error(__OBJECT_CONSUMED header_t* header) {
};

// Do not error saying that we didn't return acquired reference since there is no analysis.
__OBJECT_NO_ANALYSIS __OBJECT_RETURN_ACQUIRED header_t* test_no_return_acquired_error() {
   return 0;
};

// Test a variety of parameters to ensure it does not crash.
void test_arbtirary_parameters(int test1, void* test, header_t* test2, header_t** test3, __OBJECT_CONSUMED header_t* test4) {
  object_release(test4);
}

// Cannot release something we don't own.
void test_release_fail(header_t* foo) {
  object_release(foo); // expected-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}

// Can consume a reference from a parameter.
void test_release_consume_attribute(__OBJECT_CONSUMED header_t* foo) {
  object_release(foo);
}

// Cannot consume multiple references from consume attribute.
void test_release_consume_attribute_fail(__OBJECT_CONSUMED header_t* foo) {
  object_release(foo);
  object_release(foo); // expected-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}

// Dummy non-consuming function.
void not_consume_function(header_t* foo);

// Can call functions that do not consume the reference.
void test_not_consume(header_t* foo) {
  not_consume_function(foo);
}

// Dummy function to consume with multiple parameters.
void consume_function(__OBJECT_CONSUMED header_t* param1, __OBJECT_CONSUMED header_t* param2);

// Consume multiple references.
void test_release_consume_function(__OBJECT_CONSUMED header_t* param1, __OBJECT_CONSUMED header_t* param2) {
  consume_function(param2, param1);
}

// Cannot consume twice as a multi-parameter.
void test_release_consume_function_same_fail(__OBJECT_CONSUMED header_t* param1) {
  consume_function(param1, param1); // expected-warning {{Incorrect decrement of the reference count of an object that is not owned at this point by the caller}}
}

// Global object to release.
header_t* global_foo;

// Can release global objects. We do not analyze these.
void test_release_global(void) {
  object_release(global_foo);
  consume_function(global_foo, global_foo);
}

typedef struct {
  header_t* foo;
} bar_t;

// Can track casting.
void test_cast(__OBJECT_CONSUMED bar_t* bar) {
  object_release((header_t*)bar);
}

// Do not track within objects.
void test_release_within_object(bar_t* bar, __OBJECT_CONSUMED bar_t* bar_consumed) {
  object_release(bar->foo);
  object_release(bar_consumed->foo);
  object_release((header_t*)bar_consumed);
}
