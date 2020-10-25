// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.unix.ObjectCount -verify %s

typedef struct header header_t;

_Bool rand();

#define __OBJECT_CONSUMED __attribute__((object_consumed))
#define __OBJECT_RETURN_ACQUIRED __attribute__((object_returns_acquired))

__OBJECT_RETURN_ACQUIRED header_t* foo_create(void);
void object_release(__OBJECT_CONSUMED header_t* foo);
void object_autorelease(__OBJECT_CONSUMED header_t* foo);
void object_acquire(header_t* foo);

void opaque(header_t* foo);
void consume(__OBJECT_CONSUMED header_t* foo);
void test_consumed(__OBJECT_CONSUMED header_t* foo);

__OBJECT_RETURN_ACQUIRED header_t* object_create(void);
header_t* object_from(void);


// TODO: HANDLE NULL? OUT PARAM.

// TODO: NEXT: ATTRIBUTES

struct {
  header_t* foo;
} assign_foo;

header_t* foo;

// header_t* foo_create(void) {
//   header_t* foo = object_create();
//   object_acquire(foo);
//   return foo;
// }
void test_basic_create_fail() {
  header_t* foo = foo_create();
  if(foo == 0) {
    return;
  } else {
    object_release(foo);
  }
} // expected-warning {{Object is being leaked here}}



#ifndef CURRENT_TEST

void test_null(header_t* foo) {
  if(foo != 0) {
    object_acquire(foo);
  }

  if(foo != 0) {
    object_release(foo);
  }
}

void test_assignment(header_t* foo) {
  // Escape foo, no more static analysis checks.
  object_acquire(foo);
  assign_foo.foo = foo;
  object_acquire(foo);


  object_release(foo);
  // TODO: This should error out.
  object_autorelease(foo);
  object_release(foo);
}

void test_global_acquire() {
  object_acquire(foo);
}

void test_global_release() {
  object_release(foo);
}



void test_indirect_multiple(header_t* foo) {
  header_t* bar = foo;
  object_acquire(bar);
  object_acquire(bar);
  object_autorelease(foo);
  object_release(foo);
}

void test_basic_create() {
  header_t* foo = foo_create();
  object_autorelease(foo);
}

void test_basic_create_escape() {
  header_t* foo = foo_create();
  assign_foo.foo = foo;
}

void test_multiple_create() {
  header_t* foo = foo_create();
  object_acquire(foo);
  object_release(foo);
  object_autorelease(foo);
}

void test_basic(header_t* foo) {
  object_acquire(foo);
  object_release(foo);
}

void test_basic_multiple(header_t* foo) {
  object_acquire(foo);
  object_release(foo);
  object_acquire(foo);
  object_acquire(foo);
  object_release(foo);
  object_autorelease(foo);
}

void test_branch(header_t* foo) {
  object_acquire(foo);

  if(rand()) {
    object_autorelease(foo);
    return;
  }

  object_autorelease(foo);
}

void test_basic_multiple_param(header_t* foo, header_t* bar) {
  object_acquire(foo);
  object_acquire(bar);
  object_release(foo);
  object_release(bar);
}

header_t* test_basic_return_object(header_t* foo) {
  object_acquire(foo);
  return foo;
}

void test_basic_return_object_out_param(header_t* foo, header_t** foo_out) {
  object_acquire(foo);
  *foo_out = foo;
}

/**
 * Failure tests below here.
 */

void test_basic_create_release_fail() {
  header_t* foo = foo_create();
  object_autorelease(foo);
  object_autorelease(foo);
}

void test_not_escape_indirect_fail(header_t* foo) {
  header_t* bar = foo;
  opaque(bar);
  object_autorelease(bar);
}

void test_not_escape_fail(header_t* foo) {
  opaque(foo);
  object_autorelease(foo);
}

header_t* test_basic_return_object_fail(header_t* foo) {
  object_release(foo);
  return foo;
}

void test_basic_return_object_out_param_fail(header_t* foo, header_t** foo_out) {
  *foo_out = foo;
  object_release(foo);
}


void test_basic_multiple_fail(header_t* foo) {
  object_acquire(foo);
  object_autorelease(foo);
  object_autorelease(foo);
}

void test_basic_leak_fail(header_t* foo) {
  object_acquire(foo);
}

void test_basic_fail(header_t* foo) {
  object_release(foo);
}

void test_branch_double_release_fail(header_t* foo) {
  object_acquire(foo);

  if(rand()) {
    object_release(foo);
  }

  object_autorelease(foo);
}


void test_branch_leak_fail(header_t* foo) {
  object_acquire(foo);

  if(rand()) {
    return;
  }

  object_release(foo);
}


// TODO: Reaper won't touch unused variables.
void test_consumed_fail(header_t* foo) {
}
#endif
