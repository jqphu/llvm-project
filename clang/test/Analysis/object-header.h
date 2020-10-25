// Convenience macros.
#define __OBJECT_CONSUMED __attribute__((object_consumed))
#define __OBJECT_RETURN_ACQUIRED __attribute__((object_returns_acquired))
#define __OBJECT_NO_ANALYSIS __attribute__((annotate("object_no_analysis")))

// Opaque header.
typedef struct header header_t;

// Using the returns acquired attribute.
__OBJECT_NO_ANALYSIS __OBJECT_RETURN_ACQUIRED header_t* object_create(void);

// Special function name for acquire.
__OBJECT_NO_ANALYSIS void object_acquire(header_t* foo);

// Consumed attribute.
__OBJECT_NO_ANALYSIS void object_release(__OBJECT_CONSUMED header_t* foo);
