#if defined(__GNUC__)
#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#define UNUSED(z)  z __attribute__ ((unused))
#else
#define UNUSED(z)  z
#endif
#define PRIVATE    __attribute__ ((visibility ("hidden")))
#define PUBLIC     __attribute__ ((visibility ("default")))
#else
#define UNUSED(z)  z
#define PRIVATE
#define PUBLIC
#endif

