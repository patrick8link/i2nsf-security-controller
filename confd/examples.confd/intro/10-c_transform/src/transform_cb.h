#include <confd_lib.h>

// cleanup of the internal memory used by transform code;
// to be called in finish()
void transform_free_opaque_data(void *data);

// data callback struct to be registered with ConfD
struct confd_data_cbs * transform_cb(void);
