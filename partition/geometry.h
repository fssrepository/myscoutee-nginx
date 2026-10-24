#ifndef MYSCOUTEE_GEOMETRY_H
#define MYSCOUTEE_GEOMETRY_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void *msc_geometry_load(const char *path, char *error, size_t error_size);
const char *msc_geometry_find(void *cache, double latitude, double longitude);
void msc_geometry_free(void *cache);
#ifdef __cplusplus
}
#endif
#endif
