#ifndef REF_INIT_H
#define REF_INIT_H

#include <fstream>
#include "ref_context.h"

ref_context_t* init_ref_context(std::filebuf &fb, char *pwd);

#endif // REF_INIT_H
