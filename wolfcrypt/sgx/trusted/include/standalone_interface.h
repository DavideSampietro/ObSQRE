#ifndef SUBTOL_STANDALONE_INTERFACE_H
#define SUBTOL_STANDALONE_INTERFACE_H

#include "subtol_config.h"
#include "contexts/subtol_context.h"

subtol_context_t* init_subtol_context(void *fb, char *pwd, subtol_config_t &cfg);

#endif // SUBTOL_STANDALONE_INTERFACE_H
