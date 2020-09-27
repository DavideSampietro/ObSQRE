#ifndef SUBTOL_CONFIG_H
#define SUBTOL_CONFIG_H

// oram selection
enum obl_oram_t {
	OBL_CIRCUIT_ORAM = 0,
	OBL_RING_ORAM,
	OBL_PATH_ORAM
};

struct subtol_config_t {
	// general params
	obl_oram_t base_oram;
	unsigned int Z;
	unsigned int stash_size;
	// only for ring oram
	unsigned int S;
	unsigned int A;
	// only for recursive oram
	unsigned int csize;
	unsigned int sa_block;
};

#endif // SUBTOL_CONFIG_H
