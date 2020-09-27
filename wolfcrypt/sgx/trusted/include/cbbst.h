#ifndef CBBST_H
#define CBBST_H

#include <cstdint>
#include <cstddef>
#include "obl/oram.h"

#include <ipp/ippcp.h>

namespace obl { namespace ods {

	class cbbst {
	private:
		std::size_t N;
		std::size_t capacity;
		int L; // number of levels

		std::size_t B;
		std::size_t node_size;

		tree_oram **s_tree;

		leaf_id *subtree_roots;
		int no_subtree;
		int current_subtree;

		// utils to load data level-wise
		IppsAESSpec *leafgen;
		std::uint8_t dummy_ptx[16];
		std::uint8_t evict_ctr[16];
		std::uint8_t leaf_ctr[16];
		std::uint8_t cur_evict_ctr[16];
		std::uint8_t cur_leaf_ctr[16];
		obl::leaf_id ev_leaf;
		std::int32_t current_lvl, lvl_index;
		std::int32_t global_idx;

		// pointer for depth-wise exploration
		std::uint8_t *node_buffer;
		leaf_id next_fetch, next_evict;

	public:
		cbbst(std::size_t N, std::size_t B, oram_factory *allocator);
		cbbst(std::size_t N, std::size_t B, oram_factory *allocator, std::size_t *lvl_size, int no_levs, int no_subtree);

		~cbbst();

		std::size_t get_N() const;
		int get_L() const;

		// methods to load the binary tree level-wise
		void init_loading();
		void finalize_loading();
		void init_level(int l);
		void load_values(std::uint8_t *val, std::size_t N);
		void load_values_with_dummies(std::uint8_t *val, std::size_t N, std::size_t M);

		// methods for traversing the tree
		void select_subtree(int sbt);
		void read(obl::block_id bid, std::uint8_t *data_o, int lvl);
		void update(obl::block_id bid, std::uint8_t *data_i, bool go_left, int lvl);
	};

} }

#endif // CBBST_H
