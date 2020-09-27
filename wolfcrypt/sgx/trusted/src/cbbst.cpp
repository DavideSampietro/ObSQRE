#include "cbbst.h"

#include "obl/primitives.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#define DUMMY -1

namespace obl { namespace ods {

	struct node_t {
		leaf_id left_ch;
		leaf_id right_ch;
		std::uint8_t data[];
	};

	cbbst::cbbst(std::size_t N, std::size_t B, oram_factory *allocator)
	{
		this->N = N;

		std::uint64_t n_pow = next_two_power(this->N + 1);
		if(n_pow <= 1)
			n_pow = 2;

		capacity = n_pow - 1;
		L = __builtin_popcountll(capacity);

		this->B = B;
		node_size = sizeof(node_t) + B;
		node_buffer = new std::uint8_t[node_size];

		s_tree = new tree_oram*[L];

		subtree_roots = new leaf_id[1];
		no_subtree = 1;
		current_subtree = 0;

		std::size_t oram_size = 1;
		for(int i = 0; i < L; i++)
		{
			std::size_t f_size = N > oram_size ? oram_size : N;

			s_tree[i] = allocator->spawn_oram(f_size, node_size);

			N -= oram_size;
			oram_size <<= 1;
		}
	}

	cbbst::cbbst(std::size_t N, std::size_t B, oram_factory *allocator, std::size_t *lvl_size, int no_levs, int no_subtree)
	{
		this->N = N;
		this->L = no_levs;

		this->B = B;
		node_size = sizeof(node_t) + B;
		node_buffer = new std::uint8_t[node_size];

		s_tree = new tree_oram*[L];

		subtree_roots = new leaf_id[no_subtree];
		this->no_subtree = no_subtree;

		for(int i = 0; i < L; i++)
			s_tree[i] = allocator->spawn_oram(lvl_size[i], node_size);
	}

	cbbst::~cbbst()
	{
		for(int i = 0; i < L; i++)
			delete s_tree[i];

		delete[] s_tree;
		delete[] subtree_roots;
		delete[] node_buffer;
	}

	std::size_t cbbst::get_N() const
	{
		return N;
	}

	int cbbst::get_L() const
	{
		return L;
	}

	void cbbst::init_loading()
	{
		int ctr_state_size;
		std::uint8_t ephemeral_key[16];

		// allocate AES-CTR
		ippsAESGetSize(&ctr_state_size);
		leafgen = (IppsAESSpec*) std::malloc(ctr_state_size);

		// initialize key for loading
		obl::gen_rand_seed(ephemeral_key, 16);
		ippsAESInit(ephemeral_key, 16, leafgen, ctr_state_size);

		// initialize random IV
		obl::gen_rand_seed(leaf_ctr, 16);

		// generate random PTX
		obl::gen_rand(dummy_ptx, 16);

		global_idx = 0;
	}

	void cbbst::finalize_loading()
	{
		std::free(leafgen);
	}

	void cbbst::init_level(int l)
	{
		std::memcpy(evict_ctr, leaf_ctr, 16);
		obl::gen_rand_seed(leaf_ctr, 16);
		current_lvl = l;
		lvl_index = 0;

		std::memcpy(cur_evict_ctr, evict_ctr, 16);
		std::memcpy(cur_leaf_ctr, leaf_ctr, 16);
	}

	void cbbst::load_values_with_dummies(std::uint8_t *val, std::size_t N, std::size_t M)
	{
		assert(N >= M);

		obl::leaf_id ev_leaves[2];
		obl::leaf_id children[2];

		std::uint8_t payload[node_size];
		node_t *to_load = (node_t*) payload;

		if((lvl_index & 1) == 1)
			ev_leaves[1] = ev_leaf;

		for(unsigned int i = 0; i < N; i++)
		{
			// generate children pointers
			ippsAESEncryptCTR(dummy_ptx, (std::uint8_t*) children, 2 * sizeof(obl::leaf_id), leafgen, cur_leaf_ctr, 128);
			to_load->left_ch = children[0];
			to_load->right_ch = children[1];

			// load payload
			std::memcpy(to_load->data, val, B);
			val += B;

			int eleef = lvl_index & 1;

			if(eleef == 0)
				ippsAESEncryptCTR(dummy_ptx, (std::uint8_t*) ev_leaves, 2 * sizeof(obl::leaf_id), leafgen, cur_evict_ctr, 128);

			block_id wr_bid = ternary_op(i < M, global_idx, DUMMY);
			s_tree[current_lvl]->write(wr_bid, payload, ev_leaves[eleef]);

			// addition to extend to multi subtrees cbbst
			if(current_lvl == 0)
				subtree_roots[current_subtree] = ev_leaves[eleef];

			++lvl_index;
			++global_idx;
		}

		if((lvl_index & 1) == 1)
			ev_leaf = ev_leaves[1];
	}

	void cbbst::load_values(std::uint8_t *val, std::size_t N)
	{
		load_values_with_dummies(val, N, N);
	}

	void cbbst::select_subtree(int sbt)
	{
		//assert(sbt < no_subtree);

		for(int i = 0; i < no_subtree; i++)
			next_fetch = ternary_op(i == sbt, subtree_roots[i], next_fetch);

		current_subtree = sbt;
	}

	void cbbst::read(obl::block_id bid, std::uint8_t *data_o, int lvl)
	{
		node_t *n = (node_t*) node_buffer;

		s_tree[lvl]->access_r(bid, next_fetch, node_buffer);
		std::memcpy(data_o, n->data, B);
	}

	void cbbst::update(obl::block_id bid, std::uint8_t *data_i, bool go_left, int lvl)
	{
		node_t *n = (node_t*) node_buffer;
		leaf_id next_next_evict;
		leaf_id next_next_fetch;

		assert(lvl < L && lvl >= 0);

		obl::gen_rand((std::uint8_t*) &next_next_evict, sizeof(leaf_id));
		std::memcpy(n->data, data_i, B);
		next_next_fetch = ternary_op(go_left, n->left_ch, n->right_ch);
		n->left_ch = ternary_op(go_left, next_next_evict, n->left_ch);
		n->right_ch = ternary_op(go_left, n->right_ch, next_next_evict);

		s_tree[lvl]->access_w(bid, next_fetch, node_buffer, next_evict);

		if(lvl == 0)
			for(int i = 0; i < no_subtree; i++)
				subtree_roots[i] = ternary_op(i == current_subtree, next_evict, subtree_roots[i]);

		next_evict = next_next_evict;
		next_fetch = next_next_fetch;
	}

} }
