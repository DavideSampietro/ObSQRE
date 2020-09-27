#ifndef OPT_ALLOC_HPP
#define OPT_ALLOC_HPP

#include <cstddef>

#include "obl/oram.h"
#include "obl/linear.h"

class opt_allocator: public obl::oram_factory {
private:
	obl::oram_factory *inner_allocator;
	std::size_t threshold;
	
public:
	opt_allocator(obl::oram_factory *a, std::size_t threshold) {
		this->threshold = threshold;
		inner_allocator = a;
	}
	
	obl::tree_oram* spawn_oram(std::size_t N, std::size_t B) {
		if(N <= threshold) // apply optimization policy
			return new obl::linear_oram(N, B);
		else // forward call inner allocator
			return inner_allocator->spawn_oram(N, B);
	}
	
	~opt_allocator() {
		delete inner_allocator;
	}
};

#endif // OPT_ALLOC_HPP
