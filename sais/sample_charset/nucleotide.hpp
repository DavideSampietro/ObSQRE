#ifndef ATCG_HPP
#define ATCG_HPP

#include "base_chartype.hpp"
#include <cstdint>

class nucleotide: public base_chartype
{
public:
	
	operator std::int32_t()
	{
		switch(c)
		{
			case 'A':
				return 0;
			case 'C':
				return 1;
			case 'G':
				return 2;
			case 'T':
				return 3;
		}
		
		return -1;
	}
	
};

#endif // ATCG_HPP
