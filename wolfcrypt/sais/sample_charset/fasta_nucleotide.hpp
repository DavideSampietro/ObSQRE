#ifndef ATCGN_HPP
#define ATCGN_HPP

#include "base_chartype.hpp"
#include <cstdint>

// does not cointain all of the FASTA values for a nucleotide
class fasta_nucleotide: public base_chartype
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
			case 'M':
				return 3;
			case 'N':
				return 4;
			case 'R':
				return 5;
			case 'T':
				return 6;
		}
		
		return -1;
	}
	
};

#endif // ATCGN_HPP
