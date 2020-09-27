#ifndef AMINO_HPP
#define AMINO_HPP

#include "base_chartype.hpp"
#include <cstdint>

class aminoa: public base_chartype
{
public:
	
	operator std::int32_t()
	{
		// aminoacids (offset of 3 - offset of 'A')
		if(c >= 'A' && c <= 'Z')
			return c - 'A' + 3;
		
		// separator between different proteins in the swissprot dataset I created
		if(c == '$')
			return 0;
		
		// stop
		if(c == '*')
			return 1;
			
		// gap
		if(c == '-')
			return 2;
		
		return -1;
	}
	
};

#endif // AMINO_HPP
