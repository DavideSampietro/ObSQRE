#ifndef ATCG_HPP
#define ATCG_HPP

#include <cstdint>

class nucleotide
{
private:
	char c;

public:
	// in order to instantiate an array, you actually need an empty constructor
	nucleotide() {}

	void operator =(const nucleotide &o)
	{
		this->c = o.c;
	}

	// WARNING: REQUIRED BY sais
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

	operator char()
	{
		return c;
	}

	// WARNING: REQUIRED BY sais
	nucleotide& operator*()
	{
		return *this;
	}

	// WARNING: REQUIRED BY sais
	bool operator ==(const nucleotide &o)
	{
		return this->c == o.c;
	}

	// WARNING: REQUIRED BY sais
	bool operator <(const nucleotide &o)
	{
		return this->c < o.c;
	}
};

#endif // ATCG_HPP
