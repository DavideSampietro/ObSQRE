#ifndef BASE_CHARTYPE_H
#define BASE_CHARTYPE_H

class base_chartype
{
protected:
	char c;

public:

	bool operator ==(const base_chartype &o)
	{
		return this->c == o.c;
	}
	
	bool operator !=(const base_chartype &o)
	{
		return this->c != o.c;
	}

	bool operator <(const base_chartype &o)
	{
		return this->c < o.c;
	}
	
};

#endif // BASE_CHARTYPE_H
