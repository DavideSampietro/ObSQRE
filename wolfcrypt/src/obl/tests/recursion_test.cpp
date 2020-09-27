#include "obl/ring.h"
#include "obl/circuit.h"
#include "obl/path.h"
#include "obl/rec.h"
#include "obl/primitives.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>

#define P 12
#define N (1 << P)
#define RUN 4

using namespace std;

int main()
{
	vector<int64_t> mirror_data;

	int64_t value, value_out;

	//obl::path_factory of(4, 48);
	obl::coram_factory of(3, 8);
	obl::recursive_oram rram(N, sizeof(int64_t), 5, &of);

	mirror_data.reserve(N);

	for(unsigned int i = 0; i < N; i++)
	{
		obl::gen_rand((std::uint8_t*) &value, sizeof(int64_t));

		rram.access(i, (std::uint8_t*) &value, (std::uint8_t*) &value_out);
		mirror_data[i] = value;
	}

	cerr << "finished init" << endl;

	for(int i = 0; i < RUN; i++)
		for(int j = 0; j < N; j++)
		{
			rram.access(j, nullptr, (std::uint8_t*) &value_out);

			assert(value_out == mirror_data[j]);
		}

	return 0;
}
