#include "obl/linear.h"
#include "obl/primitives.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>

#define N 256
#define RUN 1000

using namespace std;

int main()
{
	vector<int64_t> mirror_data;

	obl::linear_oram rram(N, sizeof(int64_t));
	int64_t value, value_out;

	mirror_data.reserve(N);

	for(unsigned int i = 0; i < N; i++)
	{
		obl::gen_rand((std::uint8_t*) &value, sizeof(int64_t));

		rram.write(i, (std::uint8_t*) &value, 0);
		mirror_data[i] = value;
	}

	cerr << "finished init" << endl;

	for(int i = 0; i < RUN; i++)
		for(int j = 0; j < N; j++)
		{
			rram.access_r(j, 0, (std::uint8_t*) &value_out);
			rram.access_w(j, 0, (std::uint8_t*) &value_out, 0);

			assert(value_out == mirror_data[j]);
		}

	return 0;
}
