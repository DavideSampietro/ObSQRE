#include "obl/so_path.h"
#include "obl/primitives.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>

#define P 16
#define N (1 << P)
#define RUN 400

#define S 32
#define Z 4

using namespace std;

int main()
{
	vector<obl::leaf_id> position_map;
	vector<int64_t> mirror_data;

	obl::so_path_oram rram(N, sizeof(int64_t), Z, S);
	int64_t value, value_out;

	position_map.reserve(N);
	mirror_data.reserve(N);

	for(unsigned int i = 0; i < N; i++)
	{
		obl::leaf_id next_leef;
		obl::gen_rand((std::uint8_t*) &next_leef, sizeof(obl::leaf_id));

		obl::gen_rand((std::uint8_t*) &value, sizeof(int64_t));

		rram.write(i, (std::uint8_t*) &value, next_leef);
		mirror_data[i] = value;
		position_map[i] = next_leef;
	}

	cerr << "finished init" << endl;

	for(int i = 0; i < RUN; i++)
		for(int j = 0; j < N; j++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t*) &next_leef, sizeof(obl::leaf_id));

			int64_t value_upd = mirror_data[j] + 1;

			rram.access_r(j, position_map[j], (std::uint8_t*) &value_out);
			rram.access_w(j, position_map[j], (std::uint8_t*) &value_upd, next_leef);
			assert(value_out == mirror_data[j]);

			
			position_map[j] = next_leef;
			++mirror_data[j];
		}

	return 0;
}
