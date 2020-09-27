#ifndef SAIS_H
#define SAIS_H

#include <cstring>
#include <cstddef>
#include <cstdint>

// Interface functions

/*
      Description: build the suffix array of a given string in linear time

      Template Arguments:

      Char   -- user-defined character type. It must support:
                  operator Int()
                  bool operator==(Char&)
                  bool operator<(Char&)
                  bool operator!=(Char&)
                ASCII char and unsigned char supported by default!
                base_chartype wraps a char and provides automatic support for ==, !=, <.
                The Int() operator must fulfill the following requirement:
                  given ALPHA characters in the charset, all the occurring symbols must be
                  numbered from 0 ... ALPHA-1.
                  When deriving base_chartype, the numbering from 0 ... ALPHA-1 must reflect
                  the natural ordering of the underlying char.
      Int    -- user-defined integer type.
                It can be signed or unsigned.
                It needs to be wide enough to store indices of the Char string.
                0xFF...FF index value not allowed (use larger integer instead!)

      Arguments:

      s                -- a pointer to a string (array) of Chars
      length           -- length of the string
      alphabet_size    -- size of the alphabet
      sa               -- preallocated Int array with "length+1" locations
*/
template<typename Char, typename Int>
inline
void sais(Char *s, Int length, Int alphabet_size, Int *sa);

/*
      Description: find the leading index of each character's bucket into the suffix array

      Arguments:

      s               -- original string
      length          -- length of the string
      alphabet_size   -- size of the alphabet - terminator NOT included!!!
      buckets         -- pointer to an array of "alphabet_size+1" Int
*/
template<typename Char, typename Int>
inline
void bucket_index(Char *s, Int length, Int alphabet_size, Int *buckets);

/*
      Description: build the BWT given the valid suffix array and the input string

      Arguments:

      s          -- original string
      sa         -- precomputed suffix array
      bwt        -- preallocated Char string with "lenght + 1" locations
      length     -- original string length
      dummy      -- position of the terminator
*/
template<typename Char, typename Int>
inline
void build_bwt(Char *s, Int *sa, Char *bwt, Int length, Int *dummy);

/*
      Description: build the inverse suffix array given the valid suffix array

      Arguments:

      sa       -- precomputed suffix array
      isa      -- preallocated Int array of "length+1" locations
      length   -- length of the original string the suffix array was built on
*/
template<typename Int>
inline
void inverse_sa(Int *sa, Int *isa, Int length);

/*
      Description: build the successor array given a valid suffix array and inverse suffix array

      Arguments:

      sa       -- precomputed suffix array
      isa      -- precoumputed inverse suffix array
      psi      -- preallocated Int arrat of "length+1" locations
      length   -- length of the original string the suffix array was built on

      Trick: sa might point to the same location of psi, the computation will be unaffected
*/
template<typename Int>
inline
void build_psi(Int *sa, Int *isa, Int *psi, Int length);

/*
      Description: convert a balanced binary search tree into a complete balanced search tree
      arranged in memory as a heap

      Arguments:

      v         -- initial array
      heap      -- buffer of N elements which will store the balanced and complete heap
      idx       -- current index in the binary heap
      N         -- length of v
*/
template<typename Int>
inline
void flatten(Int *v, Int *heap, std::size_t idx, std::size_t N);

/*
      Description: for each character in the alphabet, report ALL the indices of the
      BWT where that character occurs

      Arguments:

      bwt            -- BWT of the original string
      length         -- length of the original string
      alphabet_size  -- size of the alphabet (terminator excluded)
      dummy          -- position in the BWT of the terminator character
      indices        -- array of Int* pointing to properly sized buffers
*/
template<typename Char, typename Int>
inline
void write_index(Char *bwt, Int length, Int alphabet_size, Int dummy, Int **indices);

/*
      Description: creates the Vanilla BWT occurrences matrix sampling it every
      "sample_size" rows. Moreover, it compresses each character in the bwt using
      bit_enc bits in a bitarray composed of several 16-bit words.

      bwt            -- BWT of the original string
      length         -- length of the original string
      alphabet_size  -- size of the alphabet (terminator excluded)
      dummy          -- position of the terminator in the BWT
      s_rate         -- sampling rate
      bit_enc        -- number of bits devoted to each BWT character
      sample_size    -- byte size of each sampled block of data from the BWT
      blob           -- raw memory to write data to

      N.B.: blob has a precise sizing:
         sizeof(Int) * alphabet_size + sizeof(std::uint16_t) * A,
         where A is the number of 16-bit words necessary to store s_rate bwt
         characters encoded with bit_enc bits
*/
template<typename Char, typename Int>
inline
void sampled_bwt(Char *bwt, Int length, Int alphabet_size, Int dummy, std::size_t s_rate, std::size_t bit_enc, std::size_t sample_size, std::uint8_t *blob);

// Static functions

template<typename Char, typename Int>
static void scan_LS(Char *s, Int length, Int *sa, Int &no_LMS);

template<typename Char, typename Int>
static void place_LMS(Char *s, Int length, const Int *buckets, Int alphabet_size, Int *sa, Int *LMS_positions, Int no_LMS);

template<typename Char, typename Int>
static void mod_place_LMS(Char *s, Int length, const Int *buckets, Int alphabet_size, Int *sa, Int *LMS_positions, Int *induced_LMS_positions, Int no_LMS);

template<typename Char, typename Int>
static Int tag_LMS_prefix(Char *s, Int *LMS_positions, Int *induced_LMS_positions, Int no_LMS, Int *sa, Int length);

// Implementation of static functions

/*
      scan_LS
         Scan the string to:
         1. find and store LMS characters into the temporary suffix array
         2. fill buckets
*/
template<typename Char, typename Int>
static void scan_LS(Char *s, Int length, Int *buckets, Int *sa, Int &no_LMS)
{
   bool prev_isL, current_isL;
   Int LMS_index = length;

   // the string terminator $ is always of S-type and is also LMS!
   no_LMS = 1;
   sa[LMS_index--] = length;

   // the last character is always L since it will be greater than $...
   prev_isL = true;
   ++buckets[(Int)s[length-1]];

   // i != -1 is a fix in case the Int is an unsigned type!!
   // original version was: i >= 0 -- comparison with -1 works even for unsigned types!
   for(Int i = length-2; i != (Int)-1; i--)
   {
      Char s1 = s[i];
      Char s2 = s[i+1];

      // set L or S
      current_isL = s2 < s1;

      if(s1 == s2)
         current_isL = prev_isL;

      // increment the size of the bucket corresponding to the current character
      ++buckets[(Int)s1];

      // find LMS character
      if(current_isL && !prev_isL)
      {
         // save LMS characters in the same order they occur in the original string
         sa[LMS_index] = i+1;
         ++no_LMS;
         --LMS_index;
      }

      prev_isL = current_isL;
   }
}

template<typename Char, typename Int>
static void place_LMS(Char *s, Int length, const Int *buckets, Int alphabet_size, Int *sa, Int *LMS_positions, Int no_LMS)
{
   // initialize bucket_index to the end of each bucket
   Int * const bucket_end = new Int[alphabet_size];
   Int * const bucket_start = new Int[alphabet_size];

   for(Int i = 0; i < alphabet_size; i++)
   {
      bucket_end[i] = buckets[i+1]-1;
      bucket_start[i] = buckets[i];
   }

   // copy LMS entries in proper locations at the end of each bucket
   // i != -1 is a fix for unsignedness of Int
   sa[0] = length;

   for(Int i = no_LMS-1; i != (Int)-1; i--)
   {
      Int string_position = LMS_positions[i];
      if(string_position != length)
      {
         Int sa_index = bucket_end[(Int)s[string_position]]--;
         sa[sa_index] = string_position;
      }
   }

   // bitvector-less induce_L
   sa[bucket_start[(Int)s[length-1]]++] = length-1;

   for(Int j = 0; j < alphabet_size; j++)
   {
      Int limit = buckets[j+1];
      Int limit_L = bucket_end[j] + 1;

      for(Int i = buckets[j]; i < limit; i++)
      {
         Int string_index = sa[i] + 1;

         if(string_index >= 2)
         {
            string_index--;
            Char s1 = s[string_index];
            Char s2 = s[string_index-1];

            if(s1 < s2 || (s1 == s2 && i < limit_L))
               sa[bucket_start[(Int) s2]++] = string_index - 1;
         }
      }
   }

   for(Int i = 0; i < alphabet_size; i++)
      bucket_end[i] = buckets[i+1]-1;

   // bitvector-less induce_S
   for(Int j = alphabet_size-1; j != (Int)-1; j--)
   {
      Int limit = buckets[j]-1;
      Int limit_S = bucket_start[j]; // >=

      for(Int i = buckets[j+1]-1; i != limit; i--)
      {
         Int string_index = sa[i] + 1;

         if(string_index >= 2)
         {
            string_index--;
            Char s1 = s[string_index];
            Char s2 = s[string_index-1];

            if(s2 < s1 || (s1 == s2 && i >= limit_S)) // if s2 is of type-S...
               sa[bucket_end[(Int) s2]--] = string_index - 1;
         }
      }
   }

   delete[] bucket_end;
   delete[] bucket_start;
}

template<typename Char, typename Int>
static void mod_place_LMS(Char *s, Int length, const Int *buckets, Int alphabet_size, Int *sa, Int *LMS_positions, Int *induced_LMS_positions, Int no_LMS)
{
   Int * const bucket_end = new Int[alphabet_size];
   Int * const bucket_start = new Int[alphabet_size];
   Int induced_cursor = no_LMS - 1;

   for(Int i = 0; i < alphabet_size; i++)
   {
      // buckets is alphabet_size+1 !!!
      bucket_end[i] = buckets[i+1]-1;
      bucket_start[i] = buckets[i];
   }

   // copy LMS entries in proper locations at the end of each bucket
   // i != -1 is a fix for unsignedness of Int
   sa[0] = length;

   for(Int i = no_LMS-2; i != (Int)-1; i--)
   {
      Int string_position = LMS_positions[i];
      Int sa_index = bucket_end[(Int)s[string_position]]--;
      sa[sa_index] = string_position;
   }

   // bitvector-less induce_L
   sa[bucket_start[(Int)s[length-1]]++] = length-1;

   for(Int j = 0; j < alphabet_size; j++)
   {
      Int limit = buckets[j+1];
      Int limit_L = bucket_end[j] + 1;

      for(Int i = buckets[j]; i < limit; i++)
      {
         Int string_index = sa[i] + 1;

         if(string_index >= 2)
         {
            string_index--;
            Char s1 = s[string_index];
            Char s2 = s[string_index-1];

            if(s1 < s2 || (s1 == s2 && i < limit_L))
               sa[bucket_start[(Int) s2]++] = string_index - 1;
         }
      }
   }

   for(Int i = 0; i < alphabet_size; i++)
      bucket_end[i] = buckets[i+1]-1;

   // bitvector-less mod_induce_S
   induced_LMS_positions[0] = length;

   for(Int j = alphabet_size-1; j != (Int)-1; j--)
   {
      Int limit = buckets[j]-1;
      Int limit_S = bucket_start[j]; // >=

      for(Int i = buckets[j+1]-1; i != limit; i--)
      {
         Int string_index = sa[i] + 1;

         if(string_index >= 2)
         {
            string_index--;
            Char s1 = s[string_index];
            Char s2 = s[string_index-1];

            if(s2 < s1 || (s1 == s2 && i >= limit_S)) // if s2 is of type-S...
               sa[bucket_end[(Int) s2]--] = string_index - 1;
            else if(i >= limit_S) // else s2 is of type-L, but if the entry is in range of type-S then we have an LMS
               induced_LMS_positions[induced_cursor--] = string_index;
         }

         sa[i] = (Int)-1;
      }
   }

   sa[0] = -1;

   delete[] bucket_end;
   delete[] bucket_start;
}

/*
      tag_LMS_prefix
         This function progressively tags induced-sort LMS-prefixes/substrings
*/
template<typename Char, typename Int>
static Int tag_LMS_prefix(Char *s, Int *LMS_positions, Int *induced_LMS_positions, Int no_LMS, Int *sa, Int length)
{
   Int current_tag = (Int)-1;
   Int i = 1;

   // dump LMS-substring length
   for(Int k = 0; k < no_LMS-1; k++)
      sa[LMS_positions[k]] = LMS_positions[k+1] - LMS_positions[k];

   sa[LMS_positions[no_LMS-1]] = 0; // save the string lenght of the empty suffix

   while(i < no_LMS)
   {
      Int length_1 = sa[induced_LMS_positions[i-1]];
      Int length_2 = sa[induced_LMS_positions[i]];

      // save previous tag!!!
      sa[induced_LMS_positions[i-1]] = current_tag;

      if(length_1 != length_2)
         ++current_tag;

      else { // compare character by character...
         Int index_1 = induced_LMS_positions[i-1];
         Int index_2 = induced_LMS_positions[i];

         if(index_1 + length_1 == length || index_2 + length_1 == length)
            ++current_tag;

         else {
            for(Int k = 0; k <= length_1; k++)
            {
               if(s[index_1] != s[index_2])
               {
                  ++current_tag;
                  break;
               }

               ++index_1;
               ++index_2;
            }
         }
      }

      ++i;
   }

   sa[induced_LMS_positions[i-1]] = current_tag;

   return current_tag + 1;
}

// Implementation of interface functions

template<typename Char, typename Int>
void sais(Char *s, Int length, Int alphabet_size, Int *sa)
{
   Int * const buckets = new Int[alphabet_size+1];
   Int no_LMS;
   Int *LMS_positions, *induced_LMS_positions;
   Int alphabet_size_1;

   for(Int i = 0; i <= alphabet_size; i++)
      buckets[i] = 0;

   // scan for LMS characters and fill the bucket sizes
   scan_LS<Char,Int>(s, length, buckets, sa, no_LMS);

   // find the starting index of each bucket
   for(Int i = 0, acc = 1; i <= alphabet_size; i++)
   {
      Int prev = buckets[i];
      buckets[i] = acc;
      acc += prev;
   }

   // dump locations for the LMS characters and clear suffix array
   LMS_positions = new Int[no_LMS];
   induced_LMS_positions = new Int[no_LMS];

   std::memcpy(LMS_positions, &sa[length+1-no_LMS], sizeof(Int) * no_LMS);
   std::memset(sa, 0xFF, sizeof(Int) * (length+1)); // any word padded to 0xFF counts as a -1 :)

   // induce sort of LMS prefixes
   mod_place_LMS<Char,Int>(s, length, buckets, alphabet_size, sa, LMS_positions, induced_LMS_positions, no_LMS);

   // apply tags to build next suffix array
   alphabet_size_1 = tag_LMS_prefix(s, LMS_positions, induced_LMS_positions, no_LMS, sa, length);

   // if needed, recursively apply sais
   if(alphabet_size_1 + 1 != no_LMS)
   {
      Int * const LMS_prefix_tag = new Int[no_LMS-1];
      Int * const sa_1 = new Int[no_LMS];

      // populate the new string to build the recursive suffix array...
      for(Int i = 0; i < no_LMS-1; i++)
         LMS_prefix_tag[i] = sa[LMS_positions[i]];

      sais<Int,Int>(LMS_prefix_tag, no_LMS-1, alphabet_size_1, sa_1);

      // now induce sort of LMS-suffixes thanks to sa_1
      for(Int i = 0; i < no_LMS; i++)
         induced_LMS_positions[i] = LMS_positions[sa_1[i]];

      delete[] LMS_prefix_tag;
      delete[] sa_1;
   }

   for(Int i = 0; i < no_LMS; i++)
      sa[LMS_positions[i]] = (Int)-1;

   delete[] LMS_positions;

   place_LMS<Char,Int>(s, length, buckets, alphabet_size, sa, induced_LMS_positions, no_LMS);

   delete[] induced_LMS_positions;
   delete[] buckets;
}

template<typename Char, typename Int>
void bucket_index(Char *s, Int length, Int alphabet_size, Int *buckets)
{
   for(Int i = 0; i <= alphabet_size; i++)
      buckets[i] = 0;

   for(Int i = 0; i < length; i++)
      ++buckets[(Int)s[i]];

   for(Int i = 0, acc = 1; i <= alphabet_size; i++)
   {
      Int prev = buckets[i];
      buckets[i] = acc;
      acc += prev;
   }
}

template<typename Int>
void inverse_sa(Int *sa, Int *isa, Int length)
{
   for(Int i = 0; i <= length; i++)
      isa[sa[i]] = i;
}

template<typename Int>
void build_psi(Int *sa, Int *isa, Int *psi, Int length)
{
   for(Int i = 1; i <= length; i++)
      psi[i] = isa[sa[i] + 1];

   psi[0] = (Int)-1;
}

template<typename Char, typename Int>
void build_bwt(Char *s, Int *sa, Char *bwt, Int length, Int *dummy)
{
   Int i;

   for(i = 0; i <= length; i++)
   {
      if(sa[i])
         bwt[i] = s[sa[i] - 1];
      else
      {
         // this should be like "invalid Char" or terminator...
         *dummy = i;
         break;
      }
   }

   for(i = i+1; i <= length; i++)
      bwt[i] = s[sa[i] - 1];
}

// Static functions for flatten

// Bit Twiddling Hacks
// By Sean Eron Anderson
// seander@cs.stanford.edu
static inline std::size_t fill_with_ones(std::size_t v)
{
   // on x86-64, sizeof(std::size_t) = 8
   v |= v >> 1;
   v |= v >> 2;
   v |= v >> 4;
   v |= v >> 8;
   v |= v >> 16;
   v |= v >> 32;

   return v;
}

static inline std::size_t get_subroot(std::size_t N)
{
   /*
      Given the size of an array, N, you already know how a balanced binary search
      tree (bbst) is going to be shaped.
      NN is the size of the smallest bbst that contains N elements.
      Thus NN = 2^m-1 for some m.
      Moreover, NN > N, so if N is already a bbst, NN will be the same tree plus
      one more level.
      The concept is simple, and is just padding with 1s all the bits up to the
      msb that is set to 1.
   */
   std::size_t NN = fill_with_ones(N+1);

   /*
      NN >> 1 is the number of elements in a bbst safe for the last level, which
      is possibly incomplete.
      N - (NN >> 1) represents the number of elements that will reside in the last,
      and possibly incomplete, level of the bbst.
   */
   std::size_t rem = N - (NN >> 1);

   /*
      The remainder will be unevenly split between the left and right subtree of
      the bbst.
      The last level contains at most NN - (NN >> 1) elements.
      The left subtree contains at most half of them, (NN - (NN >> 1)) >> 1.
      The left subtree will thus contain NN >> 2 elements, which is the elements
      belonging to the complete subtree, + min(max_left_subtree, rem) in its last
      level.
   */
   std::size_t max_left_subtree = (NN ^ (NN >> 1)) >> 1;
   std::size_t offset = rem > max_left_subtree ? max_left_subtree : rem;

   return (NN >> 2) + offset;
}

template<typename Int>
void flatten(Int *v, Int *heap, std::size_t idx, std::size_t N)
{
   if(N == 0)
      return;

   std::size_t middle = get_subroot(N);

   heap[idx] = v[middle];

   flatten(v, heap, (idx << 1) + 1, middle);
   flatten(v + middle + 1, heap, (idx << 1) + 2, N - 1 - middle);
}

template<typename Char, typename Int>
void write_index(Char *bwt, Int length, Int alphabet_size, Int dummy, Int **indices)
{
   Int *idx = new Int[alphabet_size];

   for(Int i = 0; i < alphabet_size; i++)
      idx[i] = 0;

   for(Int i = 0; i <= length; i++)
      if(i != dummy)
      {
         Int aa = (Int) bwt[i];
         indices[aa][idx[aa]++] = i;
      }

   delete[] idx;
}

template<typename Char, typename Int>
void sampled_bwt(Char *bwt, Int length, Int alphabet_size, Int dummy, std::size_t s_rate, std::size_t bit_enc, std::size_t sample_size, std::uint8_t *blob)
{
   Int ch_count[alphabet_size];
   Int idx = 0;
   std::uint16_t dummy_ch = (1 << bit_enc) - 1;

   // size of the sample of ch_count to be copied at the beginning of the sampling window
   std::size_t ch_offset = sizeof(Int) * alphabet_size;

   for(Int i = 0; i < alphabet_size; i++)
      ch_count[i] = 0;

   Int no_iters = (length+1) / s_rate + ((length+1) % s_rate == 0 ? 0 : 1);

   for(Int i = 0; i < no_iters; i++)
   {
      // sample the vector of occurrences
      std::memcpy(blob, ch_count, ch_offset);

      std::uint16_t *ch = (std::uint16_t*)((std::uint8_t*)blob + ch_offset);
      int shift_left = 0;
      int hword = 0;
      ch[0] = 0;

      for(unsigned int j = 0; j < s_rate; j++)
      {
         std::uint16_t c;

         // account for character
         if(idx != dummy && idx <= length)
         {
            c = (Int) bwt[idx];
            ++ch_count[c];
         }
         else
            c = dummy_ch;

         // compress character into bitvector
         ch[hword] = ch[hword] | (c << shift_left);
         shift_left += bit_enc;

         if(shift_left >= 16 && j != s_rate - 1)
         {
            ++hword;
            shift_left -= 16;
            ch[hword] = c >> (bit_enc - shift_left);
         }

         ++idx;
      }

      // jump to the next sample
      blob += sample_size;
   }
}

#endif
