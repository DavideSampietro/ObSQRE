#ifndef FLEXIBLE_ARRAY_HPP
#define FLEXIBLE_ARRAY_HPP

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>

// mock C++ STL by defining allocator-like class
// this is used to allocate in the proper memory portion, which may either
// belong to SGX protected memory of host (unprotected) memory
class m_allocator {
public:
	void* allocate(std::size_t s) {
		return std::malloc(s);
	}

	void deallocate(void *ptr) {
		std::free(ptr);
	}
};

template<typename T, class alloc = m_allocator>
class flexible_array {
private:
	std::uint8_t *raw_mem;
	std::size_t Tsize;
	std::size_t capacity;

	alloc mem;

public:
	// constructors
	flexible_array(const alloc &a = alloc());
	flexible_array(std::size_t n, std::size_t el_size, const alloc &a = alloc());
	flexible_array(const flexible_array &o);
	flexible_array(flexible_array &&o);

	// destructor
	~flexible_array();

	void set_entry_size(std::size_t el_size);

	std::size_t size() const {
		return capacity;
	}

	void reserve(std::size_t n);
	void clear();

	// implicitly inlined
	T& operator[](int idx) {
		T *ptr = (T*)(raw_mem + idx * Tsize);
		return *ptr;
	}
};

template<typename T, class alloc>
inline
flexible_array<T, alloc>::flexible_array(const alloc &a): mem(a)
{
	raw_mem = nullptr;
	Tsize = sizeof(T);
	capacity = 0;
}

template<typename T, class alloc>
inline
flexible_array<T, alloc>::flexible_array(std::size_t n, std::size_t el_size, const alloc &a): mem(a)
{
	raw_mem = nullptr;
	Tsize = el_size;
	capacity = 0;

	reserve(n);
}

template<typename T, class alloc>
inline
flexible_array<T, alloc>::flexible_array(const flexible_array<T, alloc> &o): mem(o.mem) // copy construct allocator
{
	Tsize = o.Tsize;
	capacity = o.capacity;
	raw_mem = (std::uint8_t*) mem.allocate(Tsize * capacity);
	std::memcpy(raw_mem, o.raw_mem, Tsize * capacity);
}

template<typename T, class alloc>
inline
flexible_array<T, alloc>::flexible_array(flexible_array<T, alloc> &&o): mem(std::move(o.mem)) // move construct allocator
{
	raw_mem = o.raw_mem;
	Tsize = o.Tsize;
	capacity = o.capacity;

	o.raw_mem = nullptr;
	o.capacity = 0;
}

template<typename T, class alloc>
inline
void flexible_array<T, alloc>::set_entry_size(std::size_t el_size)
{
	if(raw_mem != nullptr)
	{
		mem.deallocate(raw_mem);
		raw_mem = nullptr;
	}

	std::size_t old_capacity = capacity;
	capacity = 0;
	Tsize = el_size;

	reserve(old_capacity);
}

template<typename T, class alloc>
inline
void flexible_array<T, alloc>::reserve(std::size_t n)
{
	if(n > capacity && n > 0)
	{
		std::uint8_t *raw_mem_next = (std::uint8_t*) mem.allocate(n * Tsize);

		if(raw_mem != nullptr)
		{
			std::memcpy(raw_mem_next, raw_mem, Tsize * capacity);
			mem.deallocate(raw_mem);
		}

		raw_mem = raw_mem_next;
		capacity = n;
	}
}

template<typename T, class alloc>
inline
void flexible_array<T, alloc>::clear()
{
	if(raw_mem != nullptr)
	{
		mem.deallocate(raw_mem);
		raw_mem = nullptr;
		capacity = 0;
	}
}

template<typename T, class alloc>
inline
flexible_array<T, alloc>::~flexible_array()
{
	if(raw_mem != nullptr)
		mem.deallocate(raw_mem);
}

#endif // FLEXIBLE_ARRAY_HPP
