#ifndef USER_SESSION_H
#define USER_SESSION_H

#include <memory>

#include "subtol_config.h"
#include "contexts/subtol_context.h"

// I used unique_ptr to automatically free memory when the entry is deleted from the user_sessions
struct user_session_t {
	subtol_config_t cfg;
	std::unique_ptr<subtol_context_t> ctx;
	int status;
	bool busy; // if true, a pending operation is in execution
	
	user_session_t() {
		status = 1;
		busy = false;		
	}
	
	~user_session_t() { }
	
	user_session_t(const user_session_t&) = delete;
	user_session_t& operator=(const user_session_t&) = delete;
	
	user_session_t(user_session_t &&o)
	{
		cfg = o.cfg;
		status = o.status;
		busy = o.busy;
		ctx = std::move(o.ctx);
		
		o.status = 1;
		o.busy = false;
	}
	
	user_session_t& operator=(user_session_t &&o)
	{
		cfg = o.cfg;
		status = o.status;
		busy = o.busy;
		ctx = std::move(o.ctx);
		
		o.status = 1;
		o.busy = false;
		
		return *this;
	}
	
};

/*
	user_session_t.status conventions
	
	status = 1 => clean session
	status = 2 => cfg provided
	status = 3 => context built
*/

#endif // USER_SESSION_H
