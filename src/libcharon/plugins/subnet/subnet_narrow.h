/*
 * Copyright (C) 2026 Quanza
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup subnet_narrow subnet_narrow
 * @{ @ingroup subnet
 */

#ifndef SUBNET_NARROW_H_
#define SUBNET_NARROW_H_

#include "subnet_handler.h"

#include <bus/listeners/listener.h>

typedef struct subnet_narrow_t subnet_narrow_t;

/**
 * Listener to narrow traffic selectors based on received INTERNAL_IP4_SUBNET.
 *
 * This listener hooks into the CHILD_SA negotiation and replaces the remote
 * traffic selectors with the split-tunnel subnets received from the server.
 */
struct subnet_narrow_t {

	/**
	 * Implements listener_t.narrow.
	 */
	listener_t listener;

	/**
	 * Destroy a subnet_narrow_t.
	 */
	void (*destroy)(subnet_narrow_t *this);
};

/**
 * Create a subnet_narrow instance.
 *
 * @param handler		subnet_handler to get received subnets from
 * @return				subnet_narrow instance
 */
subnet_narrow_t *subnet_narrow_create(subnet_handler_t *handler);

#endif /** SUBNET_NARROW_H_ @}*/
