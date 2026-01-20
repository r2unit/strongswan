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
 * @defgroup subnet_handler subnet_handler
 * @{ @ingroup subnet
 */

#ifndef SUBNET_HANDLER_H_
#define SUBNET_HANDLER_H_

#include <sa/ike_sa_id.h>
#include <attributes/attribute_handler.h>

typedef struct subnet_handler_t subnet_handler_t;

/**
 * IKEv2 INTERNAL_IP4_SUBNET attribute handling for split-tunneling.
 *
 * This handler receives INTERNAL_IP4_SUBNET attributes from the IKEv2
 * Configuration Payload and stores them for use by the subnet_narrow
 * listener to narrow traffic selectors.
 */
struct subnet_handler_t {

	/**
	 * Implements attribute_handler_t.
	 */
	attribute_handler_t handler;

	/**
	 * Create an enumerator over subnets received for an IKE_SA.
	 *
	 * @param id			IKE_SA ID to get subnets for
	 * @return				enumerator over traffic_selector_t*
	 */
	enumerator_t* (*create_include_enumerator)(subnet_handler_t *this,
											   ike_sa_id_t *id);

	/**
	 * Destroy a subnet_handler_t.
	 */
	void (*destroy)(subnet_handler_t *this);
};

/**
 * Create a subnet_handler instance.
 */
subnet_handler_t *subnet_handler_create(void);

#endif /** SUBNET_HANDLER_H_ @}*/
