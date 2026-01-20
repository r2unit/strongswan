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

#include "subnet_narrow.h"

#include <daemon.h>

typedef struct private_subnet_narrow_t private_subnet_narrow_t;

struct private_subnet_narrow_t {

	subnet_narrow_t public;

	subnet_handler_t *handler;
};

static void install_routes(private_subnet_narrow_t *this, ike_sa_t *ike_sa)
{
	enumerator_t *enumerator, *vip_enum;
	traffic_selector_t *ts;
	host_t *vip = NULL, *me;
	char *if_name = NULL;
	uint8_t prefixlen;
	chunk_t dst_net;
	int count = 0;

	vip_enum = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);
	if (!vip_enum->enumerate(vip_enum, &vip))
	{
		vip_enum->destroy(vip_enum);
		DBG1(DBG_IKE, "no VIP available for split-tunnel routes");
		return;
	}
	vip_enum->destroy(vip_enum);

	me = ike_sa->get_my_host(ike_sa);
	if (me)
	{
		charon->kernel->get_interface(charon->kernel, me, &if_name);
	}

	enumerator = this->handler->create_include_enumerator(this->handler,
											ike_sa->get_id(ike_sa));
	while (enumerator->enumerate(enumerator, &ts, &prefixlen))
	{
		dst_net = ts->get_from_address(ts);

		if (charon->kernel->add_route(charon->kernel, dst_net, prefixlen,
									  NULL, vip, if_name, FALSE) == SUCCESS ||
			charon->kernel->add_route(charon->kernel, dst_net, prefixlen,
									  NULL, vip, if_name, FALSE) == ALREADY_DONE)
		{
			count++;
		}
	}
	enumerator->destroy(enumerator);

	free(if_name);

	DBG1(DBG_IKE, "installed %d split-tunnel routes via %H", count, vip);
}

static void remove_routes(private_subnet_narrow_t *this, ike_sa_t *ike_sa)
{
	enumerator_t *enumerator, *vip_enum;
	traffic_selector_t *ts;
	host_t *vip = NULL, *me;
	char *if_name = NULL;
	uint8_t prefixlen;
	chunk_t dst_net;
	int count = 0;

	vip_enum = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);
	if (!vip_enum->enumerate(vip_enum, &vip))
	{
		vip_enum->destroy(vip_enum);
		return;
	}
	vip_enum->destroy(vip_enum);

	me = ike_sa->get_my_host(ike_sa);
	if (me)
	{
		charon->kernel->get_interface(charon->kernel, me, &if_name);
	}

	enumerator = this->handler->create_include_enumerator(this->handler,
											ike_sa->get_id(ike_sa));
	while (enumerator->enumerate(enumerator, &ts, &prefixlen))
	{
		dst_net = ts->get_from_address(ts);
		charon->kernel->del_route(charon->kernel, dst_net, prefixlen,
								  NULL, vip, if_name, FALSE);
		count++;
	}
	enumerator->destroy(enumerator);

	free(if_name);

	DBG1(DBG_IKE, "removed %d split-tunnel routes", count);
}

METHOD(listener_t, child_updown, bool,
	private_subnet_narrow_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	bool up)
{
	if (ike_sa->get_version(ike_sa) == IKEV2 &&
		ike_sa->has_condition(ike_sa, COND_ORIGINAL_INITIATOR))
	{
		if (up)
		{
			install_routes(this, ike_sa);
		}
		else
		{
			remove_routes(this, ike_sa);
		}
	}
	return TRUE;
}

METHOD(listener_t, narrow, bool,
	private_subnet_narrow_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	narrow_hook_t type, linked_list_t *local, linked_list_t *remote)
{
	return TRUE;
}

METHOD(subnet_narrow_t, destroy, void,
	private_subnet_narrow_t *this)
{
	free(this);
}

subnet_narrow_t *subnet_narrow_create(subnet_handler_t *handler)
{
	private_subnet_narrow_t *this;

	INIT(this,
		.public = {
			.listener = {
				.narrow = _narrow,
				.child_updown = _child_updown,
			},
			.destroy = _destroy,
		},
		.handler = handler,
	);

	return &this->public;
}
