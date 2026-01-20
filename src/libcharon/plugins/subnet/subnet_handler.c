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

#include "subnet_handler.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <collections/linked_list.h>

typedef struct private_subnet_handler_t private_subnet_handler_t;

struct private_subnet_handler_t {

	subnet_handler_t public;

	linked_list_t *subnets;

	mutex_t *mutex;
};

typedef struct {
	ike_sa_id_t *id;
	traffic_selector_t *ts;
	uint8_t prefixlen;
	bool route_installed;
} entry_t;

static void entry_destroy(entry_t *this)
{
	this->id->destroy(this->id);
	this->ts->destroy(this->ts);
	free(this);
}

static traffic_selector_t *create_ts_from_subnet(chunk_t data, uint8_t *prefixlen)
{
	chunk_t addr;
	host_t *net;
	uint32_t netmask, mask;
	int prefix = 0;

	if (data.len < 8)
	{
		return NULL;
	}

	addr = chunk_create(data.ptr, 4);
	memcpy(&mask, data.ptr + 4, 4);
	netmask = ntohl(mask);

	while (netmask & 0x80000000)
	{
		prefix++;
		netmask <<= 1;
	}

	*prefixlen = prefix;

	net = host_create_from_chunk(AF_INET, addr, 0);
	if (!net)
	{
		return NULL;
	}

	return traffic_selector_create_from_subnet(net, prefix, 0, 0, 65535);
}

static bool add_subnet(private_subnet_handler_t *this, chunk_t data)
{
	traffic_selector_t *ts;
	ike_sa_t *ike_sa;
	entry_t *entry;
	uint8_t prefixlen;

	ike_sa = charon->bus->get_sa(charon->bus);
	if (!ike_sa)
	{
		return FALSE;
	}

	ts = create_ts_from_subnet(data, &prefixlen);
	if (!ts)
	{
		return FALSE;
	}

	DBG1(DBG_IKE, "received split-tunnel subnet: %R", ts);

	INIT(entry,
		.id = ike_sa->get_id(ike_sa),
		.ts = ts,
		.prefixlen = prefixlen,
		.route_installed = FALSE,
	);
	entry->id = entry->id->clone(entry->id);

	this->mutex->lock(this->mutex);
	this->subnets->insert_last(this->subnets, entry);
	this->mutex->unlock(this->mutex);

	return TRUE;
}

static void remove_subnet(private_subnet_handler_t *this, chunk_t data)
{
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	ike_sa_t *ike_sa;
	entry_t *entry;
	uint8_t prefixlen;

	ike_sa = charon->bus->get_sa(charon->bus);
	if (!ike_sa)
	{
		return;
	}

	ts = create_ts_from_subnet(data, &prefixlen);
	if (!ts)
	{
		return;
	}

	this->mutex->lock(this->mutex);
	enumerator = this->subnets->create_enumerator(this->subnets);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->id->equals(entry->id, ike_sa->get_id(ike_sa)) &&
			ts->equals(ts, entry->ts))
		{
			this->subnets->remove_at(this->subnets, enumerator);
			entry_destroy(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	ts->destroy(ts);
}

METHOD(attribute_handler_t, handle, bool,
	private_subnet_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	switch (type)
	{
		case INTERNAL_IP4_SUBNET:
			return add_subnet(this, data);
		default:
			return FALSE;
	}
}

METHOD(attribute_handler_t, release, void,
	private_subnet_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	switch (type)
	{
		case INTERNAL_IP4_SUBNET:
			remove_subnet(this, data);
			break;
		default:
			break;
	}
}

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t *,
	subnet_handler_t *this, ike_sa_t *ike_sa, linked_list_t *vips)
{
	return enumerator_create_empty();
}

typedef struct {
	enumerator_t public;
	private_subnet_handler_t *handler;
	enumerator_t *inner;
	ike_sa_id_t *id;
} include_enumerator_t;

METHOD(enumerator_t, include_enumerate, bool,
	include_enumerator_t *this, va_list args)
{
	entry_t *entry;
	traffic_selector_t **ts;
	uint8_t *prefixlen;

	VA_ARGS_VGET(args, ts, prefixlen);

	while (this->inner->enumerate(this->inner, &entry))
	{
		if (this->id->equals(this->id, entry->id))
		{
			*ts = entry->ts;
			if (prefixlen)
			{
				*prefixlen = entry->prefixlen;
			}
			return TRUE;
		}
	}
	return FALSE;
}

METHOD(enumerator_t, include_enumerator_destroy, void,
	include_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	this->handler->mutex->unlock(this->handler->mutex);
	free(this);
}

METHOD(subnet_handler_t, create_include_enumerator, enumerator_t*,
	private_subnet_handler_t *this, ike_sa_id_t *id)
{
	include_enumerator_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _include_enumerate,
			.destroy = _include_enumerator_destroy,
		},
		.handler = this,
		.id = id,
	);

	this->mutex->lock(this->mutex);
	enumerator->inner = this->subnets->create_enumerator(this->subnets);

	return &enumerator->public;
}

METHOD(subnet_handler_t, destroy, void,
	private_subnet_handler_t *this)
{
	this->subnets->destroy_function(this->subnets, (void*)entry_destroy);
	this->mutex->destroy(this->mutex);
	free(this);
}

subnet_handler_t *subnet_handler_create(void)
{
	private_subnet_handler_t *this;

	INIT(this,
		.public = {
			.handler = {
				.handle = _handle,
				.release = _release,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.create_include_enumerator = _create_include_enumerator,
			.destroy = _destroy,
		},
		.subnets = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
