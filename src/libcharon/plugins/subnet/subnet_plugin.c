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

#include "subnet_plugin.h"
#include "subnet_handler.h"
#include "subnet_narrow.h"

#include <daemon.h>

typedef struct private_subnet_plugin_t private_subnet_plugin_t;

struct private_subnet_plugin_t {

	subnet_plugin_t public;

	subnet_handler_t *handler;

	subnet_narrow_t *narrower;
};

METHOD(plugin_t, get_name, char*,
	private_subnet_plugin_t *this)
{
	return "subnet";
}

static bool plugin_cb(private_subnet_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		charon->attributes->add_handler(charon->attributes,
										&this->handler->handler);
		charon->bus->add_listener(charon->bus, &this->narrower->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->narrower->listener);
		charon->attributes->remove_handler(charon->attributes,
										   &this->handler->handler);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_subnet_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "subnet"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_subnet_plugin_t *this)
{
	this->narrower->destroy(this->narrower);
	this->handler->destroy(this->handler);
	free(this);
}

PLUGIN_DEFINE(subnet)
{
	private_subnet_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.handler = subnet_handler_create(),
	);

	this->narrower = subnet_narrow_create(this->handler);

	return &this->public.plugin;
}
