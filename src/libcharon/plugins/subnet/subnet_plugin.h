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
 * @defgroup subnet subnet
 * @ingroup cplugins
 *
 * @defgroup subnet_plugin subnet_plugin
 * @{ @ingroup subnet
 */

#ifndef SUBNET_PLUGIN_H_
#define SUBNET_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct subnet_plugin_t subnet_plugin_t;

/**
 * IKEv2 split-tunnel plugin using INTERNAL_IP4_SUBNET attributes.
 *
 * This plugin handles INTERNAL_IP4_SUBNET configuration attributes received
 * from IKEv2 peers and uses them to narrow CHILD_SA traffic selectors,
 * implementing split-tunnel functionality for IKEv2.
 *
 * The plugin is the IKEv2 equivalent of the unity plugin's split-tunnel
 * handling for IKEv1 with Cisco extensions.
 */
struct subnet_plugin_t {

	/**
	 * Implements plugin_t.
	 */
	plugin_t plugin;
};

#endif /** SUBNET_PLUGIN_H_ @}*/
