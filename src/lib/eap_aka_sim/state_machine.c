/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * @file src/lib/eap_aka_sim/state_machine.c
 * @brief Implement a common state machine for EAP-SIM, EAP-AKA, EAP-AKA'.
 *
 * @author Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS \<info@networkradius.com\>
 */
RCSID("$Id$")

#ifndef EAP_TLS_MPPE_KEY_LEN
#  define EAP_TLS_MPPE_KEY_LEN     32
#endif

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/unlang/module.h>

#include "base.h"
#include "state_machine.h"
#include "sim_attrs.h"

/** A state transition function
 *
 * This is passed to sub-state machines that perform other actions, before
 * fully transitioning to a new state.
 *
 * Examples of these are the sub-state machines that deal with clearing
 * pseudonyms and reauthentication data.
 */
typedef rlm_rcode_t(*aka_sim_state_enter_t)(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session);

static rlm_rcode_t common_eap_failure(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t common_failure_notification(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t common_eap_success(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t common_success_notification(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t aka_reauthentication(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t aka_challenge(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t common_identity(void *instance, void *thread, REQUEST *request);

static rlm_rcode_t common_failure_notification_enter(eap_aka_sim_state_conf_t *inst,
						     REQUEST *request, eap_session_t *eap_session);
static rlm_rcode_t aka_challenge_enter(eap_aka_sim_state_conf_t *inst,
				       REQUEST *request, eap_session_t *eap_session);
static rlm_rcode_t common_identity_enter(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session);

static module_state_func_table_t const aka_state_table[] = {
	{ "FAILURE-NOTIFICATION",	common_failure_notification	},
	{ "EAP-FAILURE",		common_eap_failure		},
	{ "SUCCESS-NOTIFICATION",	common_success_notification 	},
	{ "EAP-SUCCESS",		common_eap_success		},
	{ "AKA-REAUTHENTICATION",	aka_reauthentication		},
	{ "AKA-CHALLENGE",		aka_challenge			},
	{ "IDENTITY",			common_identity			},
	{ "EAP-IDENTITY",		aka_sim_state_machine_start	},

	{ NULL }
};

/** Cancel a call to a submodule
 *
 * @param[in] instance	UNUSED.
 * @param[in] thread	UNUSED.
 * @param[in] request	The current request.
 * @param[in] rctx	the eap_session_t
 * @param[in] action	to perform.
 */
static void mod_signal(UNUSED void *instance, UNUSED void *thread, REQUEST *request, UNUSED void *rctx,
		       fr_state_signal_t action)
{
	eap_session_t	*eap_session = eap_session_get(request->parent);

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Request cancelled - Destroying EAP-AKA session");

	TALLOC_FREE(eap_session->opaque);
}

/** Warn the user that the rcode they provided is being ignored in this section
 *
 */
static inline void section_rcode_ignored(REQUEST *request)
{
	switch (request->rcode) {
	case RLM_MODULE_USER_SECTION_REJECT:
		RWDEBUG("Ignoring rcode (%s)",
			fr_int2str(mod_rcode_table, request->rcode, "<invalid>"));
		break;

	default:
		break;
	}
}

/** Trigger a state transition to FAILURE-NOTIFICATION if the section returned a failure code
 *
 */
#define section_rcode_process(_inst, _request, _eap_session) \
{ \
	switch ((_request)->rcode) { \
	case RLM_MODULE_USER_SECTION_REJECT: \
		REDEBUG("Section rcode (%s) indicates we should reject the user", \
		        fr_int2str(rcode_table, request->rcode, "<INVALID>")); \
		return common_failure_notification_enter(_inst, _request, _eap_session); \
	default: \
		break; \
	} \
}

/** Sync up what we're requesting with attributes in the reply
 *
 */
static bool id_req_set_by_user(REQUEST *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	VALUE_PAIR 	*vp;
	fr_cursor_t	cursor;
	bool		set_by_user = false;

	/*
	 *	Check if the user included any of the
	 *      ID req attributes.  If they did, use
	 *	them to inform what we do next, and
	 *	then delete them so they don't screw
	 *	up any of the other code.
	 */
	for (vp = fr_cursor_init(&cursor, &request->reply->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da == attr_eap_aka_sim_permanent_id_req) {
			eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
		found:
			set_by_user = true;
			RDEBUG2("Previous section added &reply:%pP, will request additional identity (%s)",
				vp, fr_int2str(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
			fr_cursor_free_item(&cursor);
		}
		else if (vp->da == attr_eap_aka_sim_fullauth_id_req) {
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
			goto found;
		}
		else if (vp->da == attr_eap_aka_sim_any_id_req) {
			eap_aka_sim_session->id_req = AKA_SIM_ANY_ID_REQ;
			goto found;
		}
	}

	return set_by_user;
}

static void id_hint_pairs_add(REQUEST *request, char const *identity)
{
	fr_aka_sim_id_type_t	type;
	fr_aka_sim_method_hint_t	method;

	/*
	 *	Process the identity that we received.
	 */
	if (fr_aka_sim_id_type(&type, &method,
			   identity, talloc_array_length(identity) - 1) < 0) {
		RPWDEBUG2("Failed parsing identity, continuing anyway");
	}

	/*
	 *	Map the output from the generic ID parser
	 *	function to specific EAP-AKA internal
	 *	attributes in the subrequest.
	 */
	if (type != AKA_SIM_ID_TYPE_UNKNOWN) {
		VALUE_PAIR *vp = NULL;

		MEM(pair_update_request(&vp, attr_eap_aka_sim_identity_type) >= 0);
		switch (type) {
		case AKA_SIM_ID_TYPE_PERMANENT:
			vp->vp_uint32 = FR_IDENTITY_TYPE_VALUE_PERMANENT;
			break;

		case AKA_SIM_ID_TYPE_PSEUDONYM:
			vp->vp_uint32 = FR_IDENTITY_TYPE_VALUE_PSEUDONYM;
			break;

		case AKA_SIM_ID_TYPE_FASTAUTH:
			vp->vp_uint32 = FR_IDENTITY_TYPE_VALUE_FASTAUTH;
			break;

		default:
			rad_assert(0);
		}
	}

	/*
	 *	Map the output from the generic ID parser
	 *	function to specific EAP-AKA internal
	 *	attributes in the subrequest.
	 */
	if (method != AKA_SIM_METHOD_HINT_UNKNOWN) {
		VALUE_PAIR *vp = NULL;

		MEM(pair_update_request(&vp, attr_eap_aka_sim_method_hint) >= 0);
		switch (method) {
		case AKA_SIM_METHOD_HINT_AKA_PRIME:
			vp->vp_uint32 = FR_METHOD_HINT_VALUE_AKA_PRIME;
			break;

		case AKA_SIM_METHOD_HINT_AKA:
			vp->vp_uint32 = FR_METHOD_HINT_VALUE_AKA;
			break;

		case AKA_SIM_METHOD_HINT_SIM:
			vp->vp_uint32 = FR_METHOD_HINT_VALUE_SIM;
			break;

		default:
			rad_assert(0);
		}
	}
}

/** Copy the incoming identity to the permanent identity attribute
 *
 * If the incoming ID really looks like a permanent ID, and we were
 * told it was a permanent ID, then trim the first byte to form the
 * real permanent ID.
 *
 * Adds &session-state:Permanent-Id.
 *
 * @param[in] request	The current request.
 * @param[in] in	current identity.
 * @param[in] eap_type	The current eap_type.
 */
static int id_to_permanent_id(REQUEST *request, VALUE_PAIR *in, eap_type_t eap_type)
{
	fr_aka_sim_id_type_t		our_type;
	fr_aka_sim_method_hint_t	our_method, expected_method;

	if (in->vp_length == 0) {
		REDEBUG2("Not processing zero length identity");
		return -1;
	}

	if (fr_pair_find_by_da(request->state, attr_eap_aka_sim_permanent_id, TAG_ANY)) {
		REDEBUG2("Not overriding &session-state:%s set by policy",
			 attr_eap_aka_sim_permanent_id->name);
		return -1;
	}

	switch (eap_type) {
	case FR_EAP_METHOD_SIM:
		expected_method = AKA_SIM_METHOD_HINT_SIM;
		break;

	case FR_EAP_METHOD_AKA:
		expected_method = AKA_SIM_METHOD_HINT_AKA;
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		expected_method = AKA_SIM_METHOD_HINT_AKA_PRIME;
		break;

	default:
		return -1;
	}

	/*
	 *	First, lets see if this looks like an identity
	 *	we can process.
	 *
	 *	For now we allow all permanent identities no
	 *	matter what EAP method.
	 *
	 *	This is because we could be starting a different
	 *	EAP method to the one the identity hinted,
	 *	but we still want to strip the first byte.
	 */
	if ((fr_aka_sim_id_type(&our_type, &our_method, in->vp_strvalue, in->vp_length) < 0) ||
	    (our_type != AKA_SIM_ID_TYPE_PERMANENT)) {
		VALUE_PAIR *vp;

		RDEBUG2("&%s has incorrect hint byte, expected '%c', got '%c', "
			"copying identity to &session-state:%s verbatim without stripping",
			in->da->name,
			fr_aka_sim_hint_byte(AKA_SIM_ID_TYPE_PERMANENT, expected_method),
			fr_aka_sim_hint_byte(our_type, our_method),
			attr_eap_aka_sim_permanent_id->name);

		MEM(fr_pair_add_by_da(request->state_ctx, &vp, &request->state, attr_eap_aka_sim_permanent_id) >= 0);
		fr_pair_value_copy(vp, in);
	} else {
		VALUE_PAIR *vp;

		/*
		 *	To get here the identity must be >= 1 and must have
		 *      had the expected hint byte.
		 *
		 *	Strip off the hint byte, and then add the permanent
		 *	identity to the output list.
		 */
		MEM(fr_pair_add_by_da(request->state_ctx, &vp, &request->state, attr_eap_aka_sim_permanent_id) >= 0);
		fr_pair_value_bstrncpy(vp, in->vp_strvalue + 1, in->vp_length - 1);

		RDEBUG2("Stripping identity hint and copying &%s to &session-state:%pP", in->da->name, vp);
	}

	return 0;
}

/** Called after 'store session { ... }'
 *
 */
static rlm_rcode_t session_store_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;

	switch (request->rcode) {
	/*
	 *	Store failed.  Don't send fastauth id
	 */
	case RLM_MODULE_USER_SECTION_REJECT:
		pair_delete_reply(attr_eap_aka_sim_next_reauth_id);
		break;

	default:
		break;
	}

	pair_delete_request(attr_eap_aka_sim_next_reauth_id);

	return state_enter(instance, request, eap_session_get(request->parent));
}

/** Called after 'store pseudonym { ... }'
 *
 */
static rlm_rcode_t pseudonym_store_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	eap_aka_sim_state_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;
	VALUE_PAIR		*vp;
	VALUE_PAIR		*new;

	switch (request->rcode) {
	/*
	 *	Store failed.  Don't send pseudonym
	 */
	case RLM_MODULE_USER_SECTION_REJECT:
		pair_delete_reply(attr_eap_aka_sim_next_pseudonym);
		break;

	default:
		break;
	}

	request->rcode = RLM_MODULE_NOOP;	/* Needed because we may call resume functions directly */

	pair_delete_request(attr_eap_aka_sim_next_pseudonym);

	vp = fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_next_reauth_id, TAG_ANY);
	if (vp) {
		/*
		 *	Generate a random fastauth string
		 */
		if (vp->vp_length == 0) {
			char *identity;

			if (!inst->ephemeral_id_length) {
				RWDEBUG("Found empty Next-Reauth-Id, and told not to generate one.  "
					"Skipping store session { ... } section");

				goto done;
			}

			MEM(identity = talloc_array(vp, char, inst->ephemeral_id_length + 2));
			switch (eap_aka_sim_session->type) {
			case FR_EAP_METHOD_AKA_PRIME:
				identity[0] = (char)ID_TAG_AKA_PRIME_FASTAUTH;
				break;

			case FR_EAP_METHOD_AKA:
			 	identity[0] = (char)ID_TAG_AKA_FASTAUTH;
				break;

			default:
				break;
			}
			fr_rand_str((uint8_t *)identity + 1, inst->ephemeral_id_length, 'a');
			identity[talloc_array_length(identity) - 1] = '\0';

			fr_value_box_strdup_buffer_shallow(NULL, &vp->data, NULL, identity, false);
		}
		pair_update_request(&new, attr_session_id);
		fr_pair_value_copy(new, vp);

		MEM(eap_aka_sim_session->fastauth_sent = talloc_bstrndup(eap_aka_sim_session,
								     vp->vp_strvalue, vp->vp_length));

		switch (eap_aka_sim_session->type) {
		/*
		 *	AKA and SIM use the original MK for session resumption.
		 */
		case FR_EAP_METHOD_SIM:
		case FR_EAP_METHOD_AKA:
			MEM(pair_update_session_state(&vp, attr_session_data) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.mk,
					     sizeof(eap_aka_sim_session->keys.mk), false);
			break;
		/*
		 *	AKA' KDF 1 generates an additional key k_re
		 *	which is used for reauthentication instead
		 *	of the MK.
		 */
		case FR_EAP_METHOD_AKA_PRIME:
			MEM(pair_update_session_state(&vp, attr_session_data) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.k_re,
					     sizeof(eap_aka_sim_session->keys.k_re), false);
			break;

		default:
			rad_assert(0);
			break;
		}

		/*
		 *	If the counter already exists in session
		 *	state increment by 1, otherwise, add the
		 *	attribute and set to zero.
		 */
		vp = fr_pair_find_by_da(request->state, attr_eap_aka_sim_counter, TAG_ANY);
		if (vp) {
			vp->vp_uint16++;
		/*
		 *	Will get incremented by 1 in
		 *	reauthentication_send, so when
		 *	used, it'll be 1 (as per the standard).
		 */
		} else {
			MEM(pair_add_session_state(&vp, attr_eap_aka_sim_counter) >= 0);
			vp->vp_uint16 = 0;
		}

		return unlang_module_yield_to_section(request,
						      inst->actions.store_session,
						      RLM_MODULE_NOOP,
						      session_store_resume,
						      mod_signal,
						      rctx);
	}

done:
	return state_enter(inst, request, eap_session_get(request->parent));
}

/** Implements a set of states for storing pseudonym and fastauth identities
 *
 * At the end of challenge or reauthentication rounds, the user may have specified
 * a pseudonym and fastauth identity to return to the supplicant.
 *
 * Call the appropriate sections to persist those values.
 *
 * @param[in] inst		of rlm_eap_aka.
 * @param[in] request		the current request.
 * @param[in] state_enter	state entry function for the
 *				state to transition to *after* the current
 *				state.
 * @return RLM_MODULE_HANDLED.
 */
static rlm_rcode_t session_and_pseudonym_store(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session,
					       aka_sim_state_enter_t state_enter)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*vp;
	VALUE_PAIR		*new;

	request->rcode = RLM_MODULE_NOOP;	/* Needed because we may call resume functions directly */

	vp = fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_next_pseudonym, TAG_ANY);
	if (vp) {
		/*
		 *	Generate a random pseudonym string
		 */
		if (vp->vp_length == 0) {
			char *identity;

			if (!inst->ephemeral_id_length) {
				RWDEBUG("Found empty Pseudonym-Id, and told not to generate one.  "
					"Skipping store pseudonym { ... } section");

				return pseudonym_store_resume(inst,
							      module_thread_by_data(inst),
							      request, (void *)state_enter);
			}

			MEM(identity = talloc_array(vp, char, inst->ephemeral_id_length + 2));
			fr_rand_str((uint8_t *)identity + 1, inst->ephemeral_id_length, 'a');
			switch (eap_aka_sim_session->type) {
			case FR_EAP_METHOD_AKA_PRIME:
				identity[0] = (char)ID_TAG_AKA_PRIME_PSEUDONYM;
				break;

			case FR_EAP_METHOD_AKA:
			 	identity[0] = (char)ID_TAG_AKA_PSEUDONYM;
				break;

			default:
				break;
			}
			identity[talloc_array_length(identity) - 1] = '\0';
			fr_value_box_strdup_buffer_shallow(NULL, &vp->data, NULL, identity, false);
		}
		pair_update_request(&new, attr_eap_aka_sim_next_pseudonym);
		fr_pair_value_copy(new, vp);

		MEM(eap_aka_sim_session->pseudonym_sent = talloc_bstrndup(eap_aka_sim_session,
								      vp->vp_strvalue, vp->vp_length));

		return unlang_module_yield_to_section(request,
						      inst->actions.store_pseudonym,
						      RLM_MODULE_NOOP,
						      pseudonym_store_resume,
						      mod_signal,
						      state_enter);
	}

	return pseudonym_store_resume(inst, module_thread_by_data(inst), request, (void *)state_enter);
}

/** Called after 'clear session { ... }'
 *
 */
static rlm_rcode_t session_clear_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;

	pair_delete_request(attr_session_id);

	return state_enter(instance, request, eap_session_get(request->parent));
}

/** Called after 'clear pseudonym { ... }'
 *
 */
static rlm_rcode_t pseudonym_clear_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	eap_aka_sim_state_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;

	pair_delete_request(attr_eap_aka_sim_next_pseudonym);

	/*
	 *	Clear session
	 */
	if (eap_aka_sim_session->fastauth_sent) {
		VALUE_PAIR *vp;

		pair_delete_request(attr_session_id);

		MEM(pair_update_request(&vp, attr_session_id) >= 0);
		fr_value_box_strdup_buffer(vp, &vp->data, NULL, eap_aka_sim_session->fastauth_sent, true);
		TALLOC_FREE(eap_aka_sim_session->fastauth_sent);

		return unlang_module_yield_to_section(request,
						      inst->actions.clear_session,
						      RLM_MODULE_NOOP,
						      session_clear_resume,
						      mod_signal,
						      rctx);
	}

	return state_enter(inst, request, eap_session_get(request->parent));
}

/** Implements a set of states for clearing out pseudonym and fastauth identities
 *
 * If either a Challenge round or Reauthentication round fail, we need to clear
 * any identities that were provided during those rounds, as the supplicant
 * will have discarded them.
 *
 * @param[in] inst		of rlm_eap_aka.
 * @param[in] request		the current request.
 * @param[in] state_enter	state entry function for the
 *				state to transition to *after* the current
 *				state.
 * @return RLM_MODULE_HANDLED.
 */
static rlm_rcode_t session_and_pseudonym_clear(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session,
					       aka_sim_state_enter_t state_enter)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	/*
	 *	Clear out pseudonyms
	 */
	if (eap_aka_sim_session->pseudonym_sent) {
		VALUE_PAIR *vp;

		MEM(pair_update_request(&vp, attr_eap_aka_sim_next_pseudonym) >= 0);
		fr_value_box_strdup_buffer(vp, &vp->data, NULL, eap_aka_sim_session->pseudonym_sent, true);
		TALLOC_FREE(eap_aka_sim_session->pseudonym_sent);

		return unlang_module_yield_to_section(request,
						      inst->actions.clear_pseudonym,
						      RLM_MODULE_NOOP,
						      session_clear_resume,
						      mod_signal,
						      (void *)state_enter);
	}

	return pseudonym_clear_resume(inst, module_thread_by_data(inst), request, (void *)state_enter);
}

/** Encode EAP-AKA attributes
 *
 */
static int aka_encode(REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	fr_cursor_t		cursor;
	fr_cursor_t		to_encode;
	VALUE_PAIR		*head = NULL, *vp;
	ssize_t			ret;
	fr_aka_sim_encode_ctx_t	encoder_ctx = {
					.root = fr_dict_root(dict_eap_aka_sim),
					.keys = &eap_aka_sim_session->keys,

					.iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					.iv_included = false,

					.hmac_md = eap_aka_sim_session->mac_md,
					.eap_packet = eap_session->this_round->request,
					.hmac_extra = NULL,
					.hmac_extra_len = 0
				};

	fr_cursor_init(&cursor, &request->reply->vps);
	fr_cursor_init(&to_encode, &head);

	while ((vp = fr_cursor_current(&cursor))) {
		if (!fr_dict_parent_common(encoder_ctx.root, vp->da, true)) {
			fr_cursor_next(&cursor);
			continue;
		}
		vp = fr_cursor_remove(&cursor);

		/*
		 *	Silently discard encrypted attributes until
		 *	the peer should have k_encr.  These can be
		 *	added by policy, and seem to cause
		 *	wpa_supplicant to fail if sent before the challenge.
		 */
		if (!eap_aka_sim_session->allow_encrypted && fr_dict_parent_common(attr_eap_aka_sim_encr_data, vp->da, true)) {
			RWDEBUG("Silently discarding &reply:%s: Encrypted attributes not allowed in this round",
				vp->da->name);
			talloc_free(vp);
			continue;
		}

		fr_cursor_append(&to_encode, vp);
	}

	RDEBUG2("Encoding attributes");
	log_request_pair_list(L_DBG_LVL_2, request, head, NULL);

	eap_session->this_round->request->type.num = eap_aka_sim_session->type;
	eap_session->this_round->request->id = eap_aka_sim_session->id++ & 0xff;
	eap_session->this_round->set_request_id = true;

	ret = fr_aka_sim_encode(request, head, &encoder_ctx);
	fr_cursor_head(&to_encode);
	fr_cursor_free_list(&to_encode);

	if (ret < 0) {
		RPEDEBUG("Failed encoding");
		return -1;
	}
	return 0;
}

static rlm_rcode_t common_eap_failure_send(REQUEST *request, eap_session_t *eap_session)
{
	RDEBUG2("Sending EAP-Failure");

	eap_session->this_round->request->code = FR_EAP_CODE_FAILURE;
	eap_session->finished = true;

	return RLM_MODULE_REJECT;
}

/** Send a failure message
 *
 */
static rlm_rcode_t common_failure_notification_send(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	VALUE_PAIR		*vp;
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	vp = fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_notification, TAG_ANY);
	if (!vp) {
		pair_add_reply(&vp, attr_eap_aka_sim_notification);
		vp->vp_uint16 = FR_NOTIFICATION_VALUE_GENERAL_FAILURE;
	}

	/*
	 *	Change the failure notification depending where
	 *	we are in the eap_aka_state machine.
	 */
	if (eap_aka_sim_session->challenge_success || eap_aka_sim_session->reauthentication_success) {
		vp->vp_uint16 &= ~0x4000;	/* Unset phase bit */

		/*
		 *	Include the counter attribute if we're failing
		 *	after a reauthentication success.
		 *
		 *	RFC 4187 section 9.10
		 *
		 *	If EAP-Request/AKA-Notification is used on
		 *	a fast re-authentication exchange, and if
		 *	the P bit in AT_NOTIFICATION is set to zero,
		 *	then AT_COUNTER is used for replay protection.
		 *	In this case, the AT_ENCR_DATA and AT_IV
		 *	attributes MUST be included, and the
		 *	encapsulated plaintext attributes MUST include
		 *	the AT_COUNTER attribute.  The counter value
		 *	included in AT_COUNTER MUST be the same
   		 *	as in the EAP-Request/AKA-Reauthentication
   		 *	packet on the same fast re-authentication
   		 *	exchange.
		 *
		 *	If the counter is used it should never be zero,
		 *	as it's incremented on first reauthentication
		 *	request.
		 */
		if (eap_aka_sim_session->reauthentication_success) {
			MEM(pair_update_reply(&vp, attr_eap_aka_sim_counter) >= 0);
			vp->vp_uint16 = eap_aka_sim_session->keys.reauth.counter;
		}

		/*
		 *	If we're after the challenge phase
		 *	then we need to include a MAC to
		 *	protect notifications.
		 */
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
		fr_pair_value_memcpy(vp, NULL, 0, false);
	} else {
		vp->vp_uint16 |= 0x4000;	/* Set phase bit */
	}
	vp->vp_uint16 &= ~0x8000;		/* In both cases success bit should be low */

	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Set the subtype to notification
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_subtype) >= 0);
	vp->vp_uint16 = FR_SUBTYPE_VALUE_NOTIFICATION;

	/*
	 *	Encode the packet
	 */
	if (aka_encode(request, eap_session) < 0) return common_failure_notification_enter(inst, request, eap_session);

	return RLM_MODULE_HANDLED;
}

/** Send a success message with MPPE-keys
 *
 * The only work to be done is the add the appropriate SEND/RECV
 * attributes derived from the MSK.
 */
static rlm_rcode_t common_eap_success_send(REQUEST *request, eap_session_t *eap_session)
{
	uint8_t			*p;
	eap_aka_sim_session_t	*eap_aka_sim_session;

	RDEBUG2("Sending EAP-Success");

	eap_session->this_round->request->code = FR_EAP_CODE_SUCCESS;
	eap_session->finished = true;

	eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	RDEBUG2("Adding attributes for MSK");
	p = eap_aka_sim_session->keys.msk;
	eap_add_reply(request->parent, attr_ms_mppe_recv_key, p, EAP_TLS_MPPE_KEY_LEN);
	p += EAP_TLS_MPPE_KEY_LEN;
	eap_add_reply(request->parent, attr_ms_mppe_send_key, p, EAP_TLS_MPPE_KEY_LEN);

	return RLM_MODULE_OK;
}

/** Send a success notification
 *
 */
static rlm_rcode_t common_success_notification_send(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*vp;

	RDEBUG2("Sending EAP-Request/Notification (Success)");
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	if (!fr_cond_assert(eap_aka_sim_session->challenge_success ||
			    eap_aka_sim_session->reauthentication_success)) return RLM_MODULE_FAIL;

	/*
	 *	Set the subtype to notification
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_subtype) >= 0);
	vp->vp_uint16 = FR_SUBTYPE_VALUE_NOTIFICATION;

	/*
	 *	If we're in this state success bit is
	 *	high phase bit is low.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_notification) >= 0);
	vp->vp_uint16 = FR_NOTIFICATION_VALUE_SUCCESS;

	/*
	 *	RFC 4187 section 9.10
	 *
	 *	If EAP-Request/AKA-Notification is used on
	 *	a fast re-authentication exchange, and if
	 *	the P bit in AT_NOTIFICATION is set to zero,
	 *	then AT_COUNTER is used for replay protection.
	 *	In this case, the AT_ENCR_DATA and AT_IV
	 *	attributes MUST be included, and the
	 *	encapsulated plaintext attributes MUST include
	 *	the AT_COUNTER attribute.  The counter value
	 *	included in AT_COUNTER MUST be the same
	 *	as in the EAP-Request/AKA-Reauthentication
	 *	packet on the same fast re-authentication
	 *	exchange.
	 *
	 *	If the counter is used it should never be zero,
	 *	as it's incremented on first reauthentication
	 *	request.
	 */
	if (eap_aka_sim_session->keys.reauth.counter > 0) {
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_counter) >= 0);
		vp->vp_uint16 = eap_aka_sim_session->keys.reauth.counter;
	}

	/*
	 *	Need to include an AT_MAC attribute so that
	 *	it will get calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memcpy(vp, NULL, 0, false);

	/*
	 *	Encode the packet
	 */
	if (aka_encode(request, eap_session) < 0) return common_failure_notification_enter(inst, request, eap_session);

	return RLM_MODULE_HANDLED;
}

/** Called after 'store session { ... }' and 'store pseudonym { ... }'
 *
 */
static rlm_rcode_t aka_reauthentication_request_send(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	/*
	 *	Encode the packet - AT_IV is handled automatically
	 *	by the encoder.
	 */
	if (aka_encode(request, eap_session) < 0) return common_failure_notification_enter(inst, request, eap_session);

	return RLM_MODULE_HANDLED;
}

/** Reauthentication request send
 *
 */
static rlm_rcode_t aka_reauthentication_request_compose(eap_aka_sim_state_conf_t *inst, REQUEST *request,
							eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*to_peer = request->reply->vps, *vp;

	RDEBUG2("Generating new session keys");

	/*
	 *	Update the key structure with a new
	 *	nonce_s value, counter, and MK.
	 */
	switch (eap_aka_sim_session->type) {
	case FR_EAP_METHOD_SIM:
		/* FIXME - DO STUFF */
		break;

	case FR_EAP_METHOD_AKA:
		if (fr_aka_sim_vector_umts_kdf_0_reauth_from_attrs(request, request->state,
								   &eap_aka_sim_session->keys) != 0) {
		request_new_id:
			switch (eap_aka_sim_session->last_id_req) {
			/*
			 *	Got here processing EAP-Identity-Response
			 *	If this is the *true* reauth ID, then
			 *	there's no point in setting AKA_SIM_ANY_ID_REQ.
			 */
			case AKA_SIM_NO_ID_REQ:
			case AKA_SIM_ANY_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
				return common_identity_enter(inst, request, eap_session);

			case AKA_SIM_FULLAUTH_ID_REQ:
			case AKA_SIM_PERMANENT_ID_REQ:
				REDEBUG("Last requested fullauth or permanent ID, "
					"but received, or were told we received (by policy), "
					"a fastauth ID.  Cannot continue");
			failure:
				return common_failure_notification_enter(inst, request, eap_session);
			}
		}
		if (fr_aka_sim_crypto_kdf_0_reauth(&eap_aka_sim_session->keys) < 0) goto request_new_id;
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		switch (eap_aka_sim_session->kdf) {
		case FR_KDF_VALUE_PRIME_WITH_CK_PRIME_IK_PRIME:
			if (fr_aka_sim_vector_umts_kdf_1_reauth_from_attrs(request, request->state,
									   &eap_aka_sim_session->keys) != 0) {
				goto request_new_id;
			}
			if (fr_aka_sim_crypto_kdf_1_reauth(&eap_aka_sim_session->keys) < 0) goto request_new_id;
			break;

		default:
			rad_assert(0);
			break;
		}
		break;

	default:
		rad_assert(0);
		break;
	}

	if (RDEBUG_ENABLED3) fr_aka_sim_crypto_keys_log(request, &eap_aka_sim_session->keys);

	/*
	 *	Add AT_IV, AT_COUNTER, AT_NONCE_S, and AT_MAC to to reply
	 *      The user may have added AT_NEXT_REAUTH_ID, in which case
	 *	we'll have sent that too.
	 */
	RDEBUG2("Sending EAP-Request/Reauthentication");
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Set the subtype to reauthentication
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_subtype) >= 0);
	vp->vp_uint16 = FR_SUBTYPE_VALUE_REAUTHENTICATION;

	/*
	 *	Indicate we'd like to use protected success messages
	 *	with AT_RESULT_IND
	 *
	 *	Use our default, but allow user override too.
	 */
	vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_result_ind, TAG_ANY);
	if (vp) eap_aka_sim_session->send_result_ind = vp->vp_bool;

	/*
	 *	RFC 5448 says AT_BIDDING is only sent in the challenge
	 *	not in reauthentication, so don't add that here.
	 */

	 /*
	  *	Add AT_NONCE_S
	  */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_nonce_s) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.reauth.nonce_s,
			     sizeof(eap_aka_sim_session->keys.reauth.nonce_s), false);

	/*
	 *	Add AT_COUNTER
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_counter) >= 0);
	vp->vp_uint16 = eap_aka_sim_session->keys.reauth.counter;

	/*
	 *	need to include an empty AT_MAC attribute so that
	 *	the mac will get calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memcpy(vp, NULL, 0, false);

	/*
	 *	If we have checkcode data, send that to the peer
	 *	in AT_CHECKCODE for validation.
	 */
	if (eap_aka_sim_session->checkcode_state) {
		ssize_t	slen;

		slen = fr_aka_sim_crypto_finalise_checkcode(eap_aka_sim_session->checkcode, &eap_aka_sim_session->checkcode_state);
		if (slen < 0) {
			RPEDEBUG("Failed calculating checkcode");
			goto failure;
		}
		eap_aka_sim_session->checkcode_len = slen;

		MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
		fr_pair_value_memcpy(vp, eap_aka_sim_session->checkcode, slen, false);
	/*
	 *	If we don't have checkcode data, then we exchanged
	 *	no identity packets, so checkcode is zero.
	 */
	} else {
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
		fr_pair_value_memcpy(vp, NULL, 0, false);
		eap_aka_sim_session->checkcode_len = 0;
	}

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_aka_sim_session->allow_encrypted = true;

	return session_and_pseudonym_store(inst, request, eap_session, aka_reauthentication_request_send);
}

/** Called after 'store session { ... }' and 'store pseudonym { ... }'
 *
 */
static rlm_rcode_t aka_challenge_request_send(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	/*
	 *	Encode the packet - AT_IV is handled automatically
	 *	by the encoder.
	 */
	if (aka_encode(request, eap_session) < 0) return common_failure_notification_enter(inst, request, eap_session);

	return RLM_MODULE_HANDLED;
}

/** Send the challenge itself
 *
 * Challenges will come from one of three places eventually:
 *
 * 1  from attributes like FR_RANDx
 *	    (these might be retrieved from a database)
 *
 * 2  from internally implemented SIM authenticators
 *	    (a simple one based upon XOR will be provided)
 *
 * 3  from some kind of SS7 interface.
 *
 * For now, they only come from attributes.
 * It might be that the best way to do 2/3 will be with a different
 * module to generate/calculate things.
 */
static rlm_rcode_t aka_challenge_request_compose(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*to_peer = request->reply->vps, *vp;
	fr_aka_sim_vector_src_t	src = AKA_SIM_VECTOR_SRC_AUTO;

	RDEBUG2("Acquiring UMTS vector(s)");

	if (eap_aka_sim_session->type == FR_EAP_METHOD_AKA_PRIME) {
		/*
		 *	Copy the network name the user specified for
		 *	key derivation purposes.
		 */
		vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_kdf_input, TAG_ANY);
		if (vp) {
			talloc_free(eap_aka_sim_session->keys.network);
			eap_aka_sim_session->keys.network = talloc_memdup(eap_aka_sim_session,
								      (uint8_t const *)vp->vp_strvalue, vp->vp_length);
			eap_aka_sim_session->keys.network_len = vp->vp_length;
		} else {
			REDEBUG2("No network name available, can't set AT_KDF_INPUT");
		failure:
			return common_failure_notification_enter(inst, request, eap_session);
		}

		/*
		 *	We don't allow the user to specify
		 *	the KDF currently.
		 */
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_kdf) >= 0);
		vp->vp_uint16 = eap_aka_sim_session->kdf;
	}

	/*
	 *	Get vectors from attribute or generate
	 *	them using COMP128-* or Milenage.
	 */
	if (fr_aka_sim_vector_umts_from_attrs(request, request->control, &eap_aka_sim_session->keys, &src) != 0) {
	    	REDEBUG("Failed retrieving UMTS vectors");
		goto failure;
	}

	/*
	 *	Don't leave the AMF hanging around
	 */
	if (eap_aka_sim_session->type == FR_EAP_METHOD_AKA_PRIME) pair_delete_control(attr_sim_amf);

	/*
	 *	All set, calculate keys!
	 */
	switch (eap_aka_sim_session->type) {
	default:
	case FR_EAP_METHOD_SIM:
		rad_assert(0);	/* EAP-SIM has its own Challenge state */
		break;

	case FR_EAP_METHOD_AKA:
		fr_aka_sim_crypto_kdf_0_umts(&eap_aka_sim_session->keys);
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		switch (eap_aka_sim_session->kdf) {
		case FR_KDF_VALUE_PRIME_WITH_CK_PRIME_IK_PRIME:
			fr_aka_sim_crypto_kdf_1_umts(&eap_aka_sim_session->keys);
			break;

		default:
			rad_assert(0);
			break;
		}
	}
	if (RDEBUG_ENABLED3) fr_aka_sim_crypto_keys_log(request, &eap_aka_sim_session->keys);

	RDEBUG2("Sending EAP-Request/AKA-Challenge");
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Set the subtype to challenge
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_subtype) >= 0);
	vp->vp_uint16 = FR_SUBTYPE_VALUE_AKA_CHALLENGE;

	/*
	 *	Indicate we'd like to use protected success messages
	 *	with AT_RESULT_IND
	 *
	 *	Use our default, but allow user override too.
	 */
	vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_result_ind, TAG_ANY);
	if (vp) eap_aka_sim_session->send_result_ind = vp->vp_bool;

	/*
	 *	See if we're indicating we want EAP-AKA'
	 *	If so include AT_BIDDING with the correct
	 *	value.
	 */
	vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_bidding, TAG_ANY);
	if (vp) {
		eap_aka_sim_session->send_at_bidding_prefer_prime =
			(vp->vp_uint16 == FR_BIDDING_VALUE_PREFER_AKA_PRIME);
	}

	/*
	 *	These attributes are only allowed with
	 *	EAP-AKA', protect users from themselves.
	 */
	if (eap_aka_sim_session->type == FR_EAP_METHOD_AKA) {
		pair_delete_reply(attr_eap_aka_sim_kdf_input);
		pair_delete_reply(attr_eap_aka_sim_kdf);
	}

	/*
	 *	Okay, we got the challenge! Put it into an attribute.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_rand) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.umts.vector.rand, AKA_SIM_VECTOR_UMTS_RAND_SIZE, false);

	/*
	 *	Send the AUTN value to the client, so it can authenticate
	 *	whoever has knowledge of the Ki.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_autn) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.umts.vector.autn, AKA_SIM_VECTOR_UMTS_AUTN_SIZE, false);

	/*
	 *	need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memcpy(vp, NULL, 0, false);

	/*
	 *	If we have checkcode data, send that to the peer
	 *	in AT_CHECKCODE for validation.
	 */
	if (eap_aka_sim_session->checkcode_state) {
		ssize_t	slen;

		slen = fr_aka_sim_crypto_finalise_checkcode(eap_aka_sim_session->checkcode, &eap_aka_sim_session->checkcode_state);
		if (slen < 0) {
			RPEDEBUG("Failed calculating checkcode");
			goto failure;
		}
		eap_aka_sim_session->checkcode_len = slen;

		MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
		fr_pair_value_memcpy(vp, eap_aka_sim_session->checkcode, slen, false);
	/*
	 *	If we don't have checkcode data, then we exchanged
	 *	no identity packets, so AT_CHECKCODE is zero.
	 */
	} else {
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
		fr_pair_value_memcpy(vp, NULL, 0, false);
		eap_aka_sim_session->checkcode_len = 0;
	}

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_aka_sim_session->allow_encrypted = true;

	return session_and_pseudonym_store(inst, request, eap_session, aka_challenge_request_send);
}

/** Send an Identity request to the supplicant
 *
 * There are three types of user identities that can be implemented
 * - Permanent identities such as 0123456789098765@myoperator.com
 *   Permanent identities can be identified by the leading zero followed by
 *   by 15 digits (the IMSI number).
 * - Ephemeral identities (pseudonyms).  These are identities assigned for
 *   identity privacy so the user can't be tracked.  These can identities
 *   can either be generated as per the 3GPP 'Security aspects of non-3GPP accesses'
 *   document section 14, where a set of up to 16 encryption keys are used
 *   to reversibly encrypt the IMSI. Alternatively the pseudonym can be completely
 *   randomised and stored in a datastore.
 * - A fast resumption ID which resolves to data used for fast resumption.
 *
 * In order to perform full authentication the original IMSI is required for
 * forwarding to the HLR. In the case where we can't match/decrypt the pseudonym,
 * or can't perform fast resumption, we need to request the full identity from
 * the supplicant.
 *
 * @param[in] request		The current subrequest.
 * @param[in] eap_session	to continue.
 * @return
 *	- RLM_MODULE_HANDLED on success.
 *	- anything else on failure.
 */
static rlm_rcode_t common_identity_request_send(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*vp;

	RDEBUG2("Sending EAP-Request/Identity %s",
		fr_int2str(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Set the subtype to identity request
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_subtype) >= 0);
	vp->vp_uint16 = FR_SUBTYPE_VALUE_IDENTITY;

	/*
	 *	Update eap_aka_sim_session->id_req in case the the
	 *	user set attributes in `send Identity-Request { ... }`
	 *	Also removes all existing id_req attributes
	 *	from the reply.
	 */
	id_req_set_by_user(request, eap_aka_sim_session);

	/*
	 *	Select the right type of identity request attribute
	 *
	 *      Implement checks on identity request order described
	 *	by RFC4187 section 4.1.5.
	 *
	 *	The internal state machine should always handle this
	 *	correctly, but the user may have other ideas...
	 */
	switch (eap_aka_sim_session->id_req) {
	case AKA_SIM_ANY_ID_REQ:
		if (eap_aka_sim_session->last_id_req != AKA_SIM_NO_ID_REQ) {
		id_out_of_order:
			REDEBUG("Cannot send %s, already sent %s",
				fr_int2str(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"),
				fr_int2str(fr_aka_sim_id_request_table, eap_aka_sim_session->last_id_req, "<INVALID>"));
			return common_failure_notification_enter(inst, request, eap_session);
		}
		MEM(pair_add_reply(&vp, attr_eap_aka_sim_any_id_req) >= 0);
		vp->vp_bool = true;
		break;

	case AKA_SIM_FULLAUTH_ID_REQ:
		switch (eap_aka_sim_session->last_id_req) {
		case AKA_SIM_NO_ID_REQ:		/* Not sent anything before */
		case AKA_SIM_ANY_ID_REQ:		/* Last request was for any ID, but the re-auth ID was bad */
			break;

		default:
			goto id_out_of_order;

		}
		MEM(pair_add_reply(&vp, attr_eap_aka_sim_fullauth_id_req) >= 0);
		vp->vp_bool = true;
		break;

	case AKA_SIM_PERMANENT_ID_REQ:
		switch (eap_aka_sim_session->last_id_req) {
		case AKA_SIM_NO_ID_REQ:		/* Not sent anything before */
		case AKA_SIM_ANY_ID_REQ:		/* Last request was for any ID, but the re-auth ID was bad */
		case AKA_SIM_FULLAUTH_ID_REQ:	/* ...didn't understand the pseudonym either */
			break;

		default:
			goto id_out_of_order;

		}
		MEM(pair_add_reply(&vp, attr_eap_aka_sim_permanent_id_req) >= 0);
		vp->vp_bool = true;
		break;

	default:
		rad_assert(0);
	}
	eap_aka_sim_session->last_id_req = eap_aka_sim_session->id_req;	/* Record what we last requested */

	/*
	 *	Encode the packet
	 */
	if (aka_encode(request, eap_session) < 0) {
	failure:
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	Digest the packet contents, updating our checkcode.
	 */
	if (!eap_aka_sim_session->checkcode_state &&
	    fr_aka_sim_crypto_init_checkcode(eap_aka_sim_session, &eap_aka_sim_session->checkcode_state,
	    				 eap_aka_sim_session->checkcode_md) < 0) {
		RPEDEBUG("Failed initialising checkcode");
		goto failure;
	}
	if (fr_aka_sim_crypto_update_checkcode(eap_aka_sim_session->checkcode_state, eap_session->this_round->request) < 0) {
		RPEDEBUG("Failed updating checkcode");
		goto failure;
	}

	return RLM_MODULE_HANDLED;
}

/** Print debugging information, and write new state to eap_session->process
 *
 */
static inline void state_transition(REQUEST *request, eap_session_t *eap_session,
					    module_method_t new_state)
{
	module_method_t		old_state = eap_session->process;

	if (new_state != old_state) {
		RDEBUG2("Changed state %s -> %s",
			module_state_method_to_str(aka_state_table, old_state, "<unknown>"),
			module_state_method_to_str(aka_state_table, new_state, "<unknown>"));
	} else {
		RDEBUG2("Reentering state %s",
			module_state_method_to_str(aka_state_table, old_state, "<unknown>"));
	}

	eap_session->process = new_state;
}

/** Resume function after 'send EAP-Failure { ... }'
 *
 */
static rlm_rcode_t common_eap_failure_enter_resume(UNUSED void *instance, UNUSED void *thread,
					    REQUEST *request, UNUSED void *rctx)
{
	eap_session_t	*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	return common_eap_failure_send(request, eap_session);
}

/** Enter eap_aka_state FAILURE - Send an EAP-Failure message
 *
 */
static rlm_rcode_t common_eap_failure_enter(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t *eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	/*
	 *	Free anything we were going to send out...
	 */
	fr_pair_list_free(&request->reply->vps);

	/*
	 *	If we're failing, then any identities
	 *	we sent are now invalid.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(inst,
						   request, eap_session, common_eap_failure_enter); /* come back when we're done */
	}

	state_transition(request, eap_session, common_eap_failure);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_eap_failure,
					      RLM_MODULE_NOOP,
					      common_eap_failure_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume function after 'send Failure-Notification { ... }'
 *
 * Ignores return code from send Failure-Notification { ... } section.
 */
static rlm_rcode_t common_failure_notification_enter_resume(void *instance, UNUSED void *thread,
							 REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t	*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	/*
	 *	Free anything we were going to send out...
	 */
	fr_pair_list_free(&request->reply->vps);

	/*
	 *	If there's an issue composing the failure
	 *      message just send an EAP-Failure instead.
	 */
	return common_failure_notification_send(inst, request, eap_session);
}

/** Enter eap_aka_state FAILURE-NOTIFICATION - Send an EAP-Request/AKA-Notification (failure) message
 *
 */
static rlm_rcode_t common_failure_notification_enter(eap_aka_sim_state_conf_t *inst,
						  REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	/*
	 *	If we're failing, then any identities
	 *	we sent are now invalid.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(inst, request, eap_session, common_failure_notification_enter); /* come back when we're done */
	}

	/*
	 *	We've already sent a failure notification
	 *	Now we just fail as it means something
	 *	went wrong processing the ACK or we got
	 *	garbage from the supplicant.
	 */
	if (eap_session->process == common_failure_notification) {
		return common_eap_failure_enter(inst, request, eap_session);
	}

	/*
	 *	Otherwise just transition as normal...
	 */
	state_transition(request, eap_session, common_failure_notification);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_failure_notification,
					      RLM_MODULE_NOOP,
					      common_failure_notification_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume function after 'send EAP-Success { ... }'
 *
 */
static rlm_rcode_t common_eap_success_enter_resume(void *instance, UNUSED void *thread,
						  REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	/*
	 *	If this is true we're entering this state
	 *	after sending a AKA-Success-Notification
	 *
	 *	Is seems like a really bad idea to allow the
	 *	user to send a protected success to the
	 *	supplicant and then force a failure using
	 *	the send EAP-Success { ... } section.
	 */
	if (eap_aka_sim_session->send_result_ind) {
		switch (request->rcode) {
		case RLM_MODULE_USER_SECTION_REJECT:
			RWDEBUG("Ignoring rcode (%s) from send EAP-Success { ... } "
				"as we already sent a Success-Notification",
				fr_int2str(mod_rcode_table, request->rcode, "<invalid>"));
			RWDEBUG("If you need to force a failure, return an error code from "
				"send Success-Notification { ... }");
			break;

		default:
			break;
		}

	/*
	 *	But... if we're not working with protected
	 *	success indication, this is the only
	 *	opportunity the user has to force a failure at
	 *	the end of authentication.
	 */
	} else {
		section_rcode_process(inst, request, eap_session);
	}

	return common_eap_success_send(request, eap_session);
}

/** Enter eap_aka_state SUCCESS - Send an EAP-Success message
 *
 */
static rlm_rcode_t common_eap_success_enter(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	state_transition(request, eap_session, common_eap_success);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_eap_success,
					      RLM_MODULE_NOOP,
					      common_eap_success_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume function after 'send Success-Notification { ... }'
 *
 */
static rlm_rcode_t common_success_notification_enter_resume(void *instance, UNUSED void *thread,
							       REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t	*eap_session = eap_session_get(request->parent);

	section_rcode_process(inst, request, eap_session);

	return common_success_notification_send(inst, request, eap_session);
}

/** Enter eap_aka_state SUCCESS-NOTIFICATION - Send an EAP-Request/AKA-Notification (success) message
 *
 */
static rlm_rcode_t common_success_notification_enter(eap_aka_sim_state_conf_t *inst,
							REQUEST *request, eap_session_t *eap_session)
{
	state_transition(request, eap_session, common_success_notification);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_success_notification,
					      RLM_MODULE_NOOP,
					      common_success_notification_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume function after 'send Reauthentication-Request' - Send an EAP-Request/reauthentication message
 *
 */
static rlm_rcode_t aka_reauthentication_send_resume(UNUSED void *instance, UNUSED void *thread,
				       		    REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	switch (request->rcode) {
	/*
	 *	Failed getting the values we need for resumption
	 *	Request a different identity.
	 */
	default:
		switch (eap_aka_sim_session->last_id_req) {
		/*
		 *	Got here processing EAP-Identity-Response
		 *	If this is the *true* reauth ID, then
		 *	there's no point in setting AKA_SIM_ANY_ID_REQ.
		 */
		case AKA_SIM_NO_ID_REQ:
		case AKA_SIM_ANY_ID_REQ:
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
			return common_identity_enter(inst, request, eap_session);

		case AKA_SIM_FULLAUTH_ID_REQ:
		case AKA_SIM_PERMANENT_ID_REQ:
			REDEBUG("Last requested Full-Auth-Id or Permanent-Id, "
				"but received a Fast-Auth-Id.  Cannot continue");
			return common_failure_notification_enter(inst, request, eap_session);

		}

	/*
	 *	Policy rejected the user
	 */
	case RLM_MODULE_REJECT:
	case RLM_MODULE_USERLOCK:
		return common_failure_notification_enter(inst, request, eap_session);

	/*
	 *	Everything looks ok, send the EAP-Request/reauthentication message
	 *	After storing any new pseudonyms or session information.
	 */
	case RLM_MODULE_NOOP:
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		return aka_reauthentication_request_compose(inst, request, eap_session);
	}
}

/** Resume function after 'load session' - Send an EAP-Request/reauthentication message
 *
 */
static rlm_rcode_t session_load_resume(void *instance, UNUSED void *thread,
				       REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	pair_delete_request(attr_session_id);

	/*
	 *	Control attributes required could have been specified
	 *      in another section.
	 */
	if (!inst->actions.load_session) goto reauthenticate;

	switch (request->rcode) {
	/*
	 *	Failed getting the values we need for resumption
	 *	Request a different identity.
	 */
	default:
		switch (eap_aka_sim_session->last_id_req) {
		/*
		 *	Got here processing EAP-Identity-Response
		 *	If this is the *true* reauth ID, then
		 *	there's no point in setting AKA_SIM_ANY_ID_REQ.
		 */
		case AKA_SIM_NO_ID_REQ:
		case AKA_SIM_ANY_ID_REQ:
			RDEBUG2("Previous section returned (%s), requesting additional identity",
				fr_int2str(rcode_table, request->rcode, "<INVALID>"));
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
			return common_identity_enter(inst, request, eap_session);

		case AKA_SIM_FULLAUTH_ID_REQ:
		case AKA_SIM_PERMANENT_ID_REQ:
			REDEBUG("Last requested Full-Auth-Id or Permanent-Id, "
				"but received a Fast-Auth-Id.  Cannot continue");
			return common_failure_notification_enter(inst, request, eap_session);

		}

	/*
	 *	Policy rejected the user
	 */
	case RLM_MODULE_REJECT:
	case RLM_MODULE_USERLOCK:
		return common_failure_notification_enter(inst, request, eap_session);

	/*
	 *	Everything OK
	 */
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	reauthenticate:
		return unlang_module_yield_to_section(request,
						      inst->actions.send_reauthentication_request,
						      RLM_MODULE_NOOP,
						      aka_reauthentication_send_resume,
						      mod_signal,
						      NULL);
	}
}

/** Resume function after 'load pseudonym { ... }' - Send an EAP-Request/AKA-Challenge message
 *
 */
static rlm_rcode_t pseudonym_load_resume(void *instance, UNUSED void *thread,
					 REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	pair_delete_request(attr_eap_aka_sim_next_reauth_id);

	/*
	 *	Control attributes required could have been specified
	 *      in another section.
	 */
	if (!inst->actions.load_pseudonym) goto enter_challenge;

	switch (request->rcode) {
	/*
	 *	Failed resolving the pseudonym
	 *	request a different identity.
	 */
	default:
		switch (eap_aka_sim_session->last_id_req) {
		case AKA_SIM_NO_ID_REQ:
		case AKA_SIM_ANY_ID_REQ:
		case AKA_SIM_FULLAUTH_ID_REQ:
			RDEBUG2("Previous section returned (%s), requesting additional identity",
				fr_int2str(rcode_table, request->rcode, "<INVALID>"));
			eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
			return common_identity_enter(inst, request, eap_session);

		case AKA_SIM_PERMANENT_ID_REQ:
			REDEBUG("Last requested a Permanent-Id, but received a Pseudonym.  Cannot continue");
			return common_failure_notification_enter(inst, request, eap_session);
		}
	/*
	 *	Policy rejected the user
	 */
	case RLM_MODULE_REJECT:
	case RLM_MODULE_USERLOCK:
		return common_failure_notification_enter(inst, request, eap_session);

	/*
	 *	Everything OK
	 */
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	enter_challenge:
		return aka_challenge_enter(inst, request, eap_session);
	}
}

/** Enter eap_aka_state REAUTHENTICATION - Send an EAP-Request/AKA-Reauthentication message
 *
 */
static rlm_rcode_t aka_reauthentication_enter(eap_aka_sim_state_conf_t *inst,
					      REQUEST *request, eap_session_t *eap_session)
{
	VALUE_PAIR		*vp = NULL;
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	state_transition(request, eap_session, aka_reauthentication);

	/*
	 *	Add the current identity as session_id
	 *      to make it easier to load/store things from
	 *	the cache module.
	 */
	MEM(pair_update_request(&vp, attr_session_id) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.identity, eap_aka_sim_session->keys.identity_len, true);

	return unlang_module_yield_to_section(request,
					      inst->actions.load_session,
					      RLM_MODULE_NOOP,
					      session_load_resume,
					      mod_signal,
					      NULL);
}

/** Resume function after 'send Challenge-Request { ... }'
 *
 */
static rlm_rcode_t aka_challenge_enter_resume(void *instance, UNUSED void *thread, REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t	*eap_session = eap_session_get(request->parent);

	section_rcode_process(inst, request, eap_session);

	return aka_challenge_request_compose(inst, request, eap_session);
}

/** Enter eap_aka_state CHALLENGE - Send an EAP-Request/AKA-Challenge message
 *
 */
static rlm_rcode_t aka_challenge_enter(eap_aka_sim_state_conf_t *inst,
				       REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*vp;

	/*
	 *	If we've sent either of these identities it
	 *	means we've come here form a Reauthentication-Request
	 *	that failed.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(inst, request, eap_session, aka_challenge_enter);	/* come back when we're done */
	}

	state_transition(request, eap_session, aka_challenge);

	/*
	 *	Set some default attributes, giving the user a
	 *	chance to modify them.
	 */
	switch (eap_session->type) {
	case FR_EAP_METHOD_AKA_PRIME:
	{
		uint8_t		amf_buff[2] = { 0x80, 0x00 };	/* Set the AMF separation bit high */

		/*
		 *	Toggle the AMF high bit to indicate we're doing AKA'
		 */
		MEM(pair_update_control(&vp, attr_sim_amf) >= 0);
		fr_pair_value_memcpy(vp, amf_buff, sizeof(amf_buff), false);

	        /*
	 	 *	Use the default network name we have configured
	 	 *	and send it to the peer.
	 	 */
		if (inst->network_name &&
		    !fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_kdf_input, TAG_ANY)) {
			MEM(pair_add_reply(&vp, attr_eap_aka_sim_kdf_input) >= 0);
			fr_pair_value_bstrncpy(vp, inst->network_name, talloc_array_length(inst->network_name) - 1);
		}
	}
		break;

	default:
		/*
		 *	Use the default bidding value we have configured
		 */
		if (eap_aka_sim_session->send_at_bidding_prefer_prime &&
		    !fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_bidding, TAG_ANY)) {
			MEM(pair_add_reply(&vp, attr_eap_aka_sim_bidding) >= 0);
			vp->vp_uint16 = FR_BIDDING_VALUE_PREFER_AKA_PRIME;
		}
		break;

	}

	/*
	 *	Set the defaults for protected result indicator
	 */
	if (eap_aka_sim_session->send_result_ind &&
	    !fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_result_ind, TAG_ANY)) {
	    	MEM(pair_add_reply(&vp, attr_eap_aka_sim_result_ind) >= 0);
		vp->vp_bool = true;
	}

	return unlang_module_yield_to_section(request,
					      inst->actions.send_challenge_request,
					      RLM_MODULE_NOOP,
					      aka_challenge_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume function after 'send AKA-Identity-Request { ... }'
 *
 */
static rlm_rcode_t common_identity_enter_resume(void *instance, UNUSED void *thread,
						   REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t	*eap_session = eap_session_get(request->parent);

	section_rcode_process(inst, request, eap_session);

	return common_identity_request_send(inst, request, eap_session);
}

/** Enter eap_aka_state AKA-IDENTITY - Send an EAP-Request/AKA-Identity message
 *
 */
static rlm_rcode_t common_identity_enter(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	state_transition(request, eap_session, common_identity);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_identity_request,
					      RLM_MODULE_NOOP,
					      common_identity_enter_resume,
					      mod_signal,
					      NULL);
}

/** Process an EAP-Response/reauthentication message
 *
 */
static rlm_rcode_t aka_reauthentication_response_process(eap_aka_sim_state_conf_t *inst, REQUEST *request,
						       	 eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	uint8_t			calc_mac[AKA_SIM_MAC_DIGEST_SIZE];
	ssize_t			slen;
	VALUE_PAIR		*mac, *checkcode;
	VALUE_PAIR		*from_peer = request->packet->vps;

	mac = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_mac, TAG_ANY);
	if (!mac) {
		REDEBUG("Missing AT_MAC attribute");
		return common_failure_notification_enter(inst, request, eap_session);
	}
	if (mac->vp_length != AKA_SIM_MAC_DIGEST_SIZE) {
		REDEBUG("MAC has incorrect length, expected %u bytes got %zu bytes",
			AKA_SIM_MAC_DIGEST_SIZE, mac->vp_length);
		return common_failure_notification_enter(inst, request, eap_session);
	}

	slen = fr_aka_sim_crypto_sign_packet(calc_mac, eap_session->this_round->response, true,
					     eap_aka_sim_session->mac_md,
					     eap_aka_sim_session->keys.k_aut, eap_aka_sim_session->keys.k_aut_len,
					     eap_aka_sim_session->keys.reauth.nonce_s,
					     sizeof(eap_aka_sim_session->keys.reauth.nonce_s));
	if (slen < 0) {
		RPEDEBUG("Failed calculating MAC");
		return common_failure_notification_enter(inst, request, eap_session);
	} else if (slen == 0) {
		REDEBUG("Zero length AT_MAC attribute");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	if (memcmp(mac->vp_octets, calc_mac, sizeof(calc_mac)) == 0) {
		RDEBUG2("Received MAC matches calculated MAC");
	} else {
		REDEBUG("Received MAC does not match calculated MAC");
		RHEXDUMP_INLINE(L_DBG_LVL_2, mac->vp_octets, AKA_SIM_MAC_DIGEST_SIZE, "Received");
		RHEXDUMP_INLINE(L_DBG_LVL_2, calc_mac, AKA_SIM_MAC_DIGEST_SIZE, "Expected");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	If the peer doesn't include a checkcode then that
	 *	means they don't support it, and we can't validate
	 *	their view of the identity packets.
	 */
	checkcode = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_checkcode, TAG_ANY);
	if (checkcode) {
		if (checkcode->vp_length != eap_aka_sim_session->checkcode_len) {
			REDEBUG("Checkcode length (%zu) does not match calculated checkcode length (%zu)",
				checkcode->vp_length, eap_aka_sim_session->checkcode_len);
			return common_failure_notification_enter(inst, request, eap_session);
		}

		if (memcmp(checkcode->vp_octets, eap_aka_sim_session->checkcode, eap_aka_sim_session->checkcode_len) == 0) {
			RDEBUG2("Received checkcode matches calculated checkcode");
		} else {
			REDEBUG("Received checkcode does not match calculated checkcode");
			RHEXDUMP_INLINE(L_DBG_LVL_2, checkcode->vp_octets, checkcode->vp_length, "Received");
			RHEXDUMP_INLINE(L_DBG_LVL_2, eap_aka_sim_session->checkcode,
					eap_aka_sim_session->checkcode_len, "Expected");
			return common_failure_notification_enter(inst, request, eap_session);
		}
	/*
	 *	Only print something if we calculated a checkcode
	 */
	} else if (eap_aka_sim_session->checkcode_len > 0){
		RDEBUG2("Peer didn't include AT_CHECKCODE, skipping checkcode validation");
	}

	/*
	 *	Check to see if the supplicant sent
	 *	AT_COUNTER_TOO_SMALL, if they did then we
	 *	clear out reauth information and enter the
	 *	challenge state.
	 */
	if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_counter_too_small, TAG_ANY)) {
		RWDEBUG("Peer sent AT_COUNTER_TOO_SMALL (indicating our AT_COUNTER value (%u) wasn't fresh)",
			eap_aka_sim_session->keys.reauth.counter);

		fr_aka_sim_vector_umts_reauth_clear(&eap_aka_sim_session->keys);
		eap_aka_sim_session->allow_encrypted = false;

	 	return aka_challenge_enter(inst, request, eap_session);
	}

	/*
	 *	If the peer wants a Success notification, and
	 *	we included AT_RESULT_IND then send a success
	 *      notification, otherwise send a normal EAP-Success.
	 *
	 *	RFC 4187 Section 6.2. Result Indications
	 */
	if (eap_aka_sim_session->send_result_ind) {
		if (!fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
			RDEBUG("We wanted to use protected result indications, but peer does not");
			eap_aka_sim_session->send_result_ind = false;
		} else {
			return common_success_notification_enter(inst, request, eap_session);
		}
	} else if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
		RDEBUG("Peer wanted to use protected result indications, but we do not");
	}

	eap_aka_sim_session->reauthentication_success = true;

	return common_eap_success_enter(inst, request, eap_session);
}

/** Process an EAP-Response/AKA-Challenge message
 *
 * Verify that MAC, and RES match what we expect.
 */
static rlm_rcode_t aka_challenge_response_process(eap_aka_sim_state_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	uint8_t			calc_mac[AKA_SIM_MAC_DIGEST_SIZE];
	ssize_t			slen;
	VALUE_PAIR		*vp = NULL, *mac, *checkcode;
	VALUE_PAIR		*from_peer = request->packet->vps;

	mac = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_mac, TAG_ANY);
	if (!mac) {
		REDEBUG("Missing AT_MAC attribute");
		return common_failure_notification_enter(inst, request, eap_session);
	}
	if (mac->vp_length != AKA_SIM_MAC_DIGEST_SIZE) {
		REDEBUG("MAC has incorrect length, expected %u bytes got %zu bytes",
			AKA_SIM_MAC_DIGEST_SIZE, mac->vp_length);
		return common_failure_notification_enter(inst, request, eap_session);
	}

	slen = fr_aka_sim_crypto_sign_packet(calc_mac, eap_session->this_round->response, true,
					 eap_aka_sim_session->mac_md,
					 eap_aka_sim_session->keys.k_aut, eap_aka_sim_session->keys.k_aut_len,
					 NULL, 0);
	if (slen < 0) {
		RPEDEBUG("Failed calculating MAC");
		return common_failure_notification_enter(inst, request, eap_session);
	} else if (slen == 0) {
		REDEBUG("Zero length AT_MAC attribute");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	if (memcmp(mac->vp_octets, calc_mac, sizeof(calc_mac)) == 0) {
		RDEBUG2("Received MAC matches calculated MAC");
	} else {
		REDEBUG("Received MAC does not match calculated MAC");
		RHEXDUMP_INLINE(L_DBG_LVL_2, mac->vp_octets, AKA_SIM_MAC_DIGEST_SIZE, "Received");
		RHEXDUMP_INLINE(L_DBG_LVL_2, calc_mac, AKA_SIM_MAC_DIGEST_SIZE, "Expected");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	If the peer doesn't include a checkcode then that
	 *	means they don't support it, and we can't validate
	 *	their view of the identity packets.
	 */
	checkcode = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_checkcode, TAG_ANY);
	if (checkcode) {
		if (checkcode->vp_length != eap_aka_sim_session->checkcode_len) {
			REDEBUG("Checkcode length (%zu) does not match calculated checkcode length (%zu)",
				checkcode->vp_length, eap_aka_sim_session->checkcode_len);
			return common_failure_notification_enter(inst, request, eap_session);
		}

		if (memcmp(checkcode->vp_octets, eap_aka_sim_session->checkcode, eap_aka_sim_session->checkcode_len) == 0) {
			RDEBUG2("Received checkcode matches calculated checkcode");
		} else {
			REDEBUG("Received checkcode does not match calculated checkcode");
			RHEXDUMP_INLINE(L_DBG_LVL_2, checkcode->vp_octets, checkcode->vp_length, "Received");
			RHEXDUMP_INLINE(L_DBG_LVL_2, eap_aka_sim_session->checkcode,
					eap_aka_sim_session->checkcode_len, "Expected");
			return common_failure_notification_enter(inst, request, eap_session);
		}
	/*
	 *	Only print something if we calculated a checkcode
	 */
	} else if (eap_aka_sim_session->checkcode_len > 0){
		RDEBUG2("Peer didn't include AT_CHECKCODE, skipping checkcode validation");
	}

	vp = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_res, TAG_ANY);
	if (!vp) {
		REDEBUG("AT_RES missing from challenge response");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	if (vp->vp_length != eap_aka_sim_session->keys.umts.vector.xres_len) {
		REDEBUG("RES length (%zu) does not match XRES length (%zu)",
			vp->vp_length, eap_aka_sim_session->keys.umts.vector.xres_len);
		return common_failure_notification_enter(inst, request, eap_session);
	}

  	if (memcmp(vp->vp_octets, eap_aka_sim_session->keys.umts.vector.xres, vp->vp_length)) {
    		REDEBUG("RES from client does match XRES");
		RHEXDUMP_INLINE(L_DBG_LVL_2, vp->vp_octets, vp->vp_length, "RES  :");
		RHEXDUMP_INLINE(L_DBG_LVL_2, eap_aka_sim_session->keys.umts.vector.xres,
				eap_aka_sim_session->keys.umts.vector.xres_len, "XRES :");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	RDEBUG2("RES matches XRES");

	eap_aka_sim_session->challenge_success = true;

	/*
	 *	If the peer wants a Success notification, and
	 *	we included AT_RESULT_IND then send a success
	 *      notification, otherwise send a normal EAP-Success.
	 *
	 *	RFC 4187 Section 6.2. Result Indications
	 */
	if (eap_aka_sim_session->send_result_ind) {
		if (!fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
			RDEBUG("We wanted to use protected result indications, but peer does not");
			eap_aka_sim_session->send_result_ind = false;
		} else {
			return common_success_notification_enter(inst, request, eap_session);
		}
	} else if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
		RDEBUG("Peer wanted to use protected result indications, but we do not");
	}

	return common_eap_success_enter(inst, request, eap_session);
}

/** Process an identity response
 *
 * Handles identity negotiation
 */
static rlm_rcode_t common_identity_response_process(eap_aka_sim_state_conf_t *inst,
						    REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*id;
	bool			user_set_id_req;
	VALUE_PAIR		*from_peer = request->packet->vps;
	VALUE_PAIR		*identity_type;

	/*
	 *	Digest the identity response
	 */
	if (fr_aka_sim_crypto_update_checkcode(eap_aka_sim_session->checkcode_state,
					       eap_session->this_round->response) < 0) {
		RPEDEBUG("Failed updating checkcode");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	See if we got an AT_IDENTITY
	 */
	id = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_identity, TAG_ANY);
	if (!id) {
		/*
		 *  9.2.  EAP-Response/AKA-Identity
		 *
   		 *  The peer sends EAP-Response/Identity in response to a valid
		 *  EAP-Request/Identity from the server.
		 *  The peer MUST include the AT_IDENTITY attribute.  The usage of
		 *  AT_IDENTITY is defined in Section 4.1.
		 */
		 REDEBUG("EAP-Response/AKA-Identity does not contain AT_IDENTITY");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	Update cryptographic identity
	 */
	talloc_free(eap_aka_sim_session->keys.identity);
	eap_aka_sim_session->keys.identity_len = id->vp_length;
	MEM(eap_aka_sim_session->keys.identity = talloc_memdup(eap_aka_sim_session, id->vp_strvalue, id->vp_length));

	/*
	 *	See if the user wants us to request another
	 *	identity.
	 *
	 *	If they set one themselves don't override
	 *	what they set.
	 */
	user_set_id_req = id_req_set_by_user(request, eap_aka_sim_session);
	if ((request->rcode == RLM_MODULE_NOTFOUND) || user_set_id_req) {
		if (!user_set_id_req) {
			switch (eap_aka_sim_session->last_id_req) {
			case AKA_SIM_ANY_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
				break;

			case AKA_SIM_FULLAUTH_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
				break;

			case AKA_SIM_NO_ID_REQ:	/* Should not happen */
				rad_assert(0);
				/* FALL-THROUGH */

			case AKA_SIM_PERMANENT_ID_REQ:
				REDEBUG("Peer sent no usable identities");
				return common_failure_notification_enter(inst, request, eap_session);

			}
			RDEBUG2("Previous section returned 'notfound', requesting next most permissive identity (%s)",
				fr_int2str(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
		}
		return common_identity_enter(inst, request, eap_session);
	}

	/*
	 *	If the identity looks like a fast re-auth id
	 *	run fast re-auth, otherwise do fullauth.
	 */
	identity_type = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_identity_type, TAG_ANY);
	if (identity_type) switch (identity_type->vp_uint32) {
	case FR_IDENTITY_TYPE_VALUE_FASTAUTH:
		return aka_reauthentication_enter(inst, request, eap_session);

	/*
	 *	It's a pseudonym, which now needs resolving.
	 *	The resume function here calls aka_challenge_enter
	 *	if pseudonym resolution went ok.
	 */
	case FR_IDENTITY_TYPE_VALUE_PSEUDONYM:
		return unlang_module_yield_to_section(request,
						      inst->actions.load_pseudonym,
						      RLM_MODULE_NOOP,
						      pseudonym_load_resume,
						      mod_signal,
						      NULL);

	/*
	 *	If it's a permanent ID, copy it over to
	 *	the session state list for use in the
	 *      store pseudonym/store session sections
	 *	later.
	 */
	case FR_IDENTITY_TYPE_VALUE_PERMANENT:
	{
		VALUE_PAIR *vp;

		vp = fr_pair_find_by_da(request->packet->vps, attr_eap_identity, TAG_ANY);
		if (vp) id_to_permanent_id(request, vp, eap_aka_sim_session->type);
	}
		/* FALL-THROUGH */
	default:
		break;
	}

	return aka_challenge_enter(inst, request, eap_session);
}

/** Decode the peer's response
 *
 * This is called by the state_* functions to decode the peer's response.
 */
static rlm_rcode_t common_decode(VALUE_PAIR **subtype_vp, VALUE_PAIR **vps, eap_aka_sim_state_conf_t *inst, REQUEST *request)
{
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	fr_aka_sim_decode_ctx_t	ctx = {
					.keys = &eap_aka_sim_session->keys,
				};
	VALUE_PAIR		*aka_vps;
	fr_cursor_t		cursor;

	int			ret;

	fr_cursor_init(&cursor, &request->packet->vps);
	fr_cursor_tail(&cursor);

	ret = fr_aka_sim_decode(request,
				&cursor,
				dict_eap_aka_sim,
				eap_session->this_round->response->type.data,
				eap_session->this_round->response->type.length,
				&ctx);
	/*
	 *	RFC 4187 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case where
	 *	we cannot decode an EAP-AKA packet.
	 */
	if (ret < 0) {
		RPEDEBUG2("Failed decoding EAP-AKA attributes");
		return common_failure_notification_enter(inst, request, eap_session);
	}
	/* vps is the data from the client */
	aka_vps = fr_cursor_next(&cursor);
	if (aka_vps && RDEBUG_ENABLED2) {
		RDEBUG2("EAP-AKA decoded attributes");
		log_request_pair_list(L_DBG_LVL_2, request, aka_vps, NULL);
	}

	*subtype_vp = fr_pair_find_by_da(aka_vps, attr_eap_aka_sim_subtype, TAG_ANY);
	if (!*subtype_vp) {
		REDEBUG("Missing AT_SUBTYPE");
		return common_failure_notification_enter(inst, request, eap_session);
	}
	*vps = aka_vps;

	return RLM_MODULE_OK;
}

/** State machine exit point after sending EAP-Failure
 *
 */
static rlm_rcode_t common_eap_failure(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	rad_assert(0);	/* Should never actually be called */
	return RLM_MODULE_FAIL;
}

/** Process EAP-Response/AKA-Notification (failure)
 *
 */
static rlm_rcode_t common_failure_notification_recv_resume(void *instance, UNUSED void *thread,
						 	REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	return common_eap_failure_enter(inst, request, eap_session);
}

/** Process the response to our EAP-Request/AKA-Notification (failure)
 *
 * We don't really care about the content as we're going to send an EAP-Failure anyway
 */
static rlm_rcode_t common_failure_notification(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t		rcode;
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	VALUE_PAIR		*subtype_vp = NULL;
	VALUE_PAIR		*vps;

	rcode = common_decode(&subtype_vp, &vps, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_NOTIFICATION:
		RDEBUG2("Failure-Notification ACKed, sending EAP-Failure");
		return unlang_module_yield_to_section(request,
						      inst->actions.recv_failure_notification_ack,
						      RLM_MODULE_NOOP,
						      common_failure_notification_recv_resume,
						      mod_signal,
						      NULL);

	default:
		RWDEBUG("Failure-Notification not ACKed correctly, sending EAP-Failure anyway");
		return common_eap_failure_enter(inst, request, eap_session);
	}
}

/** State machine exit point after sending EAP-Success
 *
 */
static rlm_rcode_t common_eap_success(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	rad_assert(0);	/* Should never actually be called */
	return RLM_MODULE_FAIL;
}

/** Process EAP-Response/AKA-Notification (success)
 *
 */
static rlm_rcode_t common_success_notification_recv_resume(void *instance, UNUSED void *thread,
							REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	/*
	 *	RFC 4187 says we ignore the contents of the
	 *	next packet after we send our success notification
	 *	and always send a success.
	 */
	return common_eap_success_enter(inst, request, eap_session);
}

/** Process the response to our EAP-Request/AKA-Notification (success)
 *
 * We don't actually care what the response is, we just need to
 * create an EAP-Success, and write the MK to the outer request.
 */
static rlm_rcode_t common_success_notification(void *instance, UNUSED void *thread, REQUEST *request)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);

	return unlang_module_yield_to_section(request,
					      inst->actions.recv_success_notification_ack,
					      RLM_MODULE_NOOP,
					      common_success_notification_recv_resume,
					      mod_signal,
					      NULL);
}

/** Process EAP-Response/AKA-Challenge
 *
 */
static rlm_rcode_t aka_challenge_response_recv_resume(void *instance, UNUSED void *thread,
						      REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	section_rcode_process(inst, request, eap_session);

	return aka_challenge_response_process(inst, request, eap_session);
}

/** Process EAP-Response/AKA-Identity
 *
 */
static rlm_rcode_t common_identity_response_recv_resume(void *instance, UNUSED void *thread,
						     REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	section_rcode_process(inst, request, eap_session);

	return common_identity_response_process(inst, request, eap_session);
}

/** Process EAP-Response/AKA-Authentication-Reject
 *
 */
static rlm_rcode_t aka_authentication_reject_recv_resume(void *instance, UNUSED void *thread,
							 REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t				*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	return common_eap_failure_enter(inst, request, eap_session);
}

/** Process EAP-Response/AKA-Synchronization-Failure
 *
 */
static rlm_rcode_t aka_synchronization_failure_recv_resume(void *instance, UNUSED void *thread,
							   REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*vp;

	section_rcode_process(inst, request, eap_session);

	/*
	 *	If there's no section to handle this, then no resynchronisation
	 *	can't have occurred and we just send a reject.
	 *
	 *	Similarly, if we've already received one synchronisation failure
	 *	then it's highly likely whatever user configured action was
	 *	configured was unsuccessful, and we should just give up.
	 */
	if (!inst->actions.recv_syncronization_failure || eap_aka_sim_session->prev_recv_sync_failure) {
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	We couldn't generate an SQN and the user didn't provide one,
	 *	so we need to fail.
	 */
	vp = fr_pair_find_by_da(request->control, attr_sim_sqn, TAG_ANY);
	if (!vp) {
		REDEBUG("No &control:SQN value provided after resynchronisation, cannot continue");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	RFC 4187 Section 6.3.1
	 *
	 *	"if the peer detects that the
   	 *	sequence number in AUTN is not correct, the peer responds with
	 *	EAP-Response/AKA-Synchronization-Failure (Section 9.6), and the
	 *	server proceeds with a new EAP-Request/AKA-Challenge."
	 */
	return aka_challenge_enter(inst, request, eap_session);
}

/** Process EAP-Response/AKA-Client-Error
 *
 */
static rlm_rcode_t aka_client_error_recv_resume(void *instance, UNUSED void *thread,
						REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	return common_eap_failure_enter(inst, request, eap_session);
}

static rlm_rcode_t aka_reauthentication_response_recv_resume(void *instance, UNUSED void *thread,
							     REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	section_rcode_process(inst, request, eap_session);

	return aka_reauthentication_response_process(inst, request, eap_session);
}

static rlm_rcode_t aka_reauthentication(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t		rcode;
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	VALUE_PAIR		*subtype_vp = NULL;
	VALUE_PAIR		*vp;
	VALUE_PAIR		*from_peer;

	rcode = common_decode(&subtype_vp, &from_peer, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif
	/*
	 *	These aren't allowed in Reauthentication responses:
	 *
	 *	EAP_AKA_AUTHENTICATION_REJECT	- We didn't provide an AUTN value
	 *	EAP_AKA_SYNCHRONIZATION_FAILURE	- We didn't use new vectors.
	 */
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_REAUTHENTICATION:
		/*
		 *	AT_COUNTER_TOO_SMALL is handled
		 *      in aka_reauthentication_response_process.
		 */
		return unlang_module_yield_to_section(request,
						      inst->actions.recv_reauthentication_response,
						      RLM_MODULE_NOOP,
						      aka_reauthentication_response_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_CLIENT_ERROR:
		REDEBUG("Client error");

		vp = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_client_error_code, TAG_ANY);
		if (!vp) {
			REDEBUG("Peer rejected %s with EAP-Response/Client-Error message but "
				"has not supplied AT_ERROR_CODE",
				module_state_method_to_str(aka_state_table, eap_session->process, "<unknown>"));
		} else {
			REDEBUG("Client rejected %s with error: %pV (%i)",
				module_state_method_to_str(aka_state_table, eap_session->process, "<unknown>"),
				&vp->data, vp->vp_uint16);
		}

		eap_aka_sim_session->allow_encrypted = false;

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_client_error,
						      RLM_MODULE_NOOP,
						      aka_client_error_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	RFC 4187 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case.
	 */
	default:
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);

		eap_aka_sim_session->allow_encrypted = false;

		return common_failure_notification_enter(inst, request, eap_session);
	}
}

/** Process the response to our EAP-Request/AKA-Challenge
 *
 */
static rlm_rcode_t aka_challenge(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t		rcode;
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	VALUE_PAIR		*subtype_vp = NULL;
	VALUE_PAIR		*vps;
	VALUE_PAIR		*vp;

	rcode = common_decode(&subtype_vp, &vps, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_AKA_CHALLENGE:
		return unlang_module_yield_to_section(request,
						      inst->actions.recv_challenge_response,
						      RLM_MODULE_NOOP,
						      aka_challenge_response_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_AUTHENTICATION_REJECT:
		REDEBUG("Peer Rejected AUTN");

		eap_aka_sim_session->allow_encrypted = false;

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_authentication_reject,
						      RLM_MODULE_NOOP,
						      aka_authentication_reject_recv_resume,
						      mod_signal,
						      NULL);

	case FR_SUBTYPE_VALUE_AKA_SYNCHRONIZATION_FAILURE:
	{
		uint64_t	new_sqn;

		REDEBUG("Peer synchronization failure");

		eap_aka_sim_session->allow_encrypted = false;

		vp = fr_pair_find_by_da(request->packet->vps, attr_eap_aka_sim_auts, TAG_ANY);
		if (!vp) {
			REDEBUG("EAP-Response/AKA-Synchronisation-Failure missing AT_AUTS");
			return common_failure_notification_enter(inst, request, eap_session);
		}

		switch (fr_aka_sim_umts_resync_from_attrs(&new_sqn,
						      request, vp, &eap_aka_sim_session->keys)) {
		/*
		 *	Add everything back that we'll need in the
		 *	next challenge round.
		 */
		case 0:
			MEM(pair_add_control(&vp, attr_sim_sqn) >= 0);
			vp->vp_uint64 = new_sqn;

			MEM(pair_add_control(&vp, attr_sim_ki) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.auc.ki,
					     sizeof(eap_aka_sim_session->keys.auc.ki), false);

			MEM(pair_add_control(&vp, attr_sim_opc) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.auc.opc,
					     sizeof(eap_aka_sim_session->keys.auc.opc), false);
			break;

		case 1:	/* Don't have Ki or OPc so something else will need to deal with this */
			break;

		default:
		case -1:
			return common_failure_notification_enter(inst, request, eap_session);
		}

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_syncronization_failure,
						      RLM_MODULE_NOOP,
						      aka_synchronization_failure_recv_resume,
						      mod_signal,
						      NULL);
	}

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_CLIENT_ERROR:
		REDEBUG("Client error");

		vp = fr_pair_find_by_da(request->packet->vps, attr_eap_aka_sim_client_error_code, TAG_ANY);
		if (!vp) {
			REDEBUG("Peer rejected %s with EAP-Response/Client-Error message but "
				"has not supplied AT_ERROR_CODE",
				module_state_method_to_str(aka_state_table, eap_session->process, "<unknown>"));
		} else {
			REDEBUG("Client rejected %s with error: %pV (%i)",
				module_state_method_to_str(aka_state_table, eap_session->process, "<unknown>"),
				&vp->data, vp->vp_uint16);
		}

		eap_aka_sim_session->allow_encrypted = false;

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_client_error,
						      RLM_MODULE_NOOP,
						      aka_client_error_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	RFC 4187 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case.
	 */
	default:
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);

		eap_aka_sim_session->allow_encrypted = false;

		return common_failure_notification_enter(inst, request, eap_session);
	}
}

/** Process to response to our EAP-Request/AKA-Identity message
 *
 * Usually this will be an EAP-Response/AKA-Identity containing AT_IDENTITY.
 */
static rlm_rcode_t common_identity(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t		rcode;
	eap_aka_sim_state_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	VALUE_PAIR		*subtype_vp = NULL;
	VALUE_PAIR		*vps;

	rcode = common_decode(&subtype_vp, &vps, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif

	switch (subtype_vp->vp_uint16) {
	/*
	 *	This is the subtype we expect
	 */
	case FR_SUBTYPE_VALUE_IDENTITY:
	{
		VALUE_PAIR	*id;

		/*
		 *	The supplicant could in theory not send
		 *	and identity, and the user could configure
		 *	one in policy.
		 *
		 *	This isn't supported by the standard, but
		 *	who knows what arbitrary hacks vendors will
		 *	require.
		 */
		id = fr_pair_find_by_da(request->packet->vps, attr_eap_aka_sim_identity, TAG_ANY);
		if (id) {
			/*
			 *	Add ID hint attributes to the request to help
			 *	the user make policy decisions.
			 */
			id_hint_pairs_add(request, id->vp_strvalue);
		}

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_identity_response,
						      RLM_MODULE_NOOP,
						      common_identity_response_recv_resume,
						      mod_signal,
						      NULL);
	}

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 *
	 *	This can happen in the case of a conservative
	 *	peer, where it refuses to provide the permanent
	 *	identity.
	 */
	case FR_SUBTYPE_VALUE_CLIENT_ERROR:
		return unlang_module_yield_to_section(request,
						      inst->actions.recv_client_error,
						      RLM_MODULE_NOOP,
						      aka_client_error_recv_resume,
						      mod_signal,
						      NULL);

	default:
		/*
		 *	RFC 4187 says we *MUST* notify, not just
		 *	send an EAP-Failure in this case.
		 */
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
		return common_failure_notification_enter(inst, request, eap_session);
	}
}

/** Give the user the opportunity to override defaults for requesting another identity, and the type of identity
 *
 */
static rlm_rcode_t common_eap_identity_resume(void *instance, UNUSED void *thread, REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_state_conf_t			*inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR			*eap_type;
	VALUE_PAIR			*method;
	VALUE_PAIR			*identity_type;
	fr_aka_sim_method_hint_t	running, hinted;

	section_rcode_process(inst, request, eap_session);

	/*
	 *	Ignore attempts to change the EAP-Type
	 *	This must be done before we enter
	 *	the submodule.
	 */
	eap_type = fr_pair_find_by_da(request->control, attr_eap_type, TAG_ANY);
	if (eap_type) RWDEBUG("Ignoring &control:EAP-Type, this must be set *before* the EAP module is called");

	method = fr_pair_find_by_da(request->packet->vps, attr_eap_aka_sim_method_hint, TAG_ANY);

	/*
	 *	Set default configuration, we may allow these
	 *	to be toggled by attributes later.
	 */
	eap_aka_sim_session->send_result_ind = inst->protected_success;
	eap_aka_sim_session->id_req = AKA_SIM_NO_ID_REQ;	/* Set the default */

	/*
	 *	Unless AKA-Prime is explicitly disabled,
	 *	use it... It has stronger keying, and
	 *	binds authentication to the network.
	 */
	switch (eap_session->type) {
	case FR_EAP_METHOD_SIM:
		RDEBUG2("New EAP-SIM session");

		running = AKA_SIM_METHOD_HINT_SIM;

		eap_aka_sim_session->type = FR_EAP_METHOD_SIM;
		eap_aka_sim_session->checkcode_md = eap_aka_sim_session->mac_md = EVP_sha1();

		/*
		 *	RFC 5448 makes no mention of being
		 *	able to use this with EAP-SIM, so it's
		 *	permanently disabled.
		 */
		eap_aka_sim_session->send_at_bidding_prefer_prime = false;
		break;

	case FR_EAP_METHOD_AKA:
		RDEBUG2("New EAP-AKA session");

		running = AKA_SIM_METHOD_HINT_AKA;

		eap_aka_sim_session->type = FR_EAP_METHOD_AKA;
		eap_aka_sim_session->checkcode_md = eap_aka_sim_session->mac_md = EVP_sha1();
		eap_aka_sim_session->send_at_bidding_prefer_prime = inst->send_at_bidding_prefer_prime;
		break;

	default:
	case FR_EAP_METHOD_AKA_PRIME:

		RDEBUG2("New EAP-AKA' session");

		running = AKA_SIM_METHOD_HINT_AKA_PRIME;

		eap_aka_sim_session->type = FR_EAP_METHOD_AKA_PRIME;
		eap_aka_sim_session->kdf = FR_KDF_VALUE_PRIME_WITH_CK_PRIME_IK_PRIME;
		eap_aka_sim_session->checkcode_md = eap_aka_sim_session->mac_md = EVP_sha256();
		break;
	}

	/*
	 *	Warn the user if the selected identity
	 *	does not match what's hinted.
	 */
	if (method) {
		switch (method->vp_uint32) {
		case FR_METHOD_HINT_VALUE_AKA_PRIME:
			hinted = AKA_SIM_METHOD_HINT_AKA_PRIME;
			break;

		case FR_METHOD_HINT_VALUE_AKA:
			hinted = AKA_SIM_METHOD_HINT_AKA;
			break;

		case FR_METHOD_HINT_VALUE_SIM:
			hinted = AKA_SIM_METHOD_HINT_SIM;
			break;

		default:
			hinted = running;
			break;
		}

		if (hinted != running) {
			RWDEBUG("EAP-Identity hints that EAP-%s should be started, but we're attempting %s",
				fr_int2str(fr_aka_sim_id_method_table, hinted, "<INVALID>"),
				fr_int2str(fr_aka_sim_id_method_table, running, "<INVALID>"));
		}
	}

	/*
	 *	We always start by requesting any ID
	 *	initially as we can always negotiate down.
	 */
	if (!id_req_set_by_user(request, eap_aka_sim_session)) {
		if (request->rcode == RLM_MODULE_NOTFOUND) {
			eap_aka_sim_session->id_req = AKA_SIM_ANY_ID_REQ;
			RDEBUG2("Previous section returned 'notfound', requesting identity with %s",
				fr_int2str(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
		} else if (inst->request_identity != AKA_SIM_NO_ID_REQ) {
			eap_aka_sim_session->id_req = inst->request_identity;
			RDEBUG2("\"request_identity = %s\", requesting additional identity",
				fr_int2str(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
		}
	}

	/*
	 *	User may want us to always request an identity
	 *	initially.  The RFC says this is also the
	 *	better way to operate, as the supplicant
	 *	can 'decorate' the identity in the identity
	 *	response.
	 */
	if (eap_aka_sim_session->id_req != AKA_SIM_NO_ID_REQ) return common_identity_enter(inst, request, eap_session);

	/*
	 *	If we're not requesting the identity, then
	 *	whatever we got in the EAP-Identity-Response
	 *	is used to provide input to the KDF and
	 *	we enter the challenge phase.
	 *
	 *	We don't provide the user an opportunity to
	 *	change this identity, as the RFCs are very
	 *	explicit about it either being the value
	 *	from AT_IDENTITY, OR the value from the
	 *	EAP-Identity-Response.
	 */
	eap_aka_sim_session->keys.identity_len = talloc_array_length(eap_session->identity) - 1;
	MEM(eap_aka_sim_session->keys.identity = talloc_memdup(eap_aka_sim_session, eap_session->identity,
							       eap_aka_sim_session->keys.identity_len));

	/*
	 *	If the identity looks like a fast re-auth id
	 *	run fast re-auth, otherwise do a fullauth.
	 */
	identity_type = fr_pair_find_by_da(request->packet->vps, attr_eap_aka_sim_identity_type, TAG_ANY);
	if (identity_type) switch (identity_type->vp_uint32) {
	case FR_IDENTITY_TYPE_VALUE_FASTAUTH:
		return aka_reauthentication_enter(inst, request, eap_session);

	/*
	 *	It's a pseudonym, which now needs resolving.
	 *	The resume function here calls aka_challenge_enter
	 *	if pseudonym resolution went ok.
	 */
	case FR_IDENTITY_TYPE_VALUE_PSEUDONYM:
		return unlang_module_yield_to_section(request,
						      inst->actions.load_pseudonym,
						      RLM_MODULE_NOOP,
						      pseudonym_load_resume,
						      mod_signal,
						      NULL);

	/*
	 *	If it's a permanent ID, copy it over to
	 *	the session state list for use in the
	 *      store pseudonym/store session sections
	 *	later.
	 */
	case FR_IDENTITY_TYPE_VALUE_PERMANENT:
	{
		VALUE_PAIR *vp;

		vp = fr_pair_find_by_da(request->packet->vps, attr_eap_aka_sim_identity, TAG_ANY);
		if (vp) id_to_permanent_id(request, vp, eap_aka_sim_session->type);
	}
		/* FALL-THROUGH */

	default:
		break;
	}

	return aka_challenge_enter(inst, request, eap_session);
}

/** Zero out the eap_aka_sim_session when we free it to clear knowledge of secret keys
 *
 * @param[in] eap_aka_sim_session	to free.
 * @return 0
 */
static int _eap_aka_sim_session_free(eap_aka_sim_session_t *eap_aka_sim_session)
{
	memset(eap_aka_sim_session, 0, sizeof(*eap_aka_sim_session));
	return 0;
}

/** Initiate the EAP-SIM/AKA['] session by starting the eap_aka_sim_state machine
 *
 * The entry point called by EAP-SIM/EAP-AKA/EAP-AKA'
 */
rlm_rcode_t aka_sim_state_machine_start(void *instance, UNUSED void *thread, REQUEST *request)
{
	eap_aka_sim_state_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_state_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session;

	MEM(eap_aka_sim_session = talloc_zero(eap_session, eap_aka_sim_session_t));
	talloc_set_destructor(eap_aka_sim_session, _eap_aka_sim_session_free);

	eap_session->opaque = eap_aka_sim_session;

	/*
	 *	This value doesn't have be strong, but it is
	 *	good if it is different now and then.
	 */
	eap_aka_sim_session->id = (fr_rand() & 0xff);

	/*
	 *	Add ID hint attributes to the request to help
	 *	the user make policy decisions.
	 */
	if (eap_session->identity) {
		VALUE_PAIR *vp;

		id_hint_pairs_add(request, eap_session->identity);

		/*
		 *	Copy the EAP-Identity into and Identity
		 *	attribute to make policies easier.
		 */
		MEM(pair_add_request(&vp, attr_eap_aka_sim_identity) >= 0);
		fr_pair_value_bstrncpy(vp, eap_session->identity, talloc_array_length(eap_session->identity) - 1);
	}

	/*
	 *	Running the same section as Identity-Response
	 *	makes policies significantly easier.
	 */
	return unlang_module_yield_to_section(request,
					      inst->actions.recv_identity_response,
					      RLM_MODULE_NOOP,
					      common_eap_identity_resume,
					      mod_signal,
					      NULL);
}
