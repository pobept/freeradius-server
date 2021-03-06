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
 * $Id$
 * @file rlm_pap.c
 * @brief Hashes plaintext passwords to compare against a prehashed reference.
 *
 * @copyright 2001-2012 The FreeRADIUS server project.
 * @copyright 2012 Matthew Newton (matthew@newtoncomputing.co.uk)
 * @copyright 2001 Kostas Kalevras (kkalev@noc.ntua.gr)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/crypt.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/password.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/sha1.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.password.h>

#include <ctype.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

/*
 *      Define a structure for our module configuration.
 *
 *      These variables do not need to be in a structure, but it's
 *      a lot cleaner to do so, and a pointer to the structure can
 *      be used as the instance handle.
 */
typedef struct {
	char const		*name;
	fr_dict_enum_t		*auth_type;
	bool			normify;
} rlm_pap_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("normalise", FR_TYPE_BOOL, rlm_pap_t, normify), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_pap_dict[];
fr_dict_autoload_t rlm_pap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_proxy_to_realm;
static fr_dict_attr_t const *attr_realm;

static fr_dict_attr_t const *attr_cleartext_password;
static fr_dict_attr_t const *attr_password_with_header;

static fr_dict_attr_t const *attr_md5_password;
static fr_dict_attr_t const *attr_smd5_password;
static fr_dict_attr_t const *attr_crypt_password;
static fr_dict_attr_t const *attr_sha_password;
static fr_dict_attr_t const *attr_ssha_password;

static fr_dict_attr_t const *attr_sha2_password;
static fr_dict_attr_t const *attr_ssha2_224_password;
static fr_dict_attr_t const *attr_ssha2_256_password;
static fr_dict_attr_t const *attr_ssha2_384_password;
static fr_dict_attr_t const *attr_ssha2_512_password;

static fr_dict_attr_t const *attr_sha3_password;
static fr_dict_attr_t const *attr_ssha3_224_password;
static fr_dict_attr_t const *attr_ssha3_256_password;
static fr_dict_attr_t const *attr_ssha3_384_password;
static fr_dict_attr_t const *attr_ssha3_512_password;

static fr_dict_attr_t const *attr_pbkdf2_password;
static fr_dict_attr_t const *attr_lm_password;
static fr_dict_attr_t const *attr_nt_password;
static fr_dict_attr_t const *attr_ns_mta_md5_password;

static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_pap_dict_attr[];
fr_dict_attr_autoload_t rlm_pap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_proxy_to_realm, .name = "Proxy-To-Realm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_realm, .name = "Realm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_cleartext_password, .name = "Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_password_with_header, .name = "Password-With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_md5_password, .name = "MD5-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_smd5_password, .name = "SMD5-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_crypt_password, .name = "Crypt-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_sha_password, .name = "SHA-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha_password, .name = "SSHA-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_sha2_password, .name = "SHA2-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_224_password, .name = "SSHA2-224-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_256_password, .name = "SSHA2-256-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_384_password, .name = "SSHA2-384-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_512_password, .name = "SSHA2-512-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_sha3_password, .name = "SHA3-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_224_password, .name = "SSHA3-224-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_256_password, .name = "SSHA3-256-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_384_password, .name = "SSHA3-384-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_512_password, .name = "SSHA3-512-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_pbkdf2_password, .name = "PBKDF2-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_lm_password, .name = "LM-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_nt_password, .name = "NT-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ns_mta_md5_password, .name = "NS-MTA-MD5-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

/*
 *	For auto-header discovery.
 *
 *	@note Header comparison is case insensitive.
 */
static const FR_NAME_NUMBER header_names[] = {
	{ "{clear}",		FR_CLEARTEXT_PASSWORD },
	{ "{cleartext}",	FR_CLEARTEXT_PASSWORD },
	{ "{md5}",		FR_MD5_PASSWORD },
	{ "{base64_md5}",	FR_MD5_PASSWORD },
	{ "{smd5}",		FR_SMD5_PASSWORD },
	{ "{crypt}",		FR_CRYPT_PASSWORD },
#ifdef HAVE_OPENSSL_EVP_H
	{ "{sha2}",		FR_SHA2_PASSWORD },
	{ "{sha224}",		FR_SHA2_PASSWORD },
	{ "{sha256}",		FR_SHA2_PASSWORD },
	{ "{sha384}",		FR_SHA2_PASSWORD },
	{ "{sha512}",		FR_SHA2_PASSWORD },
	{ "{ssha224}",		FR_SSHA2_224_PASSWORD },
	{ "{ssha256}",		FR_SSHA2_256_PASSWORD },
	{ "{ssha384}",		FR_SSHA2_384_PASSWORD },
	{ "{ssha512}",		FR_SSHA2_512_PASSWORD },
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	{ "{ssha3-224}",	FR_SSHA3_224_PASSWORD },
	{ "{ssha3-256}",	FR_SSHA3_256_PASSWORD },
	{ "{ssha3-384}",	FR_SSHA3_384_PASSWORD },
	{ "{ssha3-512}",	FR_SSHA3_512_PASSWORD },
#  endif
	{ "{x-pbkdf2}",		FR_PBKDF2_PASSWORD },
#endif
	{ "{sha}",		FR_SHA_PASSWORD },
	{ "{ssha}",		FR_SSHA_PASSWORD },
	{ "{md4}",		FR_NT_PASSWORD },
	{ "{nt}",		FR_NT_PASSWORD },
	{ "{nthash}",		FR_NT_PASSWORD },
	{ "{x-nthash}",		FR_NT_PASSWORD },
	{ "{ns-mta-md5}",	FR_NS_MTA_MD5_PASSWORD },
	{ "{x- orcllmv}",	FR_LM_PASSWORD },
	{ "X- orclntv}",	FR_NT_PASSWORD },
	{ NULL, 0 }
};

#ifdef HAVE_OPENSSL_EVP_H
static const FR_NAME_NUMBER pbkdf2_crypt_names[] = {
	{ "HMACSHA1",		FR_SSHA_PASSWORD },
	{ "HMACSHA2+224",	FR_SSHA2_224_PASSWORD },
	{ "HMACSHA2+256",	FR_SSHA2_256_PASSWORD },
	{ "HMACSHA2+384",	FR_SSHA2_384_PASSWORD },
	{ "HMACSHA2+512",	FR_SSHA2_512_PASSWORD },
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	{ "HMACSHA3+224",	FR_SSHA3_224_PASSWORD },
	{ "HMACSHA3+256",	FR_SSHA3_256_PASSWORD },
	{ "HMACSHA3+384",	FR_SSHA3_384_PASSWORD },
	{ "HMACSHA3+512",	FR_SSHA3_512_PASSWORD },
#  endif
	{ NULL, 0 }
};

static const FR_NAME_NUMBER pbkdf2_passlib_names[] = {
	{ "sha1",		FR_SSHA_PASSWORD },
	{ "sha256",		FR_SSHA2_256_PASSWORD },
	{ "sha512",		FR_SSHA2_512_PASSWORD },

	{ NULL, 0 }
};
#endif

static ssize_t pap_password_header(fr_dict_attr_t const **out, char const *header)
{
	switch (fr_str2int(header_names, header, 0)) {
	case FR_CLEARTEXT_PASSWORD:
		*out = attr_cleartext_password;
		break;

	case FR_MD5_PASSWORD:
		*out = attr_md5_password;
		break;

	case FR_SMD5_PASSWORD:
		*out = attr_smd5_password;
		break;

	case FR_CRYPT_PASSWORD:
		*out = attr_crypt_password;
		break;

	case FR_SHA2_PASSWORD:
		*out = attr_sha2_password;
		break;

	case FR_SSHA2_224_PASSWORD:
		*out = attr_ssha2_224_password;
		break;

	case FR_SSHA2_256_PASSWORD:
		*out = attr_ssha2_256_password;
		break;

	case FR_SSHA2_384_PASSWORD:
		*out = attr_ssha2_384_password;
		break;

	case FR_SSHA2_512_PASSWORD:
		*out = attr_ssha2_512_password;
		break;

	case FR_SSHA3_224_PASSWORD:
		*out = attr_ssha3_224_password;
		break;

	case FR_SSHA3_256_PASSWORD:
		*out = attr_ssha3_256_password;
		break;

	case FR_SSHA3_384_PASSWORD:
		*out = attr_ssha3_384_password;
		break;

	case FR_SSHA3_512_PASSWORD:
		*out = attr_ssha3_512_password;
		break;

	case FR_PBKDF2_PASSWORD:
		*out = attr_pbkdf2_password;
		break;

	case FR_SHA_PASSWORD:
		*out = attr_sha_password;
		break;

	case FR_SSHA_PASSWORD:
		*out = attr_ssha_password;
		break;

	case FR_NS_MTA_MD5_PASSWORD:
		*out = attr_ns_mta_md5_password;
		break;

	case FR_LM_PASSWORD:
		*out = attr_lm_password;
		break;

	case FR_NT_PASSWORD:
		*out = attr_nt_password;
		break;

	default:
		*out = NULL;
		return -1;
	}

	return strlen(header);
}

/*
 *	Authorize the user for PAP authentication.
 *
 *	This isn't strictly necessary, but it does make the
 *	server simpler to configure.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_pap_t const 	*inst = instance;
	bool			found_pw = false;
	VALUE_PAIR		*known_good, *password;
	fr_cursor_t		cursor;
	size_t			normify_min_len = 0;

	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);
	if (!password) {
		RDEBUG2("No %s attribute in the request.  Cannot do PAP", attr_user_password->name);
		return RLM_MODULE_NOOP;
	}

	for (known_good = fr_cursor_init(&cursor, &request->control);
	     known_good;
	     known_good = fr_cursor_next(&cursor)) {
	     	VP_VERIFY(known_good);
	next:
		if (known_good->da == attr_user_password) {
			RWDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			RWDEBUG("!!! Ignoring control:User-Password.  Update your        !!!");
			RWDEBUG("!!! configuration so that the \"known good\" clear text !!!");
			RWDEBUG("!!! password is in Cleartext-Password and NOT in        !!!");
			RWDEBUG("!!! User-Password.                                      !!!");
			RWDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		} else if (known_good->da == attr_password_with_header) {
			VALUE_PAIR *new;

			/*
			 *	Password already exists: use that instead of this one.
			 */
			if (fr_pair_find_by_da(request->control, attr_cleartext_password, TAG_ANY)) {
				RWDEBUG("Config already contains a \"known good\" password "
					"(&control:%s).  Ignoring &control:%s",
					attr_cleartext_password->name, known_good->da->name);
				break;
			}

			MEM(new = password_normify_with_header(request, request, known_good,
							       pap_password_header,
							       attr_cleartext_password));
			if (RDEBUG_ENABLED3) {
				RDEBUG3("Normalized &control:%pP -> &control:%pP", known_good, new);
			} else {
				RDEBUG2("Normalized &control:%s -> &control:%s", known_good->da->name, new->da->name);
			}
			RDEBUG2("Removing &control:%s", known_good->da->name);
			fr_cursor_free_item(&cursor);			/* advances the cursor for us */
			fr_cursor_append(&cursor, new);			/* inserts at the end of the list */

			found_pw = true;

			known_good = fr_cursor_current(&cursor);
			if (known_good) goto next;
		} else if ((known_good->da == attr_cleartext_password) ||
			   (known_good->da == attr_crypt_password) ||
			   (known_good->da == attr_ns_mta_md5_password)) {
			found_pw = true;
		} else if ((known_good->da == attr_md5_password) ||
			   (known_good->da == attr_smd5_password) ||
			   (known_good->da == attr_nt_password) ||
			   (known_good->da == attr_lm_password)) {
			if (inst->normify) normify_min_len = 16;
			found_pw = true;
		}
#ifdef HAVE_OPENSSL_EVP_H
		else if (known_good->da == attr_sha2_password) {
			if (inst->normify) normify_min_len = 28;
			found_pw = true;
		} else if (known_good->da == attr_ssha2_224_password) {
			if (inst->normify) normify_min_len = 28;
			found_pw = true;
		} else if (known_good->da == attr_ssha2_256_password) {
			if (inst->normify) normify_min_len = 32;
			found_pw = true;
		} else if (known_good->da == attr_ssha2_384_password) {
			if (inst->normify) normify_min_len = 48;
			found_pw = true;
		} else if (known_good->da == attr_ssha2_512_password) {
			if (inst->normify) normify_min_len = 64;
			found_pw = true;
		}
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
		else if (known_good->da == attr_sha3_password) {
			if (inst->normify) normify_min_len = 28;
			found_pw = true;
		} else if (known_good->da == attr_ssha3_224_password) {
			if (inst->normify) normify_min_len = 28;
			found_pw = true;
		} else if (known_good->da == attr_ssha3_256_password) {
			if (inst->normify) normify_min_len = 32;
			found_pw = true;
		} else if (known_good->da == attr_ssha3_384_password) {
			if (inst->normify) normify_min_len = 48;
			found_pw = true;
		} else if (known_good->da == attr_ssha3_512_password) {
			if (inst->normify) normify_min_len = 64;
			found_pw = true;
		}
#  endif
		else if (known_good->da == attr_pbkdf2_password) {
			found_pw = true; /* Already base64 standardized */
		}
#endif
		else if ((known_good->da == attr_sha_password) ||
			 (known_good->da == attr_ssha_password)) {
			if (inst->normify) normify_min_len = 20;
			found_pw = true;
		}

		if (normify_min_len > 0) {
			VALUE_PAIR *new;

			new = password_normify(request, request, known_good, normify_min_len);
			if (new) {
				fr_cursor_free_item(&cursor);		/* free the old pasword */
				fr_cursor_append(&cursor, new);		/* inserts at the end of the list */

				known_good = fr_cursor_current(&cursor);
				if (known_good) goto next;
			}
		}
	}

	/*
	 *	Print helpful warnings if there was no password.
	 */
	if (!found_pw) {
		/*
		 *	Likely going to be proxied.  Avoid printing
		 *	warning message.
		 */
		if (fr_pair_find_by_da(request->control, attr_realm, TAG_ANY) ||
		    (fr_pair_find_by_da(request->control, attr_proxy_to_realm, TAG_ANY))) {
			return RLM_MODULE_NOOP;
		}

		RWDEBUG("No \"known good\" password found for the user.  Not setting Auth-Type");
		RWDEBUG("Authentication will fail unless a \"known good\" password is available");

		return RLM_MODULE_NOOP;
	}

	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) return RLM_MODULE_NOOP;

	return RLM_MODULE_UPDATED;
}

/*
 *	PAP authentication functions
 */

static rlm_rcode_t CC_HINT(nonnull) pap_auth_clear(UNUSED rlm_pap_t const *inst, REQUEST *request,
						   VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	if ((known_good->vp_length != password->vp_length) ||
	    (fr_digest_cmp(known_good->vp_octets, password->vp_octets, known_good->vp_length) != 0)) {
		REDEBUG("Cleartext password does not match \"known good\" password");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Expected   : %pV", &known_good->data);
		return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;
}

#ifdef HAVE_CRYPT
static rlm_rcode_t CC_HINT(nonnull) pap_auth_crypt(UNUSED rlm_pap_t const *inst, REQUEST *request,
						   VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	if (fr_crypt_check(password->vp_strvalue, known_good->vp_strvalue) != 0) {
		REDEBUG("Crypt digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;
}
#endif

static rlm_rcode_t CC_HINT(nonnull) pap_auth_md5(UNUSED rlm_pap_t const *inst, REQUEST *request,
						 VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	uint8_t digest[MD5_DIGEST_LENGTH];

	if (known_good->vp_length != MD5_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" MD5 password has incorrect length, expected 16 got %zu", known_good->vp_length);
		return RLM_MODULE_INVALID;
	}

	fr_md5_calc(digest, password->vp_octets, password->vp_length);

	if (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0) {
		REDEBUG("MD5 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, MD5_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, MD5_DIGEST_LENGTH));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}


static rlm_rcode_t CC_HINT(nonnull) pap_auth_smd5(UNUSED rlm_pap_t const *inst, REQUEST *request,
						  VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	fr_md5_ctx_t	*md5_ctx;
	uint8_t		digest[MD5_DIGEST_LENGTH];

	if (known_good->vp_length <= MD5_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SMD5-Password has incorrect length, expected 16 got %zu", known_good->vp_length);
		return RLM_MODULE_INVALID;
	}

	md5_ctx = fr_md5_ctx_alloc(true);
	fr_md5_update(md5_ctx, password->vp_octets, password->vp_length);
	fr_md5_update(md5_ctx, known_good->vp_octets + MD5_DIGEST_LENGTH, known_good->vp_length - MD5_DIGEST_LENGTH);
	fr_md5_final(digest, md5_ctx);
	fr_md5_ctx_free(&md5_ctx);

	/*
	 *	Compare only the MD5 hash results, not the salt.
	 */
	if (fr_digest_cmp(digest, known_good->vp_octets, MD5_DIGEST_LENGTH) != 0) {
		REDEBUG("SMD5 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, MD5_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, MD5_DIGEST_LENGTH));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_sha(UNUSED rlm_pap_t const *inst, REQUEST *request,
						 VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	fr_sha1_ctx	sha1_context;
	uint8_t		digest[SHA1_DIGEST_LENGTH];

	if (known_good->vp_length != SHA1_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SHA1-password has incorrect length, expected 20 got %zu", known_good->vp_length);
		return RLM_MODULE_INVALID;
	}

	fr_sha1_init(&sha1_context);
	fr_sha1_update(&sha1_context, password->vp_octets, password->vp_length);
	fr_sha1_final(digest,&sha1_context);

	if (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0) {
		REDEBUG("SHA1 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, SHA1_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, SHA1_DIGEST_LENGTH));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ssha(UNUSED rlm_pap_t const *inst, REQUEST *request,
						  VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	fr_sha1_ctx	sha1_context;
	uint8_t		digest[SHA1_DIGEST_LENGTH];

	if (known_good->vp_length <= SHA1_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SSHA-Password has incorrect length, expected > 20 got %zu", known_good->vp_length);
		return RLM_MODULE_INVALID;
	}

	fr_sha1_init(&sha1_context);
	fr_sha1_update(&sha1_context, password->vp_octets, password->vp_length);

	fr_sha1_update(&sha1_context, known_good->vp_octets + SHA1_DIGEST_LENGTH, known_good->vp_length - SHA1_DIGEST_LENGTH);
	fr_sha1_final(digest, &sha1_context);

	if (fr_digest_cmp(digest, known_good->vp_octets, SHA1_DIGEST_LENGTH) != 0) {
		REDEBUG("SSHA digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Salt       : %pH", fr_box_octets(known_good->vp_octets + SHA1_DIGEST_LENGTH,
							   known_good->vp_length - SHA1_DIGEST_LENGTH));
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, SHA1_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, SHA1_DIGEST_LENGTH));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

#ifdef HAVE_OPENSSL_EVP_H
static rlm_rcode_t CC_HINT(nonnull) pap_auth_sha_evp(UNUSED rlm_pap_t const *inst, REQUEST *request,
						     VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	EVP_MD_CTX	*ctx;
	EVP_MD const	*md;
	char const	*name;
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digest_len;

	if (known_good->da == attr_sha2_password) {
		/*
		 *	All the SHA-2 algorithms produce digests of different lengths,
		 *	so it's trivial to determine which EVP_MD to use.
		 */
		switch (known_good->vp_length) {
		/* SHA2-224 */
		case SHA224_DIGEST_LENGTH:
			name = "SHA2-224";
			md = EVP_sha224();
			break;

		/* SHA2-256 */
		case SHA256_DIGEST_LENGTH:
			name = "SHA2-256";
			md = EVP_sha256();
			break;

		/* SHA2-384 */
		case SHA384_DIGEST_LENGTH:
			name = "SHA2-384";
			md = EVP_sha384();
			break;

		/* SHA2-512 */
		case SHA512_DIGEST_LENGTH:
			name = "SHA2-512";
			md = EVP_sha512();
			break;

		default:
			REDEBUG("\"known good\" digest length (%zu) does not match output length of any SHA-2 digests",
				known_good->vp_length);
			return RLM_MODULE_INVALID;
		}
	}
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	else if (known_good->da == attr_sha3_password) {
		/*
		 *	All the SHA-3 algorithms produce digests of different lengths,
		 *	so it's trivial to determine which EVP_MD to use.
		 */
		switch (known_good->vp_length) {
		/* SHA3-224 */
		case SHA224_DIGEST_LENGTH:
			name = "SHA3-224";
			md = EVP_sha3_224();
			break;

		/* SHA3-256 */
		case SHA256_DIGEST_LENGTH:
			name = "SHA3-256";
			md = EVP_sha3_256();
			break;

		/* SHA3-384 */
		case SHA384_DIGEST_LENGTH:
			name = "SHA3-384";
			md = EVP_sha3_384();
			break;

		/* SHA3-512 */
		case SHA512_DIGEST_LENGTH:
			name = "SHA3-512";
			md = EVP_sha3_512();
			break;

		default:
			REDEBUG("\"known good\" digest length (%zu) does not match output length of any SHA-3 digests",
				known_good->vp_length);
			return RLM_MODULE_INVALID;
		}
	}
#  endif
	else {
		rad_assert(0);
		return RLM_MODULE_INVALID;
	}

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, password->vp_octets, password->vp_length);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_destroy(ctx);

	rad_assert((size_t) digest_len == known_good->vp_length);	/* This would be an OpenSSL bug... */

	if (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0) {
		REDEBUG("%s digest does not match \"known good\" digest", name);
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pH", &known_good->data);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ssha_evp(UNUSED rlm_pap_t const *inst, REQUEST *request,
						      VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	EVP_MD_CTX	*ctx;
	EVP_MD const	*md = NULL;
	char const	*name = NULL;
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digest_len, min_len = 0;

	if (known_good->da == attr_ssha2_224_password) {
		name = "SSHA2-224";
		md = EVP_sha224();
		min_len = SHA224_DIGEST_LENGTH;
	} else if (known_good->da == attr_ssha2_256_password) {
		name = "SSHA2-256";
		md = EVP_sha256();
		min_len = SHA256_DIGEST_LENGTH;
	} else if (known_good->da == attr_ssha2_384_password) {
		name = "SSHA2-384";
		md = EVP_sha384();
		min_len = SHA384_DIGEST_LENGTH;
	} else if (known_good->da == attr_ssha2_512_password) {
		name = "SSHA2-512";
		min_len = SHA512_DIGEST_LENGTH;
		md = EVP_sha512();
	}
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	else if (known_good->da == attr_ssha3_224_password) {
		name = "SSHA3-224";
		md = EVP_sha3_224();
		min_len = SHA224_DIGEST_LENGTH;
	} else if (known_good->da == attr_ssha3_256_password) {
		name = "SSHA3-256";
		md = EVP_sha3_256();
		min_len = SHA256_DIGEST_LENGTH;
	} else if (known_good->da == attr_ssha3_384_password) {
		name = "SSHA3-384";
		md = EVP_sha3_384();
		min_len = SHA384_DIGEST_LENGTH;
	} else if (known_good->da == attr_ssha3_512_password) {
		name = "SSHA3-512";
		min_len = SHA512_DIGEST_LENGTH;
		md = EVP_sha3_512();
	}
#endif
	else {
		rad_assert(0);
		return RLM_MODULE_INVALID;
	}

	if (known_good->vp_length <= min_len) {
		REDEBUG("\"known-good\" %s-Password has incorrect length, got %zu bytes, need at least %u bytes",
			name, known_good->vp_length, min_len + 1);
		return RLM_MODULE_INVALID;
	}

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, password->vp_octets, password->vp_length);
	EVP_DigestUpdate(ctx, known_good->vp_octets + min_len, known_good->vp_length - min_len);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_destroy(ctx);

	rad_assert((size_t) digest_len == min_len);	/* This would be an OpenSSL bug... */

	/*
	 *	Only compare digest_len bytes, the rest is salt.
	 */
	if (fr_digest_cmp(digest, known_good->vp_octets, (size_t)digest_len) != 0) {
		REDEBUG("%s digest does not match \"known good\" digest", name);
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Salt       : %pH",
			 fr_box_octets(known_good->vp_octets + min_len, known_good->vp_length - min_len));
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pH", &known_good->data);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

/** Validates Crypt::PBKDF2 LDAP format strings
 *
 * @param[in] request	The current request.
 * @param[in] str	Raw PBKDF2 string.
 * @param[in] len	Length of string.
 * @return
 *	- RLM_MODULE_REJECT
 *	- RLM_MODULE_OK
 */
static inline rlm_rcode_t CC_HINT(nonnull) pap_auth_pbkdf2_parse(REQUEST *request, const uint8_t *str, size_t len,
								 FR_NAME_NUMBER const hash_names[],
								 char scheme_sep, char iter_sep, char salt_sep,
								 bool iter_is_base64, VALUE_PAIR const *password)
{
	rlm_rcode_t		rcode = RLM_MODULE_INVALID;

	uint8_t const		*p, *q, *end;
	ssize_t			slen;

	EVP_MD const		*evp_md;
	int			digest_type;
	size_t			digest_len;

	uint32_t		iterations;

	uint8_t			*salt = NULL;
	size_t			salt_len;
	uint8_t			hash[EVP_MAX_MD_SIZE];
	uint8_t			digest[EVP_MAX_MD_SIZE];

	RDEBUG2("Comparing with \"known-good\" PBKDF2-Password");

	if (len <= 1) {
		REDEBUG("PBKDF2-Password is too short");
		goto finish;
	}

	/*
	 *	Parse PBKDF string = {hash_algorithm}<scheme_sep><iterations><iter_sep>b64(<salt>)<salt_sep>b64(<hash>)
	 */
	p = str;
	end = p + len;

	q = memchr(p, scheme_sep, end - p);
	if (!q) {
		REDEBUG("PBKDF2-Password has no component separators");
		goto finish;
	}

	digest_type = fr_substr2int(hash_names, (char const *)p, -1, q - p);
	switch (digest_type) {
	case FR_SSHA_PASSWORD:
		evp_md = EVP_sha1();
		digest_len = SHA1_DIGEST_LENGTH;
		break;

	case FR_SSHA2_224_PASSWORD:
		evp_md = EVP_sha224();
		digest_len = SHA224_DIGEST_LENGTH;
		break;

	case FR_SSHA2_256_PASSWORD:
		evp_md = EVP_sha256();
		digest_len = SHA256_DIGEST_LENGTH;
		break;

	case FR_SSHA2_384_PASSWORD:
		evp_md = EVP_sha384();
		digest_len = SHA384_DIGEST_LENGTH;
		break;

	case FR_SSHA2_512_PASSWORD:
		evp_md = EVP_sha512();
		digest_len = SHA512_DIGEST_LENGTH;
		break;

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	case FR_SSHA3_224_PASSWORD:
		evp_md = EVP_sha3_224();
		digest_len = SHA224_DIGEST_LENGTH;
		break;

	case FR_SSHA3_256_PASSWORD:
		evp_md = EVP_sha3_256();
		digest_len = SHA256_DIGEST_LENGTH;
		break;

	case FR_SSHA3_384_PASSWORD:
		evp_md = EVP_sha3_384();
		digest_len = SHA384_DIGEST_LENGTH;
		break;

	case FR_SSHA3_512_PASSWORD:
		evp_md = EVP_sha3_512();
		digest_len = SHA512_DIGEST_LENGTH;
		break;
#  endif

	default:
		REDEBUG("Unknown PBKDF2 hash method \"%.*s\"", (int)(q - p), p);
		goto finish;
	}

	p = q + 1;

	if (((end - p) < 1) || !(q = memchr(p, iter_sep, end - p))) {
		REDEBUG("PBKDF2-Password missing iterations component");
		goto finish;
	}

	if ((q - p) == 0) {
		REDEBUG("PBKDF2-Password iterations component too short");
		goto finish;
	}

	/*
	 *	If it's not base64 encoded, assume it's ascii
	 */
	if (!iter_is_base64) {
		char iterations_buff[sizeof("4294967295") + 1];
		char *qq;

		strlcpy(iterations_buff, (char const *)p, (q - p) + 1);

		iterations = strtoul(iterations_buff, &qq, 10);
		if (*qq != '\0') {
			REMARKER(iterations_buff, qq - iterations_buff,
				 "PBKDF2-Password iterations field contains an invalid character");

			goto finish;
		}
		p = q + 1;
	/*
	 *	base64 encoded and big endian
	 */
	} else {
		(void)fr_strerror();
		slen = fr_base64_decode((uint8_t *)&iterations, sizeof(iterations), (char const *)p, q - p);
		if (slen < 0) {
			RPEDEBUG("Failed decoding PBKDF2-Password iterations component (%.*s)", (int)(q - p), p);
			goto finish;
		}
		if (slen != sizeof(iterations)) {
			REDEBUG("Decoded PBKDF2-Password iterations component is wrong size");
		}

		iterations = ntohl(iterations);

		p = q + 1;
	}

	if (((end - p) < 1) || !(q = memchr(p, salt_sep, end - p))) {
		REDEBUG("PBKDF2-Password missing salt component");
		goto finish;
	}

	if ((q - p) == 0) {
		REDEBUG("PBKDF2-Password salt component too short");
		goto finish;
	}

	MEM(salt = talloc_array(request, uint8_t, FR_BASE64_DEC_LENGTH(q - p)));
	slen = fr_base64_decode(salt, talloc_array_length(salt), (char const *) p, q - p);
	if (slen < 0) {
		RPEDEBUG("Failed decoding PBKDF2-Password salt component");
		goto finish;
	}
	salt_len = (size_t)slen;

	p = q + 1;

	if ((q - p) == 0) {
		REDEBUG("PBKDF2-Password hash component too short");
		goto finish;
	}

	slen = fr_base64_decode(hash, sizeof(hash), (char const *)p, end - p);
	if (slen < 0) {
		RPEDEBUG("Failed decoding PBKDF2-Password hash component");
		goto finish;
	}

	if ((size_t)slen != digest_len) {
		REDEBUG("PBKDF2-Password hash component length is incorrect for hash type, expected %zu, got %zd",
			digest_len, slen);

		RHEXDUMP2(hash, slen, "hash component");

		goto finish;
	}

	RDEBUG2("PBKDF2 %s: Iterations %u, salt length %zu, hash length %zd",
		fr_int2str(pbkdf2_crypt_names, digest_type, "<UNKNOWN>"),
		iterations, salt_len, slen);

	/*
	 *	Hash and compare
	 */
	if (PKCS5_PBKDF2_HMAC((char const *)password->vp_octets, (int)password->vp_length,
			      (unsigned char const *)salt, (int)salt_len,
			      (int)iterations,
			      evp_md,
			      (int)digest_len, (unsigned char *)digest) == 0) {
		REDEBUG("PBKDF2 digest failure");
		goto finish;
	}

	if (fr_digest_cmp(digest, hash, (size_t)digest_len) != 0) {
		REDEBUG("PBKDF2 digest does not match \"known good\" digest");
		REDEBUG3("Salt       : %pH", fr_box_octets(salt, salt_len));
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pH", fr_box_octets(hash, slen));
		rcode = RLM_MODULE_REJECT;
	} else {
		rcode = RLM_MODULE_OK;
	}

finish:
	talloc_free(salt);

	return rcode;
}

static inline rlm_rcode_t CC_HINT(nonnull) pap_auth_pbkdf2(UNUSED rlm_pap_t const *inst,
							   REQUEST *request,
							   VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	uint8_t const *p = known_good->vp_octets, *q, *end = p + known_good->vp_length;

	if (end - p < 2) {
		REDEBUG("PBKDF2-Password too short");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	If it doesn't begin with a $ assume
	 *	It's Crypt::PBKDF2 LDAP format
	 *
	 *	{X-PBKDF2}<digest>:<b64 rounds>:<b64_salt>:<b64_hash>
	 */
	if (*p != '$') {
		/*
		 *	Strip the header if it's present
		 */
		if (*p == '{') {
			q = memchr(p, '}', end - p);
			p = q + 1;
		}
		return pap_auth_pbkdf2_parse(request, p, end - p,
					     pbkdf2_crypt_names, ':', ':', ':', true, password);
	}

	/*
	 *	Crypt::PBKDF2 Crypt format
	 *
	 *	$PBKDF2$<digest>:<rounds>:<b64_salt>$<b64_hash>
	 */
	if ((size_t)(end - p) >= sizeof("$PBKDF2$") && (memcmp(p, "$PBKDF2$", sizeof("$PBKDF2$") - 1) == 0)) {
		p += sizeof("$PBKDF2$") - 1;
		return pap_auth_pbkdf2_parse(request, p, end - p,
					     pbkdf2_crypt_names, ':', ':', '$', false, password);
	}

	/*
	 *	Python's passlib format
	 *
	 *	$pbkdf2-<digest>$<rounds>$<alt_b64_salt>$<alt_b64_hash>
	 *
	 *	Note: Our base64 functions also work with alt_b64
	 */
	if ((size_t)(end - p) >= sizeof("$pbkdf2-") && (memcmp(p, "$pbkdf2-", sizeof("$pbkdf2-") - 1) == 0)) {
		p += sizeof("$pbkdf2-") - 1;
		return pap_auth_pbkdf2_parse(request, p, end - p,
					     pbkdf2_passlib_names, '$', '$', '$', false, password);
	}

	REDEBUG("Can't determine format of PBKDF2-Password");

	return RLM_MODULE_INVALID;
}
#endif

static rlm_rcode_t CC_HINT(nonnull) pap_auth_nt(UNUSED rlm_pap_t const *inst, REQUEST *request,
						VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	ssize_t len;
	uint8_t digest[MD4_DIGEST_LENGTH];
	uint8_t ucs2_password[512];

	RDEBUG2("Comparing with \"known-good\" NT-Password");

	rad_assert(password->da == attr_user_password);

	if (known_good->vp_length != MD4_DIGEST_LENGTH) {
		REDEBUG("\"known good\" NT-Password has incorrect length, expected 16 got %zu", known_good->vp_length);
		return RLM_MODULE_INVALID;
	}

	len = fr_utf8_to_ucs2(ucs2_password, sizeof(ucs2_password),
			      password->vp_strvalue, password->vp_length);
	if (len < 0) {
		REDEBUG("User-Password is not in UCS2 format");
		return RLM_MODULE_INVALID;
	}

	fr_md4_calc(digest, (uint8_t *)ucs2_password, len);

	if (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0) {
		REDEBUG("NT digest does not match \"known good\" digest");
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, sizeof(digest)));
		REDEBUG3("Expected   : %pH", &known_good->data);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_lm(UNUSED rlm_pap_t const *inst, REQUEST *request,
						VALUE_PAIR *known_good, UNUSED VALUE_PAIR const *password)
{
	uint8_t	digest[MD4_DIGEST_LENGTH];
	char	charbuf[32 + 1];
	ssize_t	len;

	RDEBUG2("Comparing with \"known-good\" LM-Password");

	if (known_good->vp_length != MD4_DIGEST_LENGTH) {
		REDEBUG("\"known good\" LM-Password has incorrect length, expected 16 got %zu", known_good->vp_length);
		return RLM_MODULE_INVALID;
	}

	len = xlat_eval(charbuf, sizeof(charbuf), request, "%{mschap:LM-Hash %{User-Password}}", NULL, NULL);
	if (len < 0) return RLM_MODULE_FAIL;

	if ((fr_hex2bin(digest, sizeof(digest), charbuf, len) != known_good->vp_length) ||
	    (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0)) {
		REDEBUG("LM digest does not match \"known good\" digest");
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, sizeof(digest)));
		REDEBUG3("Expected   : %pH", &known_good->data);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ns_mta_md5(UNUSED rlm_pap_t const *inst, REQUEST *request,
							VALUE_PAIR *known_good, VALUE_PAIR const *password)
{
	uint8_t digest[128];
	uint8_t buff[FR_MAX_STRING_LEN];
	uint8_t buff2[FR_MAX_STRING_LEN + 50];

	RDEBUG2("Using NT-MTA-MD5-Password");

	if (known_good->vp_length != 64) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password has incorrect length, expected 64 got %zu", known_good->vp_length);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Sanity check the value of NS-MTA-MD5-Password
	 */
	if (fr_hex2bin(digest, sizeof(digest), known_good->vp_strvalue, known_good->vp_length) != 16) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password has invalid value");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Ensure we don't have buffer overflows.
	 *
	 *	This really: sizeof(buff) - 2 - 2*32 - strlen(passwd)
	 */
	if (password->vp_length >= (sizeof(buff) - 2 - 2 * 32)) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password is too long");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Set up the algorithm.
	 */
	{
		uint8_t *p = buff2;

		memcpy(p, &known_good->vp_octets[32], 32);
		p += 32;
		*(p++) = 89;
		memcpy(p, password->vp_strvalue, password->vp_length);
		p += password->vp_length;
		*(p++) = 247;
		memcpy(p, &known_good->vp_octets[32], 32);
		p += 32;

		fr_md5_calc(buff, (uint8_t *) buff2, p - buff2);
	}

	if (fr_digest_cmp(digest, buff, 16) != 0) {
		REDEBUG("NS-MTA-MD5 digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}


/*
 *	Authenticate the user via one of any well-known password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_pap_t const *inst = instance;
	VALUE_PAIR	*known_good, *password;
	rlm_rcode_t	rcode = RLM_MODULE_INVALID;
	fr_cursor_t	cursor;
	rlm_rcode_t	(*auth_func)(rlm_pap_t const *, REQUEST *, VALUE_PAIR *, VALUE_PAIR const *) = NULL;

	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);
	if (!password) {
		REDEBUG("You set 'Auth-Type = PAP' for a request that does not contain a User-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	The user MUST supply a non-zero-length password.
	 */
	if (password->vp_length == 0) {
		REDEBUG("Password must not be empty");
		return RLM_MODULE_INVALID;
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Login attempt with password \"%pV\" (%zd)",
			fr_box_strvalue_len(password->vp_strvalue, password->vp_length),
			password->vp_length);
	} else {
		RDEBUG2("Login attempt with password");
	}

	/*
	 *	Auto-detect passwords, by attribute in the
	 *	config items, to find out which authentication
	 *	function to call.
	 */
	for (known_good = fr_cursor_init(&cursor, &request->control);
	     known_good;
	     known_good = fr_cursor_next(&cursor)) {
		if (!fr_dict_attr_is_top_level(known_good->da)) continue;

		if (known_good->da == attr_cleartext_password) {
			auth_func = &pap_auth_clear;
#ifdef HAVE_CRYPT
		} else if (known_good->da == attr_crypt_password) {
			auth_func = &pap_auth_crypt;
#endif
		} else if (known_good->da == attr_md5_password) {
			auth_func = &pap_auth_md5;
		} else if (known_good->da == attr_smd5_password) {
			auth_func = &pap_auth_smd5;
		}
#ifdef HAVE_OPENSSL_EVP_H
		else if (known_good->da == attr_sha2_password
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
			 || (known_good->da == attr_sha3_password)
#  endif
			) {
			auth_func = &pap_auth_sha_evp;
		} else if ((known_good->da == attr_ssha2_224_password) ||
		    (known_good->da == attr_ssha2_256_password) ||
		    (known_good->da == attr_ssha2_384_password) ||
		    (known_good->da == attr_ssha2_512_password)
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
		    || (known_good->da == attr_ssha3_224_password) ||
		    (known_good->da == attr_ssha3_256_password) ||
		    (known_good->da == attr_ssha3_384_password) ||
		    (known_good->da == attr_ssha3_512_password)
#  endif
		    ) {
			auth_func = &pap_auth_ssha_evp;
		} else if (known_good->da == attr_pbkdf2_password) {
			auth_func = &pap_auth_pbkdf2;
		}
#endif
		else if (known_good->da == attr_sha_password) {
			auth_func = &pap_auth_sha;
		} else if (known_good->da == attr_ssha_password) {
			auth_func = &pap_auth_ssha;
		} else if (known_good->da == attr_nt_password) {
			auth_func = &pap_auth_nt;
		} else if (known_good->da == attr_lm_password) {
			auth_func = &pap_auth_lm;
		} else if (known_good->da == attr_ns_mta_md5_password) {
			auth_func = &pap_auth_ns_mta_md5;
		}

		if (auth_func != NULL) break;
	}

	/*
	 *	No attribute was found that looked like a password to match.
	 */
	if (!auth_func) {
		REDEBUG("No \"known good\" password found for user");
		return RLM_MODULE_FAIL;
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Comparing with \"known good\" %pP (%zu)", known_good, known_good->vp_length);
	} else {
		RDEBUG2("Comparing with \"known-good\" %s (%zu)", known_good->da->name, known_good->vp_length);
	}

	/*
	 *	Authenticate, and return.
	 */
	rcode = auth_func(inst, request, known_good, password);
	switch (rcode) {
	case RLM_MODULE_REJECT:
		REDEBUG("Password incorrect");
		break;

	case RLM_MODULE_OK:
		RDEBUG2("User authenticated successfully");
		break;

	default:
		break;
	}

	return rcode;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	char const		*name;
	rlm_pap_t		*inst = instance;

	/*
	 *	Create the dynamic translation.
	 */
	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->name = name;

	if (fr_dict_enum_add_alias_next(attr_auth_type, inst->name) < 0) {
		PERROR("Failed adding %s alias", attr_auth_type->name);
		return -1;
	}
	inst->auth_type = fr_dict_enum_by_alias(attr_auth_type, inst->name, -1);
	rad_assert(inst->auth_type);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_pap;
module_t rlm_pap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "pap",
	.inst_size	= sizeof(rlm_pap_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
