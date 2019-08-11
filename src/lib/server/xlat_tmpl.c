/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 *
 * @file xlat_tmpl.c
 * @brief String expansion ("translation"). Creating xlat templates.
 *
 * @copyright 2019  The FreeRADIUS server project
 * @copyright 2019  Robert Biktimirov <pobept@gmail.com>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>
#include "xlat_priv.h"

#undef XLAT_DEBUG
#ifdef DEBUG_XLAT
#  define XLAT_DEBUG DEBUG3
#else
#  define XLAT_DEBUG(...)
#endif

/** Make xlat template
 *
 * @param[in] ctx		to allocate dynamic buffers in.
 * @param[out] out		Where to write the query literals and bind place holders.
 * @param[in] fmt		the format string to expand.
 * @param[in] bind_ph	function to get bind placeholder.
 * @param[out] tmpl		the head of the xlat list / tree structure.
 * @return
 *	- <=0 on error.
 *	- >0 on success.
 */
int xlat_tmpl(TALLOC_CTX *ctx, char **out, char const *fmt, xlat_tmpl_bind_ph_t bind_ph, xlat_exp_t ** tmpl)
{
	ssize_t slen;
	char * tokens;
	xlat_exp_t * node, *prev;
	int pi;
	
	*tmpl = NULL;

	/*
	 *	Copy the original format string to a buffer so that
	 *	the later functions can mangle it in-place, which is
	 *	much faster.
	 */
	tokens = talloc_typed_strdup(ctx, fmt);
	if (!tokens) return -1;

	fr_strerror();	/* Clear error buffer */
	slen = xlat_tokenize(ctx, tmpl, tokens, NULL);
	
	if (slen < 0) {
		talloc_free(tokens);
		return slen;
	}
	
	prev = NULL;
	pi = 0;
	node = *tmpl;
	while(node != NULL) {
		if(node->type == XLAT_LITERAL) {
			*out = talloc_strdup_append	(*out, node->fmt);
			if (node == *tmpl) {
				talloc_steal(ctx, node->next);
				*tmpl = node->next;
				talloc_free(node);
				node=*tmpl;
			} else {
				talloc_steal(ctx, prev->next);
				talloc_steal(ctx, node->next);
				prev->next = node->next;
				talloc_free(node);
				node = prev -> next;
			}
		} else {
			char * buf;
			
			bind_ph(ctx, pi++, node->type, &buf, 0);
			*out = talloc_strdup_append(*out, buf);
			TALLOC_FREE(buf);
			prev = node;
			node = node->next;
		}
	}
	XLAT_DEBUG("Compiled Query:%s", *out);
	for (node = *tmpl; node != NULL; node = node->next) {
		XLAT_DEBUG("Bind type=%d fmt=%s", node->type, node->fmt);
	}

	return pi-1;
}	


size_t xlat_process_sql_bind(TALLOC_CTX *ctx, REQUEST *request, xlat_exp_t const * const head,
			   xlat_sql_bind_t bind, void const *bind_ctx)
{
	int i, n;
	char *answer;
	xlat_exp_t const *node;

	n = 0;

	/*
	 *	There are no nodes to process, so the result is a zero
	 *	length string.
	 */
	if (!head) {
		return 0;
	}

	/*
	 *	Hack for speed.  If it's one expansion, just allocate
	 *	that and return, instead of allocating an intermediary
	 *	array.
	 */
	if (!head->next) {
		/*
		 *	Pass the MAIN escape function.  Recursive
		 *	calls will call node-specific escape
		 *	functions.
		 */
		answer = xlat_aprint(ctx, request, head, NULL, NULL, 0);
		if (!answer) {
			return 0;
		}
		bind(request, n, answer, bind_ctx);
		return n;
	}
	for (node = head, i = 0; node != NULL; node = node->next, i++) {
		answer  = xlat_aprint(ctx, request, node, NULL, NULL, 0); /* may be NULL */
		bind(request, n, answer, bind_ctx);
		n++;
		/*
		 *	Nasty temporary hack
		 *
		 *	If an async func is evaluated the async code will evaluate
		 *      all codes at that level.
		 *
		 *	Break here to avoid nodes being evaluated multiple times
		 *      and parts of strings being duplicated.
		 */
		if ((node->type == XLAT_FUNC) && (node->xlat->type == XLAT_FUNC_ASYNC)) {
			i++;
			break;
		}
	}

	return n-1;
}
