/** Decode an internal pair
 *
 * @param[in] ctx context	to alloc new attributes in.
 * @param[in,out] cursor	Where to write the decoded options.
 * @param[in] dict		to lookup attributes in.
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 * @param[in] decoder_ctx	Unused.
 */
ssize_t fr_internal_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			        fr_dict_t const *dict, uint8_t const *data, size_t data_len, UNUSED void *decoder_ctx)
{
	ssize_t			ret;
	uint8_t const		*p = data;
	fr_dict_attr_t const	*child;
	fr_dict_attr_t const	*parent;

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);

	if (data_len == 0) return 0;

	FR_PROTO_HEX_DUMP(data, data_len, NULL);

	parent = fr_dict_root(dict);

	/*
	 *	Padding / End of options
	 */
	if (p[0] == 0) return 1;		/* 0x00 - Padding option */
	if (p[0] == 255) {			/* 0xff - End of options signifier */
		size_t i;

		for (i = 1; i < data_len; i++) {
			if (p[i] != 0) {
				FR_PROTO_HEX_DUMP(p + i, data_len - i, "ignoring trailing junk at end of packet");
				break;
			}
		}
		return data_len;
	}

	/*
	 *	Everything else should be real options
	 */
	if ((data_len < 2) || (data[1] > data_len)) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

	child = fr_dict_attr_child_by_num(parent, p[0]);
	if (!child) {
		/*
		 *	Unknown attribute, create an octets type
		 *	attribute with the contents of the sub-option.
		 */
		child = fr_dict_unknown_afrom_fields(ctx, parent, fr_dict_vendor_num_by_da(parent), p[0]);
		if (!child) return -1;
	}
	FR_PROTO_TRACE("decode context changed %s:%s -> %s:%s",
		       fr_int2str(fr_value_box_type_table, parent->type, "<invalid>"), parent->name,
		       fr_int2str(fr_value_box_type_table, child->type, "<invalid>"), child->name);

	ret = decode_value(ctx, cursor, child, data + 2, data[1]);
	if (ret < 0) {
		fr_dict_unknown_free(&child);
		return ret;
	}
	ret += 2; /* For header */
	FR_PROTO_TRACE("decoding option complete, returning %zu byte(s)", ret);
	return ret;
}
