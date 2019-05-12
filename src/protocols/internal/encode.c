ssize_t fr_internal_encode_pair(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	unsigned int		depth = 0;
	fr_dict_attr_t const	*tlv_stack[FR_DICT_MAX_TLV_STACK + 1];
	ssize_t			len;

	vp = first_encodable(cursor, encoder_ctx);
	if (!vp) return -1;

	fr_proto_tlv_stack_build(tlv_stack, vp->da);

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	We only have two types of options in the internal protocol
	 */
	switch (tlv_stack[depth]->type) {
	case FR_TYPE_TLV:
		len = encode_tlv_hdr(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
		break;

	default:
		len = encode_rfc_hdr(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
		break;
	}

	if (len <= 0) return len;

	FR_PROTO_TRACE("Complete option is %zu byte(s)", len);
	FR_PROTO_HEX_DUMP(out, len, NULL);

	return len;
}
