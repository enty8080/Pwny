from .types import *

BUILTIN_BASE = 0

API_QUIT = tlv_custom(TLV_TYPE_INT, BUILTIN_BASE, 1)
API_ADD_NODE = tlv_custom(TLV_TYPE_INT, BUILTIN_BASE, 2)
API_DEL_NODE = tlv_custom(TLV_TYPE_INT, BUILTIN_BASE, 3)
API_ADD_TAB = tlv_custom(TLV_TYPE_INT, BUILTIN_BASE, 4)
API_DEL_TAB = tlv_custom(TLV_TYPE_INT, BUILTIN_BASE, 5)
API_MIGRATE = tlv_custom(TLV_TYPE_INT, BUILTIN_BASE, 6)
API_TEST = tlv_custom(TLV_TYPE_INT, BUILTIN_BASE, 7)