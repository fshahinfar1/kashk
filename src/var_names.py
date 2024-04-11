# Local variable names
SIZE_DELTA_VAR = '__size_delta'
ZERO_VAR = '__zero'
EXTRA_PARAM_NAME = '__ex'
DATA_VAR = '__data'
DATA_END_VAR = '__data_end'
ITERATOR_VAR = '__i'
FAIL_FLAG_NAME = '__fail_flag'
SEND_FLAG_NAME = '__send_flag'
SHARED_REF_NAME = '__shared'
CHANNEL_VAR_NAME = '__c'
FLOW_ID_VAR_NAME = '__flow_id'
SOCK_STATE_VAR_NAME = '__sk_ctx'

# Internal function names
GET_FLOW_ID = '__get_conn_id'

# Map names
SHARED_MAP_NAME = '__shared_map'
CHANNEL_MAP_NAME = '__channel'
SOCK_MAP_NAME = 'sock_map'
SOCK_STATE_MAP_NAME = 'conn_ctx_map'

# Map entry count
CHANNEL_UNITS = 4096 # means shared channel size is (4096 x 1024) = 4MB
CACHE_SIZE = 1024 # Number of elements in the internal cache

# Struct names
UNIT_STRUCT_NMAE = '__unit'
CACHE_ITEM_STRUCT_NAME = '__cache_item'
SHARED_STATE_STRUCT_NAME = 'shared_state'
FIVE_TUPLE_STRUCT_NAME  = '__five_tuple'
SOCK_STATE_STRUCT_NAME = 'sock_context'

# For struct __unit:
UNIT_MEM_FIELD = 'mem'
FAILURE_NUMBER_FIELD = 'failure_number'
UNIT_SIZE = 1024

# For struct __cache_item
CACHE_KEY_MAX_SIZE = 255
CACHE_VALUE_MAX_SIZE = 255
