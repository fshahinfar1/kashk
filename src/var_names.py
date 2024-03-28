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

# Map names
SHARED_MAP_NAME = '__shared_map'
CHANNEL_MAP_NAME = '__channel'

# Map entry count
CHANNEL_UNITS = 4096 # means shared channel size is (4096 x 1024) = 4MB
CACHE_SIZE = 1024 # Number of elements in the internal cache

# Struct names
UNIT_STRUCT_NMAE = '__unit'
CACHE_ITEM_STRUCT_NAME = '__cache_item'

# For struct __unit:
UNIT_MEM_FIELD = 'mem'
FAILURE_NUMBER_FIELD = 'failure_number'

UNIT_SIZE = 1024
# For struct __cache_item
CACHE_KEY_MAX_SIZE = 255
CACHE_VALUE_MAX_SIZE = 255
