from instruction import Cast
from helpers.instruction_helper import U64, VOID_PTR
def cast_data(ref):
    cast1 = Cast.build(ref, U64)
    cast2 = Cast.build(cast1, VOID_PTR)
    return cast2
