"""
This a data type to be used in a code pass.
The use-case is to mark instruction that should be placed after the currently
processed node in a pass.

For adding nodes before the current node under inspection, the pass can find
the block buffer (using CodeBlockRef) and add its instructions. But since the
current node is not added yet, it is a bit weird to add instructions after it
without disrupting the normal flow our pass. The idea is to place the
instructions in this container and add it before the current instruction, then
in the pass they are moved forward to the correct place.
"""
class After:
    def __init__(self, box):
        self.box = box
