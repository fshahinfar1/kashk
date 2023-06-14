class UserProg:
    def __init__(self):
        self._path_number_gen = 0
        self.paths = []

    def add_path(self, inst):
        """
        @param inst: expect it to be a `Block' of code.
        """
        path = UserPath(inst)
        self.paths.append(path)


class UserPath:
    _path_number_gen = 0

    def __init__(self, inst):
        self.body = inst
        self.number = UserPath._path_number_gen
        UserPath._path_number_gen += 1
        # TODO: how am I going to implement this?
        self.states_it_need = []
