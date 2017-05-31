class Structure:
    def __init__(self):
        self.member_name = ()
        self.member = ()
        self._format = ""
        self.size = 0
        return

    def get_format_string(fmt_tuple):
        format = ''
        for f in fmt_tuple:
            format += f
        return format

    def get_attr(self, name):
        for (index, value) in enumerate(self._member_name):
            if value == name:
                return self.member[index]

    def show_member(self):
        for i in range(0, len(self._member_name)):
            if isinstance(self.member[i], int):
                value = hex(self.member[i])
            else:
                value = self.member[i]
            print("\t{:<40}({}) {}".format(
                self._member_name[i] + ":", self._format[i],  value)
            )
