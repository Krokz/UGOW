from permstore import path_to_win


class TestPathToWin:
    def test_c_drive_root(self):
        assert path_to_win("/mnt/c") == "C:\\"

    def test_c_drive_file(self):
        assert path_to_win("/mnt/c/Users/me/file.txt") == "C:\\Users\\me\\file.txt"

    def test_d_drive(self):
        assert path_to_win("/mnt/d/bar/baz") == "D:\\bar\\baz"

    def test_lowercase_drive_uppercased(self):
        assert path_to_win("/mnt/e/data") == "E:\\data"

    def test_non_mnt_path_unchanged(self):
        assert path_to_win("/home/user/file") == "/home/user/file"

    def test_short_path_unchanged(self):
        assert path_to_win("/mnt") == "/mnt"

    def test_root_unchanged(self):
        assert path_to_win("/") == "/"

    def test_deep_nesting(self):
        assert path_to_win("/mnt/c/a/b/c/d") == "C:\\a\\b\\c\\d"
