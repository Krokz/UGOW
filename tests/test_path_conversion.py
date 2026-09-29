import os

import pytest

from permstore import kernel_dev, path_to_win


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


class TestNonDriveMntPaths:
    """/mnt also holds real WSL mounts that are not Windows drive letters."""

    def test_wsl_internal_mount_unchanged(self):
        assert path_to_win("/mnt/wsl/foo") == "/mnt/wsl/foo"

    def test_wslg_mount_unchanged(self):
        assert path_to_win("/mnt/wslg/x") == "/mnt/wslg/x"

    def test_multichar_dir_unchanged(self):
        assert path_to_win("/mnt/data/x") == "/mnt/data/x"

    def test_numeric_component_unchanged(self):
        assert path_to_win("/mnt/1/x") == "/mnt/1/x"

    def test_trailing_slash_mnt_unchanged(self):
        assert path_to_win("/mnt/") == "/mnt/"


class TestKernelDev:
    """BPF map keys hold super_block->s_dev, which is MKDEV(major, minor).

    stat()'s st_dev uses a different layout (new_encode_dev). The two agree
    only for major 0 with minor < 256 -- which is what a fresh WSL2 /mnt/c
    looks like, so a raw st_dev appears to work right up until an anonymous
    superblock minor passes 255 and enforcement quietly stops matching.
    """

    # Kept within one byte of major and 20 bits of minor so os.makedev round
    # trips on every platform a developer might run the suite on -- Darwin's
    # major field is 8 bits, glibc's is 12.
    DEVICES = [(0, 1), (0, 52), (0, 255), (0, 256), (0, 300), (0, 4096),
               (0, 0xFFFFF), (8, 1), (8, 300), (255, 255)]

    @staticmethod
    def _mkdev(major, minor):
        """The kernel's internal dev_t -- include/linux/kdev_t.h MKDEV()."""
        return (major << 20) | minor

    @staticmethod
    def _new_encode_dev(major, minor):
        """What stat() reports as st_dev -- include/linux/kdev_t.h."""
        return (minor & 0xFF) | (major << 8) | ((minor & ~0xFF) << 12)

    @pytest.mark.parametrize("major,minor", DEVICES)
    def test_converts_st_dev_to_the_kernels_encoding(self, major, minor):
        st_dev = os.makedev(major, minor)
        assert (os.major(st_dev), os.minor(st_dev)) == (major, minor)
        assert kernel_dev(st_dev) == self._mkdev(major, minor)

    @pytest.mark.parametrize("major,minor", DEVICES)
    def test_fits_the_u32_map_key(self, major, minor):
        assert kernel_dev(os.makedev(major, minor)) < 2 ** 32

    def test_the_two_kernel_encodings_really_do_diverge(self):
        """Pins down why the conversion is needed at all, independently of the
        host's libc: they agree only for major 0 with minor below 256."""
        assert self._new_encode_dev(0, 52) == self._mkdev(0, 52)
        assert self._new_encode_dev(0, 255) == self._mkdev(0, 255)
        assert self._new_encode_dev(0, 256) != self._mkdev(0, 256)
        assert self._new_encode_dev(0, 300) != self._mkdev(0, 300)
        assert self._new_encode_dev(8, 1) != self._mkdev(8, 1)
