"""Deterministic filesystem races at Map Local's descriptor ownership boundary."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from local_mapping import local_response, read_regular


class LocalMappingOwnership(unittest.TestCase):
    def test_replacing_opened_root_with_outside_symlink_keeps_original_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, held, outside = (parent / name for name in ("root", "held", "outside"))
            root.mkdir()
            outside.mkdir()
            (root / "file.txt").write_bytes(b"selected root")
            (outside / "file.txt").write_bytes(b"outside secret")
            opened = os.open
            replaced = False

            def replace_before_child(path, flags, **options):
                nonlocal replaced
                if options.get("dir_fd") is not None and not replaced:
                    replaced = True
                    root.rename(held)
                    root.symlink_to(outside, target_is_directory=True)
                return opened(path, flags, **options)

            with patch("local_mapping.os.open", side_effect=replace_before_child):
                response = local_response("http://fixture/assets/file.txt", "http://fixture/assets/*", str(root))
            self.assertTrue(replaced)
            self.assertEqual(response.content, b"selected root")

    def test_file_growth_after_stat_is_bounded_without_closing_callers_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / "growing"
            file.write_bytes(b"12345678")
            descriptor = os.open(file, os.O_RDONLY)
            self.addCleanup(os.close, descriptor)
            inspect = os.fstat

            def grow_after_snapshot(fd):
                identity = inspect(fd)
                with file.open("ab") as writer:
                    writer.write(b"9")
                return identity

            with patch("local_mapping.BODY_BYTES", 8), patch("local_mapping.os.fstat", side_effect=grow_after_snapshot):
                with self.assertRaisesRegex(ValueError, "exceeds"):
                    read_regular(descriptor)
            self.assertEqual(inspect(descriptor).st_size, 9)


if __name__ == "__main__":
    unittest.main()
