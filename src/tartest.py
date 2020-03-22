#!/usr/bin/env python3

import unittest
import tar
import os

class TarTest(unittest.TestCase):
    
    def test_get_all_files(self):
        # given
        with tar.Tar("tartest.tar") as t:
            
            # when
            files = t.get_all_files()

            # then
            self.assertTrue(len(files) == 5)
            self.assertTrue(self.containsFile(files, "tartest/a.txt"))
            self.assertTrue(self.containsFile(files, "tartest/b.txt"))
            self.assertTrue(self.containsFile(files, "tartest/foo/c.txt"))

    def test_extract_file(self):
        # given
        with tar.Tar("tartest.tar") as t:

            # when
            t.extract_file("tartest/a.txt")
            t.extract_file("tartest/foo/c.txt")

            # then
            self.assertTrue(os.path.isfile("a.txt"))
            self.assertTrue(self.fileContains("a.txt", "This is file a"))

            self.assertTrue(os.path.isfile("c.txt"))
            self.assertTrue(self.fileContains("c.txt", "This is file c"))

            os.remove("a.txt")
            os.remove("c.txt")

    def test_extract_all(self):
        # given
        with tar.Tar("tartest.tar") as t:

            # when
            t.extract_all()

            # then
            self.assertTrue(os.path.isdir("tartest"))
            self.assertTrue(os.path.isdir("tartest/foo"))
            self.assertTrue(os.path.isfile("tartest/a.txt"))
            self.assertTrue(os.path.isfile("tartest/b.txt"))
            self.assertTrue(os.path.isfile("tartest/foo/c.txt"))

            os.system("rm -rf tartest")

    def containsFile(self, files, file_name):
        for f in files:
            if f.file_name == file_name:
                return True
        return False

    def fileContains(self, file_name, content):
        with open(file_name) as f:
            return content == f.read().splitlines()[0]

if __name__ == '__main__':
    unittest.main()