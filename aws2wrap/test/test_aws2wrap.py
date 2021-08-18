"""Unittests for aws2wrap."""


import unittest
from unittest import mock

import aws2wrap

# pylint: disable=missing-class-docstring,missing-function-docstring


class FakeSysExit(Exception):
    """Fake Exception for sys.exit calls."""


class TestRetrieveAttribute(unittest.TestCase):
    def setUp(self) -> None:
        self.addCleanup(mock.patch.stopall)
        self.exit = mock.patch('sys.exit').start()
        self.exit.side_effect = FakeSysExit()

    def test_success(self):
        self.assertEqual(42, aws2wrap.retrieve_attribute({'answer': 42}, 'answer'))
        self.exit.assert_not_called()

    def test_failure(self):
        with self.assertRaises(FakeSysExit):
            aws2wrap.retrieve_attribute({'answer': 42}, 'question')
            self.exit.assert_called_once_with()
