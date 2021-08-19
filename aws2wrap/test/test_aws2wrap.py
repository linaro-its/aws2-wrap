"""Unittests for aws2wrap."""
import contextlib
import io
import os
import unittest
from unittest.mock import mock_open, patch

import aws2wrap

# pylint: disable=missing-class-docstring,missing-function-docstring

BASIC_CONFIG_FILE = """\
[default]
region = us-east-1
output = json
"""

SOURCE_CONFIG_FILE = """\
[default]
region = us-east-1
output = json

[profile source]
source_profile = default
"""

class TestReadAwsConfig(unittest.TestCase):
    """Test the profile retrieval code"""

    def test_specified_path(self):
        os.environ["AWS_CONFIG_FILE"] = "/foo/bar"
        with patch("builtins.open", mock_open(read_data=BASIC_CONFIG_FILE)) as mock_file:
            _, _ = aws2wrap.read_aws_config()
            mock_file.assert_called_with("/foo/bar", encoding=None)

    def test_default_path(self):
        # Clear AWS_CONFIG_FILE environment variable if it is set.
        # That causes read_aws_config to use a default path, which is
        # what we are testing for here.
        if "AWS_CONFIG_FILE" in os.environ:
            os.environ.pop("AWS_CONFIG_FILE")
        # The code expands "~" so we need to work out what the path
        # *should* be for later comparison
        path_to_file = os.path.abspath(os.path.expanduser("~/.aws/config"))
        with patch("builtins.open", mock_open(read_data=BASIC_CONFIG_FILE)) as mock_file:
            _, _ = aws2wrap.read_aws_config()
            mock_file.assert_called_with(path_to_file, encoding=None)

    def test_missing_profile(self):
        os.environ["AWS_CONFIG_FILE"] = "/foo/bar"
        with patch("builtins.open", mock_open(read_data=BASIC_CONFIG_FILE)):
            with self.assertRaises(aws2wrap.Aws2WrapError) as exc:
                _ = aws2wrap.retrieve_profile("foo")
        self.assertEqual("Cannot find profile 'foo' in /foo/bar", str(exc.exception))

    def test_default_retrieval(self):
        os.environ["AWS_CONFIG_FILE"] = "/foo/bar"
        with patch("builtins.open", mock_open(read_data=BASIC_CONFIG_FILE)):
            profile = aws2wrap.retrieve_profile("default")
        self.assertEqual(profile["profile_name"], "default")
        self.assertEqual(profile["region"], "us-east-1")
        self.assertEqual(profile["output"], "json")

    def test_source_retrieval(self):
        os.environ["AWS_CONFIG_FILE"] = "/foo/bar"
        with patch("builtins.open", mock_open(read_data=SOURCE_CONFIG_FILE)):
            profile = aws2wrap.retrieve_profile("source")
        self.assertTrue("source_profile" in profile)
        self.assertEqual(profile["profile_name"], "source")
        self.assertEqual(profile["source_profile"]["profile_name"], "default")
        self.assertEqual(profile["source_profile"]["region"], "us-east-1")
        self.assertEqual(profile["source_profile"]["output"], "json")

class TestProcessArguments(unittest.TestCase):
    """Test a few cases of the cli parsing to ensure it is functional."""

    def test_no_args(self):
        args = aws2wrap.process_arguments(['aws2-wrap'])
        self.assertFalse(args.export)
        self.assertFalse(args.generate)

    def test_exclusive(self):
        fake = io.StringIO()
        with self.assertRaises(SystemExit) as exc, contextlib.redirect_stderr(fake):
            aws2wrap.process_arguments(['aws2-wrap', '--export', '--generate'])
        self.assertEqual(exc.exception.code, 2)
        self.assertTrue(
            "argument --generate: not allowed with argument --export" in fake.getvalue())


class TestRetrieveAttribute(unittest.TestCase):

    def test_success(self):
        self.assertEqual(42, aws2wrap.retrieve_attribute({'answer': 42}, 'answer'))

    def test_failure(self):
        with self.assertRaises(aws2wrap.Aws2WrapError):
            aws2wrap.retrieve_attribute({'answer': 42}, 'question')
