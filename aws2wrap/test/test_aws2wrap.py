"""Unittests for aws2wrap."""
import contextlib
import io
import json
import os
from subprocess import CalledProcessError
import unittest
from unittest.mock import mock_open, patch

import aws2wrap

# pylint: disable=missing-class-docstring,missing-function-docstring

class TestGetRoleCredentials(unittest.TestCase):
    """Test get_role_credentials code"""

    PROFILE = {
        "profile_name": "dummy profile name",
        "sso_start_url": "dummy sso start url",
        "sso_region": "dummy sso region",
        "sso_account_id": "dummy sso account id",
        "sso_role_name": "dummy sso role name"
    }

    FULL_BLOB = {
        "startUrl": "dummy sso start url",
        "region": "dummy sso region",
        "expiresAt": "2100-10-31T13:15:06Z",
        "accessToken": "NotAtAllValid"
    }

    @patch('pathlib.Path.iterdir')
    @patch("aws2wrap.subprocess.run")
    def test_exception(self, mock_subprocess, mock_iterdir):
        mock_iterdir.return_value = ["bar"]
        mock_subprocess.side_effect = CalledProcessError(returncode=1, cmd="")
        with self.assertRaises(aws2wrap.Aws2WrapError) as exc:
            with patch(
                    "builtins.open",
                    mock_open(read_data=json.dumps(self.FULL_BLOB))) as mock_file:
                _ = aws2wrap.get_role_credentials(self.PROFILE)
                mock_file.assert_called_with("bar", "r")
        self.assertEqual(
            "Please login with 'aws sso login --profile=dummy profile name'",
            str(exc.exception))

    class MockSubprocessStdout: # pylint: disable=too-few-public-methods
        stdout = '{"roleCredentials":{"expiration": 10000}}'

    @patch('pathlib.Path.iterdir')
    @patch("aws2wrap.subprocess.run")
    def test_result(self, mock_subprocess, mock_iterdir):
        mock_subprocess.return_value = self.MockSubprocessStdout
        mock_iterdir.return_value = ["bar"]
        with patch(
                "builtins.open",
                mock_open(read_data=json.dumps(self.FULL_BLOB))) as mock_file:
            result = aws2wrap.get_role_credentials(self.PROFILE)
            mock_file.assert_called_with("bar", "r")
        # Check we got a valid response
        self.assertEqual(result["roleCredentials"]["expiration"], '1970-01-01T00:00:10+00:00')


class TestRetrieveToken(unittest.TestCase):
    """Test retrieve_token code"""

    FULL_BLOB = {
        "startUrl": "https://jim.bob",
        "region": "foobar",
        "expiresAt": "2100-10-31T13:15:06Z",
        "accessToken": "NotAtAllValid"
    }

    @patch('pathlib.Path.iterdir')
    def test_empty_dir(self, mock_listdir):
        mock_listdir.return_value = []
        with self.assertRaises(aws2wrap.Aws2WrapError) as exc:
            _ = aws2wrap.retrieve_token(
                "fred", "bob", "jim")
        self.assertEqual("Please login with 'aws sso login --profile=jim'", str(exc.exception))

    @patch('pathlib.Path.iterdir')
    def test_token_retrieval(self, mock_listdir):
        mock_listdir.return_value = ["bar"]
        with patch(
                "builtins.open",
                mock_open(read_data=json.dumps(self.FULL_BLOB))) as mock_file:
            result = aws2wrap.retrieve_token("https://jim.bob", "foobar", "jim")
            mock_file.assert_called_with("bar", "r")
        self.assertEqual(result, "NotAtAllValid")


class TestRetrieveTokenFromFile(unittest.TestCase):
    """Test token retrival code"""

    STARTURL_TEST_BLOB = {
        "startUrl": "https://jim.bob"
    }

    FULL_BLOB = {
        "startUrl": "https://jim.bob",
        "region": "foobar",
        "expiresAt": "2100-10-31T13:15:06Z",
        "accessToken": "NotAtAllValid"
    }

    EXPIRED_BLOB = {
        "startUrl": "https://jim.bob",
        "region": "foobar",
        "expiresAt": "2000-10-31T13:15:06Z",
        "accessToken": "NotAtAllValid"
    }

    def test_no_starturl(self):
        with patch("builtins.open", mock_open(read_data="{}")) as mock_file:
            result = aws2wrap.retrieve_token_from_file("/foo/bar", None, None)
            mock_file.assert_called_with("/foo/bar", "r")
        self.assertEqual(result, None)

    def test_starturl_not_equal(self):
        with patch(
                "builtins.open",
                mock_open(read_data=json.dumps(self.STARTURL_TEST_BLOB))) as mock_file:
            result = aws2wrap.retrieve_token_from_file("/foo/bar", "https://sue.mary", None)
            mock_file.assert_called_with("/foo/bar", "r")
        self.assertEqual(result, None)

    def test_no_region(self):
        with patch(
                "builtins.open",
                mock_open(read_data=json.dumps(self.STARTURL_TEST_BLOB))) as mock_file:
            result = aws2wrap.retrieve_token_from_file("/foo/bar", "https://jim.bob", None)
            mock_file.assert_called_with("/foo/bar", "r")
        self.assertEqual(result, None)

    def test_region_not_equal(self):
        with patch(
                "builtins.open",
                mock_open(read_data=json.dumps(self.FULL_BLOB))) as mock_file:
            result = aws2wrap.retrieve_token_from_file("/foo/bar", "https://jim.bob", "nowhere")
            mock_file.assert_called_with("/foo/bar", "r")
        self.assertEqual(result, None)

    def test_expired_token(self):
        with patch(
                "builtins.open",
                mock_open(read_data=json.dumps(self.EXPIRED_BLOB))) as mock_file:
            result = aws2wrap.retrieve_token_from_file("/foo/bar", "https://jim.bob", "foobar")
            mock_file.assert_called_with("/foo/bar", "r")
        self.assertEqual(result, None)

    def test_access_token(self):
        with patch(
                "builtins.open",
                mock_open(read_data=json.dumps(self.FULL_BLOB))) as mock_file:
            result = aws2wrap.retrieve_token_from_file("/foo/bar", "https://jim.bob", "foobar")
            mock_file.assert_called_with("/foo/bar", "r")
        self.assertEqual(result, "NotAtAllValid")


class TestReadAwsConfig(unittest.TestCase):
    """Test the profile retrieval code"""

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

    def test_specified_path(self):
        os.environ["AWS_CONFIG_FILE"] = "/foo/bar"
        with patch("builtins.open", mock_open(read_data=self.BASIC_CONFIG_FILE)) as mock_file:
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
        with patch("builtins.open", mock_open(read_data=self.BASIC_CONFIG_FILE)) as mock_file:
            _, _ = aws2wrap.read_aws_config()
            mock_file.assert_called_with(path_to_file, encoding=None)

    def test_missing_profile(self):
        os.environ["AWS_CONFIG_FILE"] = "/foo/bar"
        with patch("builtins.open", mock_open(read_data=self.BASIC_CONFIG_FILE)):
            with self.assertRaises(aws2wrap.Aws2WrapError) as exc:
                _ = aws2wrap.retrieve_profile("foo")
        self.assertEqual("Cannot find profile 'foo' in /foo/bar", str(exc.exception))

    def test_default_retrieval(self):
        os.environ["AWS_CONFIG_FILE"] = "/foo/bar"
        with patch("builtins.open", mock_open(read_data=self.BASIC_CONFIG_FILE)):
            profile = aws2wrap.retrieve_profile("default")
        self.assertEqual(profile["profile_name"], "default")
        self.assertEqual(profile["region"], "us-east-1")
        self.assertEqual(profile["output"], "json")

    def test_source_retrieval(self):
        os.environ["AWS_CONFIG_FILE"] = "/foo/bar"
        with patch("builtins.open", mock_open(read_data=self.SOURCE_CONFIG_FILE)):
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
