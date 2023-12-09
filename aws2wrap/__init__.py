#!/usr/bin/python3
#
# Copyright (c) 2022 Linaro Ltd
#

"""
Simple AWS Credentials wrapper.

A simple script that exports the accessKeyId, secretAccessKey and sessionToken
for the specified AWS SSO credentials, or it can run a subprocess with those
credentials.

This script is intended to plug a (hopefully temporary) gap in the official aws2
tool. As such, it makes certain assumptions about the cache file and does not
rely on boto3 because the aws2 tool packages a dev version.
"""

import argparse
import configparser
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone  # pylint: disable=wrong-import-order
from typing import (Any, Dict, List,  # pylint: disable=wrong-import-order
                    Optional, Tuple, Union, Callable, cast)

import psutil

from aws2wrap.version import __version__

ProfileDef = Dict[str, Union[str, Dict[str, Any]]]


class Aws2WrapError(Exception):
    """Base exception class for aws2wrap."""


def process_arguments(argv: List[str]) -> argparse.Namespace:
    """Check and extract arguments provided.

    Args:
        argv: The command line arguments, usually from sys.argv().
    Returns:
        The parsed command line.
    """
    parser = argparse.ArgumentParser(allow_abbrev=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--export",
        action="store_true",
        help="export credentials as environment variables")
    group.add_argument(
        "--generate",
        action="store_true",
        help="generate credentials from the input profile")
    parser.add_argument(
        "--generatestdout",
        action="store_true",
        help="generate credentials from the input profile and output to the console")
    group.add_argument("--process", action="store_true")
    group.add_argument("--exec", action="store")
    profile_from_envvar = os.environ.get(
        "AWS_PROFILE", os.environ.get(
            "AWS_DEFAULT_PROFILE", "default"))
    parser.add_argument(
        "--profile", action="store", default=profile_from_envvar,
        help="the source profile to use for creating credentials")
    parser.add_argument(
        "--outprofile", action="store", default="default",
        help="the destination profile to save generated credentials")
    parser.add_argument(
        "--configfile", action="store", default="~/.aws/config",
        help="the config file to append resulting config")
    parser.add_argument(
        "--credentialsfile", action="store", default="~/.aws/credentials",
        help="the credentials file to append resulting credentials")
    parser.add_argument(
        "command", action="store", nargs=argparse.REMAINDER,
        help="a command that you want to wrap")
    parser.add_argument(
        "--version", "-v", action="version",
        version=f"%(prog)s {__version__}",
        help="get version")
    args = parser.parse_args(argv[1:])
    return args


def retrieve_attribute(profile: Dict[str, Any], tag: str) -> Any:
    """Safely find and return the desired attribute from the AWS Config profile.

    Args:
        profile: A dictionary usually representing the AWS profile.
        tag: The tag to fetch from the profile.
    Returns:
        The value of the tag if found.
    Raises:
        Aws2WrapError: The tag was not present in the profile.
    """
    if tag not in profile:
        if "sso_session" in profile and tag in profile["sso_session"]:
            return profile["sso_session"][tag]
        raise Aws2WrapError(f"{tag!r} not found in profile: {profile!r}")
    return profile[tag]


def readline_generator(file_handle):
    """Support mocked reading of config with Python 3.6"""
    line = file_handle.readline()
    while line:
        yield line
        line = file_handle.readline()


def read_aws_config() -> Tuple[configparser.ConfigParser, str]:
    """Read the AWS config from the appropriate file"""
    aws_config_file = os.environ.get("AWS_CONFIG_FILE")
    if aws_config_file:
        config_path = os.path.abspath(aws_config_file)
    else:
        config_path = os.path.abspath(os.path.expanduser("~/.aws/config"))
    config = configparser.ConfigParser()
    # Mocking "open" in Python 3.6 doesn't work with ConfigParser.
    # It is suspected that this is because the reading mechanism
    # iterates on the file handle and not by calling readline().
    # If this package ever stops supporting Python 3.6, the following
    # block of code can be replaced with:
    # config.read(config_path)
    # and the whole of "def readline_generator" removed
    with open(config_path, mode="r", encoding="utf-8") as conf:
        config.read_file(readline_generator(conf))
    return config, config_path


def retrieve_profile(profile_name: str, profile_type: str = "profile") -> ProfileDef:
    """Find the AWS Config profile matching the specified profile name.

    Args:
        profile_name: The name of the AWS profile to return.
    Returns:
        The AWS profile matching that name if found.
    Raises:
        Aws2WrapError: The profile was not found in the config file.
    """
    config, config_path = read_aws_config()

    # Look for the required profile
    look_for = f"{profile_type} {profile_name}"
    if look_for in config:
        section_name = look_for
    elif profile_name in config:
        section_name = profile_name
    else:
        raise Aws2WrapError(f"Cannot find {profile_type} {profile_name!r} in {config_path}")
    # Retrieve the values as dict
    profile: ProfileDef = dict(config[section_name])

    # append profile_name as an attribute
    profile["profile_name"] = profile_name

    if "source_profile" in profile:
        # Retrieve source_profile recursively and append it to profile dict
        profile["source_profile"] = retrieve_profile(
            retrieve_attribute(profile, "source_profile")
        )

    if "sso_session" in profile:
        # Retrieve sso_session recursively and append it to profile dict
        profile["sso_session"] = retrieve_profile(
            retrieve_attribute(profile, "sso_session"),
            profile_type="sso-session"
        )

    return profile


def retrieve_token_from_file(
    filename: pathlib.Path, sso_start_url: str, sso_region: str
) -> Optional[str]:
    """Check specified file and, if valid, return the access token.

    Args:
        filename: Full path to the SSO cache file.
        sso_start_url: The SSO URL to match for a valid token.
        sso_region: The AWS region to match for a valid token.
    Returns:
        The access token if matched and not expired, otherwise None.
    """
    with open(filename, mode="r", encoding="utf-8") as json_file:
        blob = json.load(json_file)
    if ("startUrl" not in blob or
            blob["startUrl"] != sso_start_url or
            "region" not in blob or
            blob["region"] != sso_region):
        return None
    expires_at = blob["expiresAt"]
    # This will be a string like "2020-03-26T13:28:35UTC" OR "2021-01-21T23:30:56Z"
    # OR "2021-02-18T18:13:41.632177Z".
    if expires_at[-1] == "Z":
        # Unfortunately, Python version 3.6 or earlier doesn't seem to recognise "Z" so we replace
        # that with UTC first.
        expires_at = expires_at[:-1] + "UTC"
    datetime_format = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in expires_at else "%Y-%m-%dT%H:%M:%S%z"
    expire_datetime = datetime.strptime(expires_at.replace("UTC", "+0000"), datetime_format)
    if expire_datetime < datetime.now(timezone.utc):
        # This has expired
        return None
    # Everything looks OK ...
    return blob["accessToken"]


def retrieve_token(sso_start_url: str,
                   sso_region: str,
                   profile_name: ProfileDef,
                   refresh_profile: Optional[ProfileDef]) -> str:
    """Get the access token back from the SSO cache.

    Args:
        sso_start_url: The SSO URL to match for a valid token.
        sso_region: The AWS region to match for a valid token.
        profile_name: The desired profile to fetch the token for.
        refresh_profile: If set and the token is expired, refresh the token for this profile.
    Returns:
        The access token if matched and not expired.
    Raises:
        Aws2WrapError: No valid token found for the specified profile
    """
    try:
        return retrieve_token_from_cache(sso_start_url, sso_region, profile_name)
    except Aws2WrapError as exception:
        if refresh_profile is None:
            raise exception

        try_refreshing_tokens(refresh_profile)
        return retrieve_token_from_cache(sso_start_url, sso_region, profile_name)


def retrieve_token_from_cache(sso_start_url: str, sso_region: str, profile_name: ProfileDef) -> str:
    """Check each of the files in ~/.aws/sso/cache looking for one that references
       the specific SSO URL and region. If found then check the expiration.

    Args:
        sso_start_url (str): The SSO URL to match for a valid token.
        sso_region (str): The AWS region to match for a valid token.
        profile_name (str): The desired profile to fetch the token for.

    Raises:
        Aws2WrapError: No valid token found for the specified profile

    Returns:
        str: The access token if matched and not expired.
    """
    cachedir_path = os.path.abspath(os.path.expanduser("~/.aws/sso/cache"))
    cachedir = pathlib.Path(cachedir_path)
    for cachefile in cachedir.iterdir():
        token = retrieve_token_from_file(cachefile, sso_start_url, sso_region)
        if token is not None:
            return token
    raise Aws2WrapError(f"Please login with 'aws sso login --profile={profile_name}'")


def try_refreshing_tokens(profile_name: ProfileDef):
    """Try to refresh any token that AWS CLI currently has for the desired profile.

    There's no direct way to refresh the tokens, but a quick STS api call does the trick.
    Note that `aws sso login ...` will *not* refresh the tokens but will invalidate
    the whole SSO session (if any) which is not what we want here.

    Args:
        profile_name (str): Profile to try to refresh
    """
    call_aws_cli(["sts", "get-caller-identity"], profile_name)


def get_role_credentials(profile: ProfileDef,
                         parent_profile_name: Optional[ProfileDef] = None) -> Dict[str, Any]:
    """Get the role credentials.

    Args:
        profile: An AWS profile object.
        parent_profile_name: The name of the parent profile (which included this profile
                             via source_profile), if any.
    Returns:
        A dict of AWS credential values.
    Raises:
        Aws2WrapError: The call to get-role-credentials failed
    """

    profile_name = retrieve_attribute(profile, "profile_name")
    sso_start_url = retrieve_attribute(profile, "sso_start_url")
    sso_region = retrieve_attribute(profile, "sso_region")
    sso_account_id = retrieve_attribute(profile, "sso_account_id")
    sso_role_name = retrieve_attribute(profile, "sso_role_name")

    refresh_profile = choose_refreshable_profile(parent_profile_name, profile)
    sso_access_token = retrieve_token(sso_start_url, sso_region, profile_name, refresh_profile)

    result = call_aws_cli([
        "sso",
        "get-role-credentials",
        "--role-name", sso_role_name,
        "--account-id", sso_account_id,
        "--access-token", sso_access_token,
        "--region", sso_region
    ], profile_name)
    output = json.loads(result)
    # convert expiration from float value to isoformat string
    output["roleCredentials"]["expiration"] = datetime.fromtimestamp(
        float(output["roleCredentials"]["expiration"])/1000, tz=timezone.utc).isoformat()
    return output


def choose_refreshable_profile(parent_profile_name: Optional[ProfileDef],
                               profile: ProfileDef) -> Optional[ProfileDef]:
    """Determine the name of the refreshable profile.

    Args:
        parent_profile_name (Optional[str]): _description_
        profile (ProfileDef): _description_

    Returns:
        Optional[str]: name of the refreshable profile
    """
    if "sso_session" not in profile:
        # Not refreshable
        return None

    if parent_profile_name is not None:
        # This is a nested profile (via source_profile). The parent profile has
        # to be refreshed.
        return parent_profile_name

    return retrieve_attribute(profile, "profile_name")


def call_aws_cli(args,
                 profile_name: ProfileDef,
                 error_supplier: Optional[Callable]=None,
                 append_profile_option: bool=True,
                 env: Optional[dict]=None) -> bytes:
    """Generalised function to call AWS CLI

    Args:
        args: arguments to pass to AWS CLI
        profile_name (ProfileDef): profile to use
        error_supplier (Callable, optional): Function to call in the event of an error.
                                             Defaults to None.
        append_profile_option (bool, optional): Appends profile name to arguments. Defaults to True.
        env (dict, optional): Mapping to define environment variables for the process.
                                Defaults to None.

    Raises:
        error_supplier: Defined error function

    Returns:
        bytes: standard output from running the command
    """
    # We call the aws2 CLI tool rather than trying to use boto3 because the latter is
    # currently a special version and this script is trying to avoid needing any extra
    # packages.
    profile_args = ["--profile", profile_name] if append_profile_option else []
    error_supplier = error_supplier or (
        lambda: Aws2WrapError(f"Please login with 'aws sso login --profile={profile_name}'")
    )

    try:
        final_args = ["aws"] + args + profile_args + ["--output", "json", "--no-cli-auto-prompt"]
        result = subprocess.run(
            final_args,
            check=True,
            env=env,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE
        )
    except subprocess.CalledProcessError as error:
        if error.stderr is not None:
            print(error.stderr.decode(), file=sys.stderr)
        raise error_supplier() from None

    return result.stdout


def get_assumed_role_credentials(
        profile: ProfileDef,
        parent_profile_name: Optional[ProfileDef] = None
) -> Dict[str, Dict[str, str]]:
    """Get the assumed role credentials specified by role_arn and source_profile.

    Args:
        profile: An AWS profile object.
    Returns:
        A dict of AWS credential values.
    Raises:
        Aws2WrapError: The call to assume-role failed.
    """

    # If given profile is root, return sso role credentials.
    if "source_profile" not in profile:
        return get_role_credentials(profile, parent_profile_name)

    # Get credentials of source_profile recursively.
    source_credentials = get_assumed_role_credentials(
        retrieve_attribute(profile, "source_profile"),
        parent_profile_name=cast(ProfileDef, profile["profile_name"])
    )

    # Set credentials of source_profile.
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = source_credentials["roleCredentials"]["accessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = source_credentials["roleCredentials"]["secretAccessKey"]
    env["AWS_SESSION_TOKEN"] = source_credentials["roleCredentials"]["sessionToken"]

    # Extract role_session_name.
    # If role_session_name is not in profile,
    # use "botocore-session-<unix_time>" as with AWS CLI.
    if "role_session_name" in profile:
        role_session_name = retrieve_attribute(profile, "role_session_name")
    else:
        unix_time = int(datetime.now().timestamp())
        role_session_name = f"botocore-session-{unix_time}"

    role_arn = retrieve_attribute(profile, 'role_arn')

    # AssumeRole using source credentials
    result = call_aws_cli(
        [
            "sts", "assume-role",
            "--role-arn", role_arn,
            "--role-session-name", role_session_name
        ],
        profile,
        env=env,
        append_profile_option=False,
        error_supplier=lambda: Aws2WrapError(f"Failed to assume-role {role_arn!r}")
    )
    output = json.loads(result)
    return {
        "roleCredentials": {
            "accessKeyId": output["Credentials"]["AccessKeyId"],
            "secretAccessKey": output["Credentials"]["SecretAccessKey"],
            "sessionToken": output["Credentials"]["SessionToken"],
            "expiration": output["Credentials"]["Expiration"],
        }
    }


def process_cred_generation(  # pylint: disable=too-many-arguments
    credentialsfile: str, configfile: str, expiration: str, outprofile: str,
    access_key: str, secret_access_key: str, session_token: str, profile: ProfileDef
) -> None:
    """Export the credentials and config to the specified files.

    Args:
        credentialsfile: The user's AWS credentials file.
        configfile: The user's AWS config file.
        expiration: When the credentials will expire.
        outprofile: The name of the profile under which to store the credentials
        access_key: The generated access key.
        secret_access_key: The generated secret access key.
        session_token: The generated session token.
        profile: AWS profile.
    Raises:
        Aws2WrapError: The call to get-role-credentials failed
    """

    credentialsfile = os.path.expanduser(credentialsfile)
    configfile = os.path.expanduser(configfile)

    config = configparser.ConfigParser()
    config.read(credentialsfile)
    config[outprofile] = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_access_key,
        "aws_session_token": session_token
    }
    with open(credentialsfile, mode="w", encoding="utf-8") as file:
        config.write(file)

    config = configparser.ConfigParser()
    config.read(configfile)
    new_config = {}
    if "region" in profile:
        new_config = {
            "region": retrieve_attribute(profile, "region")
        }
    if outprofile == "default":
        config["default"] = new_config
    else:
        config[f"profile {outprofile}"] = new_config
    with open(configfile, mode="w", encoding="utf-8") as file:
        config.write(file)

    print(f"Credentials written to {credentialsfile}")
    print(f"Configuration written to {configfile}")
    print(f"The credentials will expire at {expiration}")


def run_command(
    access_key: str, secret_access_key: str, session_token: str,
    profile: ProfileDef, args: argparse.Namespace
) -> int:
    """Run the specified command with the credentials set up.

    Args:
        access_key: The AWS access key.
        secret_access_key: The AWS secret access key.
        session_token: The AWS session token.
        profile: The local AWS profile to use.
        args: The command line arguments.
    Returns:
        The exit code from the command.
    """
    os.environ["AWS_ACCESS_KEY_ID"] = access_key
    os.environ["AWS_SECRET_ACCESS_KEY"] = secret_access_key
    os.environ["AWS_SESSION_TOKEN"] = session_token
    status = None # ensure this is initialised
    # If region is specified in profile, also set AWS_DEFAULT_REGION
    if "AWS_DEFAULT_REGION" not in os.environ and "region" in profile:
        os.environ["AWS_DEFAULT_REGION"] = retrieve_attribute(profile, "region")
    if args.exec is not None:
        status = os.system(args.exec)
    elif args.command is not None:
        status = os.system(' '.join(shlex.quote(x) for x in args.command))
    # The return value of os.system is not simply the exit code of the process
    # see: https://mail.python.org/pipermail/python-list/2003-May/207712.html
    # noinspection PyUnboundLocalVariable
    if status is None:
        return 0
    # noinspection PyUnboundLocalVariable
    if status % 256 == 0:
        return status//256
    return status % 256


def export_credentials(
    access_key: str, secret_access_key: str, session_token: str, profile: ProfileDef
) -> None:
    """Export the AWS credentials to environment variables.

    Args:
        access_key: The AWS access key.
        secret_access_key: The AWS secret access key.
        session_token: The AWS session token.
        profile: The local AWS profile to use.
    """
    # On Windows, parent process is aws2-wrap.exe, in unix it's the shell
    if os.name == "nt":
        shell_name = psutil.Process().parent().parent().name()
    else:
        shell_name = psutil.Process().parent().name()

    is_powershell = bool(re.fullmatch(r'pwsh|pwsh.exe|powershell.exe', shell_name))

    if is_powershell:
        print(f"$ENV:AWS_ACCESS_KEY_ID=\"{access_key}\"")
        print(f"$ENV:AWS_SECRET_ACCESS_KEY=\"{secret_access_key}\"")
        print(f"$ENV:AWS_SESSION_TOKEN=\"{session_token}\"")
        # If region is specified in profile, also export AWS_DEFAULT_REGION
        if "AWS_DEFAULT_REGION" not in os.environ and "region" in profile:
            print(f"$ENV:AWS_DEFAULT_REGION=\"{retrieve_attribute(profile, 'region')}\"")
    else:
        print(f"export AWS_ACCESS_KEY_ID={access_key}")
        print(f"export AWS_SECRET_ACCESS_KEY={secret_access_key}")
        print(f"export AWS_SESSION_TOKEN={session_token}")
        # If region is specified in profile, also export AWS_DEFAULT_REGION
        if "AWS_DEFAULT_REGION" not in os.environ and "region" in profile:
            print(f"export AWS_DEFAULT_REGION={retrieve_attribute(profile, 'region')}")


def main(argv: Optional[List[str]]=None) -> int:
    """ Main! """
    if argv is None:
        argv = sys.argv
    args = process_arguments(argv)
    try:
        profile = retrieve_profile(args.profile)

        if "source_profile" in profile:
            grc_structure = get_assumed_role_credentials(profile)
        else:
            grc_structure = get_role_credentials(profile)

        # Extract the results from the roleCredentials structure
        access_key = grc_structure["roleCredentials"]["accessKeyId"]
        secret_access_key = grc_structure["roleCredentials"]["secretAccessKey"]
        session_token = grc_structure["roleCredentials"]["sessionToken"]
        expiration = grc_structure["roleCredentials"]["expiration"]
        if args.export:
            # On Windows, parent process is aws2-wrap.exe, in unix it's the shell
            export_credentials(access_key, secret_access_key, session_token, profile)
        elif args.generatestdout:
            print(f"[{args.outprofile}]")
            print("aws_access_key_id =", access_key)
            print("aws_secret_access_key =", secret_access_key)
            print("aws_session_token =", session_token)
        elif args.generate:
            process_cred_generation(
                args.credentialsfile, args.configfile, expiration, args.outprofile,
                access_key, secret_access_key, session_token, profile)
        elif args.process:
            output = {
                "Version": 1,
                "AccessKeyId": access_key,
                "SecretAccessKey": secret_access_key,
                "SessionToken": session_token,
                "Expiration": expiration.replace('+00:00', 'Z'),
            }
            print(json.dumps(output))
        else:
            return run_command(access_key, secret_access_key, session_token, profile, args)
    except Aws2WrapError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
