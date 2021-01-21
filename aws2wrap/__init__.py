#!/usr/bin/python3
#
# aws2-wrap [-h] [--export] [--profile PROFILE] [--exec <command>] <command>
#
# A simple script that exports the accessKeyId, secretAccessKey and sessionToken for the specified
# AWS SSO credentials, or it can run a subprocess with those credentials.
#
# This script is intended to plug a (hopefully temporary) gap in the official aws2 tool. As such, it
# makes certain assumptions about the cache file and does not rely on boto3 because the aws2 tool
# packages a dev version.
#
# Copyright (c) 2021 Linaro Ltd


import argparse
import configparser
import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone


def process_arguments():
    """ Check and extract arguments provided. """
    parser = argparse.ArgumentParser(allow_abbrev=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--export", action="store_true", help="export credentials as environment variables")
    group.add_argument("--generate", action="store_true", help="generate credentials file from the input profile")
    group.add_argument("--process", action="store_true")
    group.add_argument("--exec", action="store")
    profile_from_envvar = os.environ.get("AWS_PROFILE", os.environ.get("AWS_DEFAULT_PROFILE", None))
    parser.add_argument("--profile", action="store", default=profile_from_envvar, help="the source profile to use for creating credentials")
    parser.add_argument("--outprofile", action="store", default="default", help="the destination profile to save generated credentials")
    parser.add_argument("--configfile", action="store", default="~/.aws/config", help="the config file to append resulting config")
    parser.add_argument("--credentialsfile", action="store", default="~/.aws/credentials", help="the credentials file to append resulting credentials")
    parser.add_argument("command", action="store", nargs=argparse.REMAINDER, help="a command that you want to wrap")
    args = parser.parse_args()
    return args


def retrieve_attribute(profile, tag):
    """ Safely find and return the desired attribute from the AWS Config profile. """
    if tag not in profile:
        sys.exit("'%s' not in '%s' profile" % (tag, profile))
    return profile[tag]


def retrieve_profile(profile_name):
    """ Find the AWS Config profile matching the specified profile name. """
    if "AWS_CONFIG_FILE" in os.environ:
        config_path = os.path.abspath(os.environ.get("AWS_CONFIG_FILE"))
    else:
        config_path = os.path.abspath(os.path.expanduser("~/.aws/config"))
    config = configparser.ConfigParser()
    config.read(config_path)

    if profile_name == "default":
        section_name = "default"
    else:
        section_name = "profile %s" % profile_name

    # Look for the required profile
    if section_name not in config:
        sys.exit("Cannot find profile '%s' in ~/.aws/config" % profile_name)
    # Retrieve the values as dict
    profile = dict(config[section_name])

    # append profile_name as an attribute
    profile["profile_name"] = profile_name

    if "source_profile" in profile:
        # Retrieve source_profile recursively and append it to profile dict
        profile["source_profile"] = retrieve_profile(
            retrieve_attribute(profile, "source_profile")
        )

    return profile


def retrieve_token_from_file(filename, sso_start_url, sso_region):
    """ Check specified file and, if valid, return the access token. """
    with open(filename, "r") as json_file:
        blob = json.load(json_file)
    if ("startUrl" not in blob or
            blob["startUrl"] != sso_start_url or
            "region" not in blob or
            blob["region"] != sso_region):
        return None
    expires_at = blob["expiresAt"]
    # This will be a string like "2020-03-26T13:28:35UTC" OR "2021-01-21T23:30:56Z".
    if expires_at[-1] == "Z":
        # Unfortunately, Python version 3.6 or earlier doesn't seem to recognise "Z" so we replace
        # that with UTC first.
        expires_at = expires_at[:-1] + "UTC"
    expire_datetime = datetime.strptime(expires_at.replace("UTC", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
    if expire_datetime < datetime.now(timezone.utc):
        # This has expired
        return None
    # Everything looks OK ...
    return blob["accessToken"]


def retrieve_token(sso_start_url, sso_region, profile_name):
    """ Get the access token back from the SSO cache. """
    # Check each of the files in ~/.aws/sso/cache looking for one that references
    # the specific SSO URL and region. If found then check the expiration.
    cachedir_path = os.path.abspath(os.path.expanduser("~/.aws/sso/cache"))
    cachedir = pathlib.Path(cachedir_path)
    for cachefile in cachedir.iterdir():
        token = retrieve_token_from_file(cachefile, sso_start_url, sso_region)
        if token is not None:
            return token
    sys.exit("Please login with 'aws sso login --profile=%s'" % profile_name)


def get_role_credentials(profile):
    """ Get the role credentials. """

    profile_name = retrieve_attribute(profile, "profile_name")
    sso_start_url = retrieve_attribute(profile, "sso_start_url")
    sso_region = retrieve_attribute(profile, "sso_region")
    sso_account_id = retrieve_attribute(profile, "sso_account_id")
    sso_role_name = retrieve_attribute(profile, "sso_role_name")

    sso_access_token = retrieve_token(sso_start_url, sso_region, profile_name)

    # We call the aws2 CLI tool rather than trying to use boto3 because the latter is
    # currently a special version and this script is trying to avoid needing any extra
    # packages.
    result = subprocess.run(
        [
            "aws", "sso", "get-role-credentials",
            "--profile", profile_name,
            "--role-name", sso_role_name,
            "--account-id", sso_account_id,
            "--access-token", sso_access_token,
            "--region", sso_region,
            "--output", "json"
        ],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE
    )
    if result.returncode != 0:
        print(result.stderr.decode(), file=sys.stderr)
        sys.exit("Please login with 'aws sso login --profile=%s'" % profile_name)

    output = json.loads(result.stdout)
    # convert expiration from float value to isoformat string
    output["roleCredentials"]["expiration"] = datetime.fromtimestamp(float(output["roleCredentials"]["expiration"])/1000).replace(tzinfo=timezone.utc).isoformat()
    return output


def get_assumed_role_credentials(profile):
    """Get the assumed role credentials specified by role_arn and source_profile."""

    # If given profile is root, return sso role credentials.
    if "source_profile" not in profile:
        return get_role_credentials(profile)

    # Get credentials of source_profile recursively.
    source_credentials = get_assumed_role_credentials(
        retrieve_attribute(profile, "source_profile")
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
        role_session_name = "botocore-session-%d" % unix_time

    # AssumeRole using source credentials
    result = subprocess.run(
        [
            "aws", "sts", "assume-role",
            "--role-arn", retrieve_attribute(profile, "role_arn"),
            "--role-session-name", role_session_name,
            "--output", "json"
        ],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env=env,
    )
    if result.returncode != 0:
        print(result.stderr.decode(), file=sys.stderr)
        sys.exit("Failed to assume-role %s" % retrieve_attribute(profile, "role_arn"))

    output = json.loads(result.stdout)
    return {
        "roleCredentials": {
            "accessKeyId": output["Credentials"]["AccessKeyId"],
            "secretAccessKey": output["Credentials"]["SecretAccessKey"],
            "sessionToken": output["Credentials"]["SessionToken"],
            "expiration": output["Credentials"]["Expiration"],
        }
    }


def process_cred_generation(
    credentialsfile, configfile, expiration, outprofile,
    access_key, secret_access_key, session_token, profile):
    """ Export the credentials and config """

    config = configparser.ConfigParser()
    config.read(credentialsfile)
    config[outprofile] = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_access_key,
        "aws_session_token": session_token
    }
    with open(credentialsfile, "w") as file:
        config.write(file)

    config.read(configfile)
    new_config = {}
    if "region" in profile:
        new_config = {
            "region": retrieve_attribute(profile, "region")
        }
    config[outprofile] = new_config
    with open(configfile, "w") as file:
        config.write(file)

    print("Credentials written to %s" % credentialsfile)
    print("Configuration written to %s" % configfile)
    print("The credentials will expire at %s" % expiration)


def main():
    """ Main! """
    args = process_arguments()
    if args.profile is None:
        sys.exit("Please specify profile name by --profile or environment variable AWS_PROFILE")

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
        print("export AWS_ACCESS_KEY_ID=%s" % access_key)
        print("export AWS_SECRET_ACCESS_KEY=%s" % secret_access_key)
        print("export AWS_SESSION_TOKEN=%s" % session_token)
        # If region is specified in profile, also export AWS_DEFAULT_REGION
        if "AWS_DEFAULT_REGION" not in os.environ and "region" in profile:
            print("export AWS_DEFAULT_REGION=%s" % retrieve_attribute(profile, "region"))
    elif args.generate:
        if args.outprofile is not None:
            process_cred_generation(
                args.credentialsfile, args.configfile, expiration, args.outprofile,
                access_key, secret_access_key, session_token, profile)
    elif args.process:
        output = {
            "Version": 1,
            "AccessKeyId": access_key,
            "SecretAccessKey": secret_access_key,
            "SessionToken": session_token,
            "Expiration": expiration,
        }
        print(json.dumps(output))
    else:
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
            status = os.system(" ".join(args.command))
        # The return value of os.system is not simply the exit code of the process
        # see: https://mail.python.org/pipermail/python-list/2003-May/207712.html
        # noinspection PyUnboundLocalVariable
        if status is None:
            sys.exit(0)
        # noinspection PyUnboundLocalVariable
        if status % 256 == 0:
            sys.exit(status//256)
        sys.exit(status % 256)


if __name__ == '__main__':
    main()
