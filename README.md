# aws2-wrap

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=linaro-its_aws2-wrap&metric=alert_status)](https://sonarcloud.io/dashboard?id=linaro-its_aws2-wrap)

This is a simple script to make it easier to use AWS Single Sign On credentials with tools that don't understand the `sso` entries in an AWS profile.

The script provides the following capabilities:

* Run a command using AWS SSO credentials
* Generate a temporary profile in the $AWS_CONFIG_FILE and $AWS_SHARED_CREDENTIALS_FILE file
* Exporting the AWS SSO credentials
* Use the credentials via .aws/config
* Assume a role via AWS SSO
* Supports automatic authentication refresh via AWS IAM Identity Center (https://docs.aws.amazon.com/cli/latest/userguide/sso-configure-profile-token.html)

Please note that the script is called `aws2-wrap` to show that it works with AWS CLI v2, even though the CLI tool is no longer called `aws2`.

## Install

### Using `pip`

<https://pypi.org/project/aws2-wrap>

```
pip3 install aws2-wrap
```

### Using `brew`

```
brew install aws2-wrap
```

## Run a command using AWS SSO credentials

`aws2-wrap [--profile <awsprofilename>] [--exec] <command>`

Note that if you are using `--exec` and `<command>` contains spaces, it must be surrounded with double-quotation marks.

You can also specify the profile to be used via AWS_PROFILE which then allows the same profile to be used by subsequent tools and commands.

Examples:

`aws2-wrap --profile MySSOProfile terraform plan`

`aws2-wrap --profile MySSOProfile --exec "terraform plan"`

`AWS_PROFILE=MySSOProfile aws2-wrap terraform plan`

If you are having problems with the use of quotes in the command, you may find one of the other methods works better for you.

## Generate a temporary profile in the $AWS_CONFIG_FILE and $AWS_SHARED_CREDENTIALS_FILE file

There are some utilities which work better with the configuration files rather than the environment variables. For example, if you need to access more than one profile at a time.

`aws2-wrap --generate --profile $AWS_PROFILE --credentialsfile $AWS_SHARED_CREDENTIALS_FILE --configfile $AWS_CONFIG_FILE --outprofile $DESTINATION_PROFILE`

Optionally, you can specify `--generatestdout` instead of `--generate`. `--outprofile` is still required in order to name the section but `--credentialsfile` and `--configfile` are ignored. With this command option, the generated credentials will then be output to the console.

## Export the AWS SSO credentials

There may be circumstances when it is easier/better to set the appropriate environment variables so that they can be re-used by any `aws` command.

Since the script cannot directly set the environment variables in the calling shell process, it is necessary to use the following syntax:

`eval "$(aws2-wrap [--profile <awsprofilename>] --export)"`

For example:

`eval "$(aws2-wrap --profile MySSOProfile --export)"`

If you are using PowerShell, the equivalent command is:

`aws2-wrap --profile MySSOProfile --export | invoke-expression`

## Use the credentials via .aws/config

If you are using a tool that works with normal AWS credentials but doesn't understand the new AWS SSO credentials, another option is to add a profile to `.aws/config` that calls the `aws2-wrap` script.

For example, add the following block to `.aws/config`:

```text
[profile Wrapped]
credential_process = aws2-wrap --process --profile <awsprofilename>
```

then, after authentication, you can run any command that uses AWS credentials by specifying the "Wrapped" profile:

```text
aws sso login --profile <awsprofilename>
export AWS_PROFILE=Wrapped
export AWS_SDK_LOAD_CONFIG=1
terraform plan
```

Note that because the profile is being specified via `AWS_PROFILE`, it is sometimes necessary (as shown above) to set `AWS_SDK_LOAD_CONFIG` in order to get tools like `terraform` to successfully retrieve the credentials.

## Assume a role via AWS SSO

Your `.aws/config` file can look like this:

```text
[default]
sso_start_url = xxxxxxxxxxxx
sso_region = us-west-2
sso_account_id = xxxxxxxxxxxx
sso_role_name = SSORoleName

[profile account1]
role_arn = arn:aws:iam::xxxxxxxxxxxx:role/role-to-be-assumed
source_profile = default
region = ap-northeast-1
```

allowing you to then run:

`aws2-wrap --profile account1 <command>`

and `<command>` will be run under `role-to-be-assumed`.

## Contributing

Contributions are more than welcome, particularly if you are able to expand on the test code. Please ensure, though, that before you submit a Pull Request, you run `make test` to ensure that your changes don't break any of the existing tests and `make pylint` to ensure that the linter is happy. Please note that the CI/CD pylint test *may* use different pylint rules from your own local setup.

Please also note that `make pylint` will only report errors. You *may* want to explicitly run `python3 -m pylint setup.py aws2wrap`

## Credits

Thanks to @matan129, @nitrocode, @chenrui333, @l1n, @sodul, @damian-bisignano, @flyinprogrammer, @abeluck, @topu, @bigwheel, @krabbit, @jscook2345, @hieki, @blazdivjak, @fukushun1994, @johann8384, @ppezoldt, @atwoodjw, @lummish, @life36-vinny, @lukemassa and @axelri for their contributions.
