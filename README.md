[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=linaro-its_aws2-wrap&metric=alert_status)](https://sonarcloud.io/dashboard?id=linaro-its_aws2-wrap)

# aws2-wrap
This is a simple script to make it easier to use AWS Single Sign On credentials with tools that don't understand the `sso` entries in an AWS profile.

The script provides the following capabilities:

* Running a specified command with the retrieved AWS SSO credentials.
* Exporting the AWS SSO credentials.
* Supporting `credential_process` within an aWS profile

Please note that the script is called `aws2-wrap` to show that it works with AWS CLI v2, even though the CLI tool is no longer called `aws2`.

## Install using `pip`

https://pypi.org/project/aws2-wrap

`pip install aws2-wrap==1.0.3`

## Run a command using AWS SSO credentials

`aws2-wrap [--profile <awsprofilename>] [--exec] <command>`

Note that if you are using `--exec` and `<command>` contains spaces, it must be surrouned with double-quotation marks.

You can also specify the profile to be used via AWS_PROFILE which then allows the same profile to be used by subsequent tools and commands.

Examples:

`aws2-wrap --profile MySSOProfile terraform plan`

`aws2-wrap --profile MySSOProfile --exec "terraform plan"`

`AWS_PROFILE=MySSOProfile aws2-wrap terraform plan`

## Export the credentials

There may be circumstances when it is easier/better to set the appropriate environment variables so that they can be re-used by any `aws` command.

Since the script cannot directly set the environment variables in the calling shell process, it is necessary to use the following syntax:

`eval "$(aws2-wrap [--profile <awsprofilename>] --export)"`

For example:

`eval "$(aws2-wrap --profile MySSOProfile --export)"`

## Use the credentials via .aws/config

If you are using a tool that works with normal AWS credentials but doesn't understand the new AWS SSO credentials, another option is to add a profile to `.aws/config` that calls the `aws2-wrap` script.

For example, add the following block to `.aws/config`:

```
[profile Wrapped]
credential_process = aws2-wrap --process --profile <awsprofilename>
```

then, after authentication:

`aws sso login --profile <awsprofilename>`

you can run any command that uses AWS credentials by specifying the "Wrapped" profile:

```
export AWS_PROFILE=Wrapped
terraform plan
```

## Credits

Thanks to @flyinprogrammer, @abeluck, @topu, @bigwheel, @krabbit, @jscook2345 and @hieki for their contributions.
