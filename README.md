# aws2-wrap
This is aimple script to facilitate exporting the current AWS SSO credentials or runing a command with them.

## Run a sub-command

`aws2-wrap.py --profile <awsprofilename> --exec "<command>"`

Note that you must enclose the command to be executed within double-quotes in order to ensure that any parameters are passed to that sub-command and not to `aws2-wrap`.

For example:

`aws2-wrap.py --profile MySSOProfile --exec "aws sts get-caller-identity"`

## Export the credentials

There may be circumstances when it is easier/better to set the appropriate environment variables so that they can be re-used by any `aws` command.

Since the script cannot directly set the environment variables in the calling shell process, it is necessary to use the following syntax:

`eval "$(aws2-wrap.py --profile <awsprofilename --export)"`

For example:

`eval "$(aws2-wrap.py --profile MySSOProfile --export)"`
