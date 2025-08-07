# Using CloudWatch Alarms and Lambda to catch exceptional traffic
This repository provides the CloudFormation templates talked about in the blog post. The layout of the files is:

- [alarms-and-lambda.yaml](alarms-and-lambda.yaml) - A full deployment of the monitoring solution. Generally, you can leave all the parameters at the defaults, but you do need to provide either a Transit Gateway ID in the TransitGatewayId parameter, or the ARN of a Network Manager Global Network in for GlobalNetworkArn (not both).

The folder python_scripts contain the original Python scripts that are copied inside the templates as Lambda functions. They are not needed for a deployment, but instead are present as an easier-to-read reference.

The template creates everything needed, with the main function being named (objectname)_Event_Handler. This lambda is automatically called every hour by EventBridge, and triggered by CloudFormation or Network Manager (if in use). You can also test this function but going to the Lambda console for it, and providing in the event JSON a key of 'TEST' and any value. If you want more debugging information, add in a key of 'DEBUG' and any value.

## Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This tool is licensed under the MIT-0 License. See the LICENSE file.
