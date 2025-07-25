# Using CloudWatch Alarms and Lambda to catch exceptional traffic
This repository provides the CloudFormation templates talked about in the blog post. The layout of the files is:

- [alarms-and-lambda-single-tgw.yaml](alarms-and-lambda-single-tgw.yaml) - A full deployment of the monitoring solution for a single Transit Gateway
- [alarms-and-lambda-network-manager.yaml](alarms-and-lambda-network-manager.yaml) - A full deployment of the monitoring solution for a group of Transit Gateways that are part of a Network Manager Global Network.

The folder python_scripts contain the original Python scripts that are copied inside the templates as Lambda functions. They are not needed for a deployment, but instead are present as an easier-to-read reference.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

