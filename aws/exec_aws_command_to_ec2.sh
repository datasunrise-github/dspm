#!/bin/bash
instanceName=$1
aws_region=$2

instanceIDs=`aws ec2 describe-instances --region $aws_region --filters Name=tag:Name,Values=$instanceName Name=instance-state-name,Values=running --query "Reservations[*].Instances[*].InstanceId" --output text`
echo "Instance Name: $instanceName";
echo "Region: $aws_region";
echo "instanceIDs: $instanceIDs";

echo $instanceIDs | tr " " "\n" | while read instanceID; do
  echo "InstanceID: $instanceID";
  commandStatus="Pending";
  commandID=`aws ssm send-command --document-name "AWS-RunShellScript" --region $aws_region --query "Command.CommandId" --output text --parameters "commands=[\"cd /home/ec2-user/dsssm && npm run uninstall\"]" --targets "Key=instanceids,Values=$instanceID" --comment "DELETION_RESOURCES_CREATED_BY_DSSSM"`;
  echo "commandID: $commandID";
  while [[ $commandStatus == "Pending" || $commandStatus == "InProgress" || $commandStatus == "None" ]]; do
    echo ".";
    commandStatus=`aws ssm list-commands --region $aws_region --command-id "$commandID" --query "Commands[0].Status" --output text`;
    echo "Status: $commandStatus";
    sleep 5;
  done;
done;

exit 0
