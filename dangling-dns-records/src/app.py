import os
import boto3
import botocore
import datetime
import logging
logger = logging.getLogger()

bucketName = os.environ.get('DestinationBucketName')


def lambda_handler(event, context):

    client = boto3.client('organizations')
    response = client.list_accounts()

    audit_result = ""

    for account in response['Accounts']:
        try:
            # Skip Management account
            if ("::"+account["Id"]+":" not in account["Arn"]) and (account["Status"] == 'ACTIVE'):

                logger.info("Checking DNS for account {0}({1} - {2})".format(
                    account["Id"], account["Name"], account["Status"]))

                sts_connection = boto3.client('sts')
                # Assume role in target account
                account_to_audit = sts_connection.assume_role(
                    RoleArn="arn:aws:iam::" +
                    account['Id'] +
                    ":role/aws-controltower-ReadOnlyExecutionRole",
                    RoleSessionName="auditaccount_dns_audit"
                )
                ACCESS_KEY = account_to_audit['Credentials']['AccessKeyId']
                SECRET_KEY = account_to_audit['Credentials']['SecretAccessKey']
                SESSION_TOKEN = account_to_audit['Credentials']['SessionToken']

                # Dangling DNS record use case
                rt53_connection = boto3.client(
                    'route53',
                    aws_access_key_id=ACCESS_KEY,
                    aws_secret_access_key=SECRET_KEY,
                    aws_session_token=SESSION_TOKEN
                )

                ec2_client = boto3.client(
                    'ec2',
                    aws_access_key_id=ACCESS_KEY,
                    aws_secret_access_key=SECRET_KEY,
                    aws_session_token=SESSION_TOKEN
                )

                hosted_zones = rt53_connection.list_hosted_zones()
                for hosted_zone in [hosted_zone for hosted_zone in hosted_zones['HostedZones'] if not hosted_zone["Config"]["PrivateZone"]]:
                    record_sets = rt53_connection.list_resource_record_sets(
                        HostedZoneId=hosted_zone["Id"]
                    )
                    for record_set in [record_set for record_set in record_sets['ResourceRecordSets'] if record_set['Type'] == 'A' and 'ResourceRecords' in record_set]:
                        for record in record_set['ResourceRecords']:
                            found = False
                            #  Iterate over regions until the IP is found (success) or you exhaust all regions
                            for region in ec2_client.describe_regions()['Regions']:
                                try:
                                    ec2_client = boto3.client(
                                        'ec2',
                                        aws_access_key_id=ACCESS_KEY,
                                        aws_secret_access_key=SECRET_KEY,
                                        aws_session_token=SESSION_TOKEN,
                                        region_name=region['RegionName']
                                    )
                                    response = ec2_client.describe_addresses(
                                        PublicIps=[record['Value']]
                                    )
                                    found = True
                                    break
                                except botocore.exceptions.ClientError as ec2error:
                                    # Exception denotes IP not found; continue checking
                                    continue
                            if not found:
                                audit_result += ','.join(
                                    [account["Id"], hosted_zone["Id"], record_set["Name"], record['Value'], '\n'])
            else:
                logger.warning("Skipping check for account {0}({1} - {2})".format(
                    account["Id"], account["Name"], account["Status"]))
        except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
            logger.error(
                "Exception in DNS check for account {0}: {1} ".format(account["Id"], e))
            continue

    if audit_result != "":
        s3 = boto3.resource('s3')
        today = datetime.date.today()
        objectName = today.strftime("%Y/%m/%d/auditreport")
        audit_report = "Account#, Hosted Zone ID, Record Set Name, IP Address, IP Owned \n" + audit_result
        s3.Bucket(bucketName).put_object(Key=objectName, Body=audit_report)

        return {
            'statusCode': 200,
            'body': 'Dangling DNS records found. Audit report at ' + bucketName+objectName
        }
    return {
        'statusCode': 200,
        'body': 'No dangling DNS records found'
    }
