import os
import boto3
import datetime

bucketName = os.environ.get('DestinationBucketName')


def lambda_handler(event, context):

    client = boto3.client('organizations')
    response = client.list_accounts()

    audit_result = ""

    for account in response['Accounts']:
        try:
            # Skip Management account
            if ("::"+account["Id"]+":" not in account["Arn"]) and (account["Status"] == 'ACTIVE'):

                sts_connection = boto3.client('sts')
                # Assume role in target account
                account_to_audit = sts_connection.assume_role(
                    RoleArn="arn:aws:iam::" +
                    account['Id'] +
                    ":role/aws-controltower-ReadOnlyExecutionRole",
                    RoleSessionName="cross_acct_lambda"
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
                        hosted_zone_id=hosted_zone["Id"]
                    )
                    for record_set in record_sets['ResourceRecordSets']:
                        for record in (record for record in record_set['ResourceRecords'] if (record_set['Type'] == 'A' and 'ResourceRecords' not in record_set)):
                            found = False
                            #  Iterate over regions until its found (success) or exhausts all regions
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
                                except Exception as ec2error:
                                    # The IP address does not exist in any region
                                    continue
                        if not found:
                            audit_result += ','.join(
                                [account["Id"], hosted_zone["Id"], record_set["Name"], record['Value'], '\n'])
            else:
                print("Skipping : ----- ",
                      account["Id"], "|", account["Name"], "|", account["Status"])

        except Exception as e:
            print("Exception : ##### ", account["Id"], e)
            continue
        if audit_result != "":
            s3 = boto3.resource('s3')
            today = datetime.date.today()
            objectName = today.strftime("%Y/%m/%d/auditreport")
            s3.Bucket(bucketName).put_object(Key=objectName, Body=audit_result)

            return {
                'statusCode': 200,
                'body': 'Dangling DNS records found. Audit report at ' + bucketName+objectName
            }
        return {
            'statusCode': 200,
            'body': 'No dangling DNS records found'
        }
