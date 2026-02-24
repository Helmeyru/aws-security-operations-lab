import boto3

iam = boto3.client('iam')


def lambda_handler(event, context):
    try:
        # Extract user name from GuardDuty finding
        user_name = event['detail']['resource']['accessKeyDetails']['userName']

        # List access keys
        keys = iam.list_access_keys(UserName=user_name)

        # Deactivate and rotate the compromised key
        for key in keys['AccessKeyMetadata']:
            if key['Status'] == 'Active':
                # Create new key
                new_key = iam.create_access_key(UserName=user_name)

                # Deactivate old key
                iam.update_access_key(
                    UserName=user_name,
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive'
                )

                return {
                    'status': 'success',
                    'message': f'Rotated keys for {user_name}',
                    'new_key_id': new_key['AccessKey']['AccessKeyId']
                }

        return {
            'status': 'warning',
            'message': f'No active keys found for {user_name}'
        }

    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }
