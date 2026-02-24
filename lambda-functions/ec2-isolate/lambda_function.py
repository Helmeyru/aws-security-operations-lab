import boto3
import os
import json

ec2 = boto3.client('ec2')

QUARANTINE_SG_ID = os.environ['QUARANTINE_SG_ID']


def lambda_handler(event, context):
    print("EVENT RECEIVED:")
    print(json.dumps(event))

    try:
        instance_id = event['instance_id']

        print(f"Isolating instance: {instance_id}")

        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[QUARANTINE_SG_ID]
        )

        return {
            "status": "success",
            "message": f"Instance {instance_id} isolated successfully"
        }

    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }
