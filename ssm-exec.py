from datetime import datetime

import boto3

class SsmProcessRunner():
    """
    Runs a process on an EC2 instance via SSM
    """
    def __init__(self, profile=None, tags=None):
        if profile:
            boto3.setup_default_session(profile_name=profile)
        self.profile = profile
        self.tags = tags
        self.the_ssm_client = None
        self.the_ec2_client = None
        self.ec2_instance = None
        self.credentials = None

    def ssm_client(self):
        if self.the_ssm_client is None:
            self.assume_role()
            if self.credentials:
                self.the_ssm_client = boto3.client(
                    'ssm',
                    aws_access_key_id=self.credentials['AccessKeyId'],
                    aws_secret_access_key=self.credentials['SecretAccessKey'],
                    aws_session_token=self.credentials['SessionToken']
                )
            else:
                self.the_ssm_client = boto3.client('ssm')
        return self.the_ssm_client

    def ec2_client(self):
        if self.the_ec2_client is None:
            self.the_ec2_client = boto3.client('ec2')
        return self.the_ec2_client

    def assume_role(self, role_name='jenkins-agent-role'):
        needs_creds = self.credentials is None
        if not needs_creds:
            needs_creds = (datetime.now_utc() - self.credentials['Expiration']).total_seconds() < 5
        needs_creds = False
        if needs_creds:
            client = boto3.client('sts')
            response = client.assume_role(
                RoleArn=f'arn:aws:iam::511058993116:role/{role_name}',
                RoleSessionName='SSM-exec'
            )
            self.credentials = response['Credentials']

    def find_ec2_instance(self, **kwargs):
        result = self.ec2_client().describe_instances(**kwargs)
        if result and 'Reservations' in result:
            reservations = result['Reservations']
            if reservations:
                for r in reservations:
                    instance = self.filter_by_state(r['Instances'], 'running')
                    if not instance:
                        instance = self.filter_by_state(r['Instances'], 'pending')
                    if not instance:
                        instance = self.filter_by_state(r['Instances'], 'stopped')
                    if not instance:
                        instance = self.filter_by_state(r['Instances'], 'stopping')
                    if instance:
                        return instance
        return None

    def filter_by_state(self, instances, state_name, return_all=False):
        filtered = [i for i in instances if i['State']['Name'] == state_name]
        if filtered:
            if return_all:
                return filtered
            else:
                return filtered[0]
        return None

    def find_ami(self, **kwargs):
        result = self.ec2_client().describe_images(**kwargs)
        print(f'find_ami response: {result}')
        if 'Images' in result and result['Images']:
            return result['Images'][0]
        return None

    def start_ec2_instance(self, **kwargs):
        ami = self.find_ami(**kwargs)
        if ami is not None:
            print(f"Starting a new instance using AMI {ami['ImageId']}")
            launch_info = {
                'ImageId': ami['ImageId'],
                'MaxCount': 1,
                'MinCount': 1,
                'Monitoring': {'Enabled': False},
                'SecurityGroups': ['launch-wizard-1'],
                'InstanceType': 't2.micro',
                'DryRun': True
            }
            return self.ec2_client().run_instances(**launch_info)
        return None

    def restart_ec2_instance(self, instance):
        result = self.ec2_client().start_instances(
            InstanceIds = [instance['InstanceId']]
        )
        instance['State'] = result['StartingInstances'][0]['CurrentState']
        return instance

    def wait_for_instance(self, instance):
        current_state = instance['State']['Name']
        if current_state == 'pending':
            desired_state_code = 16
            desired_state = 'running'
        elif current_state == 'stopping':
            desired_state_code = 80
            desired_state = 'stopped'
        else:
            # No need to wait
            desired_state = current_state
        if desired_state != current_state:
            print(f"Waiting for instance {instance['InstanceId']} to reach state \'{desired_state}\'", flush=True)
            waiter = self.ec2_client().get_waiter(f'instance_{desired_state}')
            waiter.wait(InstanceIds=[instance['InstanceId']])
            # Update the instance state
            instance['State'] = {
                'Code': desired_state_code,
                'Name': desired_state
            }
        return desired_state

    def obtain_ec2_instance(self):
        if self.tags:
            filters = [{'Name': 'tag:' + t[0], 'Values': [t[1]]} for t in self.tags.items()]
        else:
            filters = []
        state_name = None
        self.ec2_instance = self.find_ec2_instance(Filters=filters)
        if self.ec2_instance:
            print(f"Found instance {self.ec2_instance['InstanceId']} in state \'{self.ec2_instance['State']['Name']}\'")
            state_name = self.wait_for_instance(self.ec2_instance)
            if state_name == 'stopped':
                print(f"Restarting the instance")
                self.ec2_instance = self.restart_ec2_instance(self.ec2_instance)
                state_name = self.wait_for_instance(self.ec2_instance)
        else:
            self.ec2_instance = self.start_ec2_instance(Filters=filters)
        if state_name == 'running':
            print(f"Obtained instance {self.ec2_instance['InstanceId']}")
        else:
            print(f"Unable to obtain an EC2 instance")

    def run_ssm(self, command):
        ec2_instance_id = self.ec2_instance['InstanceId']
        document_name = 'run-shell-script'
        user_name = self.profile if self.profile else ''
        directory_name = f'/home/{self.profile}' if self.profile else '/'
        parameters = {
            'commands': [f'{directory_name}/{command}'],
            'executionTimeout': ['3600'],
            'workingDirectory': [directory_name]
        }
        response = self.ssm_client().send_command(
            InstanceIds=[ec2_instance_id],
            DocumentName=document_name,
            Parameters=parameters
        )
        command = response['Command']
        print(f"Command ID: {command['CommandId']}\n  Waiting for the job to finish...", flush=True)
        waiter = self.ssm_client().get_waiter('command_executed')
        waiter.wait(
            CommandId=command['CommandId'],
            InstanceId=ec2_instance_id
        )
        # Obtain the output
        response = self.ssm_client().get_command_invocation(
            CommandId=command['CommandId'],
            InstanceId=ec2_instance_id,
            PluginName='aws:RunShellScript'
        )
        print(f"Response: {response}")


def main():
    try:
        profile = 'sas-user'
        tags = {'sas-usage': 'true'}
        runner = SsmProcessRunner(profile=profile, tags=tags)
        runner.obtain_ec2_instance()
        command = 'sasjob2'
        runner.run_ssm(command)
    except BaseException as err:
        print(err)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
