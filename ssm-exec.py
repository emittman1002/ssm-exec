from datetime import datetime
from math import ceil

import boto3

class SsmProcessRunner():
    """
    Executes shell scripts on an EC2 instance using SSM
    """
    def __init__(self, profile=None, tags=None, wait_interval=None, timeout_sec=None):
        """
        Initialize a new runner
        :param profile: (optional) a profile to use for clients
        :param tags: (optional) tags to use as filters when looking for instances and AMIs
        :param wait_interval: (optional) how long to wait between polls when waiting for a command to execute
        :param timeout_sec: (optional) how long the job will be allowed to run
        """
        if profile:
            boto3.setup_default_session(profile_name=profile)
        self.profile = profile
        self.tags = tags
        self.the_ssm_client = None
        self.the_ec2_client = None
        self.ec2_instance = None
        self.credentials = None
        self.wait_interval = wait_interval
        self.timeout_sec = timeout_sec
        self.exit_code = None
        self.final_status = None
        self.output_content = None
        self.error_content = None

    def ssm_client(self):
        """
        Obtain a client for SSM operations
        :return:
        """
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
        """
        Obtain a client for EC2 operations
        :return:
        """
        if self.the_ec2_client is None:
            self.the_ec2_client = boto3.client('ec2')
        return self.the_ec2_client

    def assume_role(self, role_name='jenkins-agent-role'):
        """
        Obtain credentials that can be used to assume the
        specified role
        :param role_name: the name (not ARN) of the role
        :return: None.  The credentials variable of this runner is populated
        """
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
        """
        Find one or more instances
        :param kwargs: option keyword args, possibly containing a filter
        :return: a dict with instance info, or None if none was found
        """
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
        """
        Search a list of dicts containing instance information
        for ones in a specified state
        :param instances: a list of dicts containing infor about EC2 instances
        :param state_name: the name of the state to filter on
        :param return_all: if True return all matching instances,
                            if False just return the first one
        :return:
        """
        filtered = [i for i in instances if i['State']['Name'] == state_name]
        if filtered:
            if return_all:
                return filtered
            else:
                return filtered[0]
        return None

    def find_ami(self, **kwargs):
        """
        Find an AMI to use to start an EC2 instance
        :param kwargs:
        :return: info about the AMI, or None if none can be found
        """
        result = self.ec2_client().describe_images(**kwargs)
        print(f'find_ami response: {result}')
        if 'Images' in result and result['Images']:
            return result['Images'][0]
        return None

    def start_ec2_instance(self, **kwargs):
        """
        Start a new EC2 instance to do some work
        :param kwargs:
        :return: a dict with information about the new instance,
                    or None if no instance was started
        """
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
        """
        Restarts an instance that was stopped
        :param instance:
        :return: a dict with info about the restarted instance
        """
        result = self.ec2_client().start_instances(
            InstanceIds = [instance['InstanceId']]
        )
        instance['State'] = result['StartingInstances'][0]['CurrentState']
        return instance

    def wait_for_instance(self, instance):
        """
        Waits for an instance to get to a stable state
        :param instance:
        :return: the name of the stable state that the instance is now in
        """
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
        """
        Initializes this runner with the ID of
        a running EC2 instance that can run commands
        :return:
        """
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

    def run_ssm(self, commands, as_user=None):
        """
        Run a set of commands using an SSM managed document
        :param commands: a single string or a list of string commands
        :param as_user: run the command as something other than root
        :return: a response returned after commands have finished executing
        """
        document_name = 'run-shell-script'
        if type(commands) == str:
            commands = [commands]
        if commands:
            su_command = f'ruser -l {as_user}'
            if as_user:
                commands = [f"runuser -l {as_user} --session-command={c}" for c in commands]
            if self.timeout_sec:
                execution_timeout = str(self.timeout_sec)
            else:
                execution_timeout = '3600'
            parameters = {
                'commands': commands,
                'executionTimeout': [execution_timeout],
            }
            if self.profile:
                parameters['workingDirectory'] = [f'/home/{self.profile}']

            response = self.ssm_client().send_command(
                InstanceIds=[self.ec2_instance['InstanceId']],
                DocumentName=document_name,
                Parameters=parameters
            )
            response_command = response['Command']
            print(f"Command ID: {response_command['CommandId']}\n  Waiting for the job to finish...", flush=True)
            # Wait for the command to execute,
            # then obtain the output
            try:
                self.wait_for_command(response_command)
            except:
                # We'll find out what's going on
                # from get_command_invocation()
                pass
            response = self.ssm_client().get_command_invocation(
                CommandId=response_command['CommandId'],
                InstanceId=self.ec2_instance['InstanceId'],
                PluginName='aws:RunShellScript'
            )
            self.final_status = response['Status']
            self.exit_code = response['ResponseCode']
            self.output_content = response['StandardOutputContent']
            if self.output_content:
                self.output_content = self.output_content.strip()
            self.error_content = response['StandardErrorContent']
            if self.error_content:
                self.error_content = self.error_content.strip()
            if self.exit_code == 0 and not self.error_content:
                self.error_content = None
            return response
        return None

    def wait_for_command(self, command):
        """
        Wait for a command to finish executing
        :param command:
        :return: nothing
        :raises: an exception if execution fails
        """
        waiter = self.ssm_client().get_waiter('command_executed')
        if self.wait_interval:
            delay = int(self.wait_interval)
            if delay <= 0:
                delay = 1
        else:
            delay = 5
        if self.timeout_sec:
            # The timeout should come from send_command(), not from
            # the waiter, so add some extra seconds to give it time
            # to do that
            max_attempts = int(ceil(float(self.timeout_sec) / delay)) + 2
            if max_attempts <= 0:
                max_attempts = 2
        else:
            max_attempts = 20
        waiter_config = {
            'Delay': delay,
            'MaxAttempts': max_attempts
        }
        waiter.wait(
            CommandId=command['CommandId'],
            InstanceId=self.ec2_instance['InstanceId'],
            WaiterConfig=waiter_config
        )


def main():
    """
    You know what this is
    :return:
    """
    try:
        profile = 'sas-user'
        tags = {'sas-usage': 'true'}
        runner = SsmProcessRunner(profile=profile, tags=tags, wait_interval=5, timeout_sec=10)
        runner.obtain_ec2_instance()
        command = '/opt/sas/sasjob2'
        runner.run_ssm(command, as_user='ssm-user')
        if runner.final_status is not None:
            if runner.exit_code == 0:
                print("The job succeeded")
            else:
                print("The job failed")
            print(f"  Exit code: {runner.exit_code}")
            print(f"  Status: {runner.final_status}")
            print(f"  Output: \'{runner.output_content}\'")
            if runner.error_content is not None:
                print(f"  Error: \'{runner.error_content}\'")
    except BaseException as err:
        print(err)


if __name__ == '__main__':
    main()
