#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: aws_service_discovery_namespace
short_description: Create and delete AWS Service Discovery Namespaces
version_added: 2.10
description:
  - Create and delete AWS Service Discovery Namespaces
requirements: [boto3]
options:
  name:
    description:
      - The name of the namespace, special characters is only supported when
        you use C(type=http).
    type: str
    required: true
  description:
    description:
      - Description of the namespace.
    type: str
    required: false
  type:
    description:
      - Inform what kind of namespace will be created.
    choices: ['http', 'public_dns', 'private_dns']
    type: str
    required: false
  vpc_id:
    description:
      - The vpc_id that will be associate when you use private_dns.
        Required if C(type=private_dns).
    type: str
    required: false
  recursive_delete:
    description:
      - By default the API don't delete the namespace if there is any service,
        set this option to true to delete services too.
    type: bool
    required: false
  state:
    description:
      - Create or destroy namespace.
    choices: ['present', 'absent']
    type: str
    default: present
  wait:
    description:
      - Wait until the operation done.
    type: bool
    default: true
  wait_delay:
    description:
      - The amount of time in seconds to wait between attempts.
    type: int
    default: 30
  wait_max_attempts:
    description:
      - The number of attempts to the operation done.
    type: int
    default: 60
author:
  - Wellington Moreira Ramos (@wmaramos)
extends_documentation_fragment:
  - aws
  - ec2
notes:
  - Special characters in only supported in the option name when you use C(type=http).
'''

EXAMPLES = '''
- name: Create http namespace
  aws_service_discovery_namespace:
    name: local-http
    type: http

- name: Create private_dns namespace
  aws_service_discovery_namespace:
    name: local
    type: private_dns
    vpc_id: vpc-09532f8bfa2c493d3

- name: Delete namepasce with all services
  aws_service_discovery_namespace:
    name: local
    state: absent
'''

RETURN = '''
Namespace:
  description: Complex type the contains information about the namespace.
  returned: always
  type: complex
  contains:
    Id:
      description: The id of the namespace
      returned: always
      type: str
    Arn:
      description: The Amazon Resource Name (ARN) that AWS Cloud Map assign.
      returned: always
      type: str
    Name:
      description: The name of the namespace.
      returned: always
      type: str
    Type:
      description: The type of the namespace.
      returned: when supported
      type: str
    Description:
      description: The description that you specify when you create it.
      returned: always
      type: str
    ServiceCount:
      description: The number of services that are associated with the namespace.
      returned: when supported
      type: int
    Properties:
      description: A complex type contains information to the type of the namespace.
      returned: always
      type: complex
      contains:
        DnsProperties:
          description: A complex type that contains the ID for the Route 53 hosted zone.
          type: complex
          returned: when supported
          contains:
            HostedZoneId:
              description: The ID for the Route 53 hosted zone.
              type: str
              returned: when supported
        HttpProperties:
          description: A complex type that contains the name of the HTTP namespace.
          type: complex
          returned: when supported
          contains:
            HttpName:
              description: The name of the HTTP namespace.
              type: str
              returned: when supported
    CreateDate:
      description: The date that the namespace was created.
      type: str
      returned: always
    CreatorRequestId:
      description: A uniqe string that identifies the request and that allows failed requests
                   to be retried wihout the risk of executing an operation twice.
      type: str
      returned: always
'''

import time
import re

from ansible.module_utils.aws.core import AnsibleAWSModule

try:
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    pass  # caught by imported HAS_BOTO3


def waiter(client, operation_id, wait_status, wait_delay, wait_max_attempts):
    while wait_max_attempts > 0:
        operation = client.get_operation(OperationId=operation_id)['Operation']

        if operation['Status'] == wait_status:
            return operation

        time.sleep(wait_delay)
        wait_max_attempts -= 1

    return operation


def find_namespace(client, name, **params):
    paginator = client.get_paginator('list_namespaces')

    while True:
        response_iterator = paginator.paginate(**params)

        for response in response_iterator:
            for namespace in response['Namespaces']:
                if namespace['Name'] == name:
                    return namespace

            if 'NextToken' in response:
                params.update({
                    'PaginationConfig': {
                        'StartingToken': response['NextToken']
                    }
                })
            else:
                return None


def create_namespace(client, module):
    name = module.params.get('name')

    namespace = find_namespace(client, name)

    if namespace:
        changed = False

        return changed, namespace

    else:
        changed = True

        type = module.params.get('type')
        vpc_id = module.params.get('vpc_id')

        case = {
            'http': {
                'method': client.create_http_namespace,
                'params': {
                    'Name': name
                }
            },
            'public_dns': {
                'method': client.create_public_dns_namespace,
                'params': {
                    'Name': name
                }
            },
            'private_dns': {
                'method': client.create_private_dns_namespace,
                'params': {
                    'Name': name,
                    'Vpc': vpc_id
                }
            }
        }

        try:
            operation_id = case.get(type)['method'](
                **case.get(type)['params'])['OperationId']

        except (ClientError, BotoCoreError) as e:
            module.fail_json_aws(e)

        wait = module.params.get('wait')

        if wait:
            wait_delay = module.params.get('wait_delay')
            wait_max_attempts = module.params.get('wait_max_attempts')

            waiter(client=client, operation_id=operation_id,
                   wait_status='SUCCESS', wait_delay=wait_delay,
                   wait_max_attempts=wait_max_attempts)

            namespace = find_namespace(client, name)

            return changed, namespace

        else:
            try:
                operation = client.get_operation(
                    OperationId=operation_id)['Operation']

            except (ClientError, BotoCoreError) as e:
                module.fail_json_aws(e)

            return changed, operation


def delete_namespace(client, module):
    def get_services(**params):
        paginator = client.get_paginator('list_services')
        response_iterator = paginator.paginate(**params)

        for response in response_iterator:
            data = response['Services']

            if 'NextToken' in response:
                params.update({
                    'PaginationConfig': {
                        'StartingToken': response['NextToken']
                    }
                })

                data += response['Services']

            return data

    name = module.params.get('name')
    wait = module.params.get('wait')
    recursive_delete = module.params.get('recursive_delete')

    namespace = find_namespace(client=client, name=name)

    if namespace:
        changed = True

        if recursive_delete:
            params = {
                'Filters': [
                    {
                        'Name': 'NAMESPACE_ID',
                        'Values': [namespace['Id']],
                        'Condition': 'EQ'
                    }
                ]
            }

            services = get_services(params=params)

            for service in services:
                try:
                    client.delete_service(Id=service['Id'])

                except (ClientError, BotoCoreError) as e:
                    module.fail_json_aws(e)

        try:
            operation_id = client.delete_namespace(
                Id=namespace['Id'])['OperationId']

        except (ClientError, BotoCoreError) as e:
            module.fail_json_aws(e)

        if wait:
            wait_delay = module.params.get('wait_delay')
            wait_max_attempts = module.params.get('wait_max_attempts')

            operation = waiter(client=client, operation_id=operation_id,
                               wait_status='SUCCESS', wait_delay=wait_delay,
                               wait_max_attempts=wait_max_attempts)

        else:
            operation = client.get_operation(
                OperationId=operation_id)['Operation']

        return changed, operation
    else:
        changed = False
        message = {'msg': 'Already absent'}
        return changed, message


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        description=dict(type='str'),
        type=dict(type='str', choices=['http', 'public_dns', 'private_dns']),
        vpc_id=dict(type='str'),
        recursive_delete=dict(type='bool', default=False),
        wait=dict(type='bool', default=True),
        wait_delay=dict(type='int', default=30),
        wait_max_attempts=dict(type='int', default=60),
        state=dict(type='str', choices=[
                   'present', 'absent'], default='present')
    )

    module = AnsibleAWSModule(argument_spec=argument_spec,
                              required_if=[
                                  ['state', 'present', ['type']],
                                  ['type', 'private_dns', ['vpc_id']]
                              ],
                              supports_check_mode=True)

    name = module.params.get('name')
    type = module.params.get('type')

    if bool(re.search('[$&+,:;=?@#|\'<>^*()%!-]', name)) \
       and (type == 'public_dns' or type == 'private_dns'):

        module.fail_json_aws(
            'Only words, numbers and dots are supported in the name')

    case = {
        'present': create_namespace,
        'absent': delete_namespace
    }

    state = module.params.get('state')

    client = module.client('servicediscovery')

    changed, response = case.get(state)(client=client, module=module)

    module.exit_json(changed=changed, **response)


if __name__ == '__main__':
    main()
