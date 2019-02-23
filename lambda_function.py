
import json
import logging
import os

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# The log level
log_level = os.environ['log_level'].upper()

subnet_alert_level  = os.environ['subnet_alert_level']
nacl_alert_level     = os.environ['nacl_alert_level']
gateway_alert_level = os.environ['gateway_alert_level']
routing_alert_level = os.environ['routing_alert_level']
vpc_alert_level     = os.environ['vpc_alert_level']

high_hook_url   = os.environ['high_hook_url']
medium_hook_url = os.environ['medium_hook_url']
low_hook_url    = os.environ['low_hook_url']

high_channel   = os.environ['high_channel']
medium_channel = os.environ['medium_channel']
low_channel    = os.environ['low_channel']

logger = logging.getLogger()
logger.setLevel(log_level)


subnet_actions = [
    "AssociateSubnetCidrBlock",
    "CreateDefaultSubnet",
    "CreateSubnet",
    "DeleteSubnet",
    "DisassociateSubnetCidrBlock",
    "ModifySubnetAttribute"
]
    
nacl_actions = [
    "CreateNetworkAcl",
    "CreateNetworkAclEntry",
    "DeleteNetworkAcl",
    "DeleteNetworkAclEntry",
    "ReplaceNetworkAclAssociation",
    "ReplaceNetworkAclEntry"
]
gateway_actions = [
    "AttachInternetGateway",
    "AttachVpnGateway",
    "CreateCustomerGateway",
    "CreateEgressOnlyInternetGateway",
    "CreateInternetGateway",
    "CreateNatGateway",
    "CreateTransitGateway",
    "CreateVpnGateway",
    "DeleteCustomerGateway",
    "DeleteEgressOnlyInternetGateway",
    "DeleteInternetGateway",
    "DeleteNatGateway",
    "DeleteTransitGateway",
    "DeleteVpnGateway",
    "DetachInternetGateway",
    "DetachVpnGateway"
]

routing_actions = [
    "AssociateRouteTable",
    "CreateClientVpnRoute",
    "CreateRoute",
    "CreateRouteTable",
    "CreateTransitGatewayRoute",
    "CreateTransitGatewayRouteTable",
    "CreateVpnConnectionRoute",
    "DeleteClientVpnRoute",
    "DeleteRoute",
    "DeleteRouteTable",
    "DeleteTransitGatewayRoute",
    "DeleteTransitGatewayRouteTable",
    "DeleteVpnConnectionRoute",
    "DisableTransitGatewayRouteTablePropagation",
    "DisableVgwRoutePropagation",
    "DisassociateRouteTable",
    "DisassociateTransitGatewayRouteTable",
    "EnableTransitGatewayRouteTablePropagation",
    "EnableVgwRoutePropagation",
    "ExportTransitGatewayRoutes",
    "ReplaceRoute",
    "ReplaceRouteTableAssociation",
    "ReplaceTransitGatewayRoute"
]

vpc_actions = [
    "AcceptTransitGatewayVpcAttachment",
    "AcceptVpcEndpointConnections",
    "AcceptVpcPeeringConnection",
    "AssociateVpcCidrBlock",
    "AttachClassicLinkVpc",
    "CreateDefaultVpc",
    "CreateTransitGatewayVpcAttachment",
    "CreateVpc",
    "CreateVpcEndpoint",
    "CreateVpcEndpointConnectionNotification",
    "CreateVpcEndpointServiceConfiguration",
    "CreateVpcPeeringConnection",
    "DeleteTransitGatewayVpcAttachment",
    "DeleteVpc",
    "DeleteVpcEndpointConnectionNotifications",
    "DeleteVpcEndpoints",
    "DeleteVpcEndpointServiceConfigurations",
    "DeleteVpcPeeringConnection",
    "DetachClassicLinkVpc",
    "DisableVpcClassicLink",
    "DisableVpcClassicLinkDnsSupport",
    "DisassociateVpcCidrBlock",
    "EnableVpcClassicLink",
    "EnableVpcClassicLinkDnsSupport",
    "ModifyTransitGatewayVpcAttachment",
    "ModifyVpcAttribute",
    "ModifyVpcEndpoint",
    "ModifyVpcEndpointConnectionNotification",
    "ModifyVpcEndpointServiceConfiguration",
    "ModifyVpcEndpointServicePermissions",
    "ModifyVpcPeeringConnectionOptions",
    "ModifyVpcTenancy",
    "MoveAddressToVpc",
    "RejectTransitGatewayVpcAttachment",
    "RejectVpcEndpointConnections",
    "RejectVpcPeeringConnection"
]

def push_slack(slack_request):
    hook_url = slack_request['hook_url']
    slack_message =slack_request['msg']
    
    req = Request(hook_url, json.dumps(slack_message).encode('utf-8'))
    
    try:
      response = urlopen(req)
      response.read()
      logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
      logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
      logger.error("Server connection failed: %s", e.reason)

def check_event(detail):
    
    slack_request = {}
    event_name = detail['eventName']
    account_id = detail['userIdentity']['accountId']
    access_key_id = detail['userIdentity']['accessKeyId']
    user_name = detail['userIdentity']['userName']
    parameters = detail['requestParameters']
    
    if event_name in subnet_actions:
        category = "Subnet"
        if subnet_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif subnet_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif subnet_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"
            
    elif event_name in nacl_actions:
        category = "NACL"
        if nacl_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif nacl_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif nacl_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"

    elif event_name in gateway_actions:
        category = "Gateway"
        if gateway_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif gateway_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif gateway_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"
    
    elif event_name in routing_actions:
        category = "Routing"
        if routing_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif routing_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif routing_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"

    elif event_name in vpc_actions:
        category = "VPC"
        if vpc_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif vpc_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif vpc_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"
    else:
        return None
    slack_request = {
            "hook_url" : hook_url,
            "msg" : {
              "channel" : channel,
              "username" : "AWS:Networking modification alert",
              "text" : "*%s Action: %s*" % (category,event_name),
              "attachments": [
                  {
                    "color": color,
                    "fields": [
                        {
                            "title": "Account ID",
                            "value": account_id,
                            "short": True
                        },
                        {
                            "title": "Access key ID",
                            "value": access_key_id,
                            "short": True
                        },
                        {
                            "title": "User name",
                            "value": user_name,
                            "short": True
                        },
                        {
                            "title": "Detail parameters",
                            "value": str(parameters)
                        }
                    ],
                  }
                ]
            }
        }
    return slack_request


def lambda_handler(event, context):
    # TODO implement
    logger.info("Event: " + str(event))
    
    detail = event['detail']
    logger.info("Detail: " + str(detail))
    
    slack_request = check_event(detail)
    if slack_request == None:
        pass
    else:
        push_slack(slack_request)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
