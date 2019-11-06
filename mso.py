import requests
import json
import urllib3
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

auth = {
  'username': 'admin',
  'password': 'Cisco123!Cisco123!'
}

xls_file = pd.read_excel(r'./cloud-aci-id.xlsx')
xls_file = xls_file[xls_file["id"]==2]
for i in xls_file.index:
    url = 'https://{}'.format(xls_file['mso'][i])
    podId = int(xls_file['id'][i])
    vlanId = int(xls_file['vlan'][i])
    print('Pod {} with VLAN {} on MSO {}'.format(podId, vlanId, url))
    r = requests.post('{}/api/v1/auth/login'.format(url), json=auth, verify=False)

    token = r.json()['token']
    headers = {'Authorization': 'Bearer {}'.format(token)}
    newSite = {
        'name': 'On-Premises',
        'urls': [
            'https://192.168.200.193'
        ],
        'username': 'admin',
        'password': 'MySuperSecretPassword',
        'apicSiteId': '1',
        'labels': [],
        'location': {
            'long': -123.91160220994475,
            'lat': 47.25848009811691
        }
    }

    r = requests.get('{}/api/v1/sites'.format(url), headers=headers, verify=False)
    sites = r.json()['sites']
    for site in sites:
        if site['name'] == newSite['name']:
            newSite['id'] = site['id']
            print('Site ID: {}'.format(newSite['id']))
            

    if not 'id' in newSite:
        r = requests.post('{}/api/v1/sites'.format(url), json=newSite, headers=headers, verify=False)
        if r.ok:
            newSite = r.json()
            print('Created new Site')
            print('Site ID: {}'.format(newSite['id']))
        else:
            print(r.status_code)
            print(r.json())
     

    pushSite = {
        "controlPlaneBgpConfig": {
            "peeringType": "full-mesh",
            "ttl": 16,
            "keepAliveInterval": 60,
            "holdInterval": 180,
            "staleInterval": 300,
            "gracefulRestartEnabled": True,
            "maxAsLimit": 0
        },
        "sites": [{
            "fabricId": 1,
            "ospfAreaType": "regular",
            "ospfAreaId": "0",
            "urls": ["https://192.168.200.190"],
            "msiteDataPlaneMulticastTep": "10.1.200.1",
            "bgpPassword": "",
            "cloudRegions": [],
            "ospfPolicies": [{
                "priority": 1,
                "interfaceCost": 0,
                "networkType": "unspecified",
                "retransmitInterval": 5,
                "deadInterval": 40,
                "name": "common/default",
                "interfaceControls": [],
                "transmitDelay": 1,
                "helloInterval": 10
            }, {
                "priority": 1,
                "interfaceCost": 0,
                "networkType": "point-to-point",
                "retransmitInterval": 5,
                "deadInterval": 40,
                "name": "msc-ospf-policy-default",
                "interfaceControls": [],
                "transmitDelay": 1,
                "helloInterval": 10
            }],
            "externalRoutedDomain": "uni/l3dom-MultiSite_L3Dom",
            "apicSiteId": 1,
            "name": "On-Premises",
            "clusterStatus": [{
                "controllerId": 1,
                "controllerName": "lh-dmz1-apic1",
                "dn": "topology/pod-1/node-1/av/node-1",
                "ipAddress": "10.0.0.1",
                "adminState": "in-service",
                "operationalState": "available",
                "health": "fully-fit"
            }],
            "msiteEnabled": True,
            "pods": [{
                "podId": 1,
                "mpodDataPlaneUnicastTep": "10.1.200.3",
                "name": "pod-1",
                "msiteDataPlaneRoutableTEPPools": [],
                "msiteDataPlaneUnicastTep": "10.1.200.2",
                "spines": [{
                    "mpodControlPlaneTep": "10.1.0.201",
                    "routeReflectorEnabled": True,
                    "name": "lh-dmz1-spine201",
                    "msiteControlPlaneTep": "10.1.0.201",
                    "bgpPeeringEnabled": True,
                    "ports": [{
                        "portId": "1/32",
                        "ipAddress": "10.1.201.1/30",
                        "mtu": "9216",
                        "routingPolicy": "msc-ospf-policy-default",
                        "ospfAuthType": "none",
                        "ospfAuthKeyId": 1
                    }],
                    "nodeId": 201
                }]
            }],
            "passwordEncryptionStatus": True,
            "bgpAsn": 100,
            "status": {
                "state": "success"
            },
            "platform": "on-premise",
            "location": {
                "long": -123.91160220994475,
                "lat": 47.25848009811691
            },
            "username": "admin",
            "id": newSite['id'],
            "password": 'MySuperSecretPassword',
            "labels": []
        }],
    }

    r = requests.put('{}/api/v1/sites/fabric-connectivity'.format(url), json=pushSite, headers=headers, verify=False)
    print('PUT Infra')
    print(r.status_code)

    newTenant = {
        'name': 'CloudACI-POD{}'.format(podId),
        'displayName': 'CloudACI-POD{}'.format(podId),
        'siteAssociations': [
        {
            'siteId': newSite['id'],
            'securityDomains': []
        }
        ],
        'userAssociations': [
        {
            'userId': '0000ffff0000000000000020'
        }
        ],
        'description': 'Cloud ACI Lab Tenant {}'.format(podId)
    }

    r = requests.get('{}/api/v1/tenants'.format(url), headers=headers, verify=False)
    tenants = r.json()['tenants']
    for tenant in tenants:
        if tenant['name'] == newTenant['name']:
            newTenant['id'] = tenant['id']
            print('Tenant ID: {}'.format(newTenant['id']))
            break

    if not 'id' in newTenant:
        r = requests.post('{}/api/v1/tenants'.format(url), json=newTenant, headers=headers, verify=False)
        if r.ok:
            newTenant = r.json()
            print('Created new Tenant')
            print('Tenant ID: {}'.format(newTenant['id']))
        else:
            print(r.status_code)
            print(r.json())
    

    newSchema = {
        'id' : '5cde7a5f2a0000d30186c9b4',
        'displayName': 'Hybrid Cloud',
        'templates': [
        {
            'name': 'Template 1',
            'displayName': 'Template 1',
            'tenantId': newTenant['id'],
            'anps': [
            {
                'name': 'ANP',
                'displayName': 'ANP',
                'anpRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/anps/ANP',
                'epgs': [
                {
                    'name': 'Web',
                    'displayName': 'Web',
                    'epgRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/anps/ANP/epgs/Web',
                    'contractRelationships': [
                    {
                        'relationshipType': 'consumer',
                        'contractRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/contracts/Web-to-DB'
                    },
                    {
                        'relationshipType': 'provider',
                        'contractRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/contracts/Web-to-Internet'
                    }
                    ],
                    'subnets': [],
                    'uSegEpg': False,
                    'uSegAttrs': [],
                    'intraEpg': 'unenforced',
                    'proxyArp': False,
                    'preferredGroup': False,
                    'bdRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/bds/BD',
                    'vrfRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/vrfs/Hybrid-VRF',
                    'selectors': []
                },
                {
                    'name': 'DB',
                    'displayName': 'DB',
                    'epgRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/anps/ANP/epgs/DB',
                    'contractRelationships': [
                    {
                        'relationshipType': 'provider',
                        'contractRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/contracts/Web-to-DB'
                    }
                    ],
                    'subnets': [],
                    'uSegEpg': False,
                    'uSegAttrs': [],
                    'intraEpg': 'unenforced',
                    'proxyArp': False,
                    'preferredGroup': False,
                    'bdRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/bds/BD',
                    'vrfRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/vrfs/Hybrid-VRF',
                    'selectors': []
                }
                ]
            }
            ],
            'vrfs': [
            {
                'name': 'Hybrid-VRF',
                'displayName': 'Hybrid-VRF',
                'vrfRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/vrfs/Hybrid-VRF',
                'preferredGroup': False,
                'vzAnyEnabled': False,
                'vzAnyProviderContracts': [],
                'vzAnyConsumerContracts': []
            }
            ],
            'bds': [
            {
                'name': 'BD',
                'displayName': 'BD',
                'bdRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/bds/BD',
                'l2UnknownUnicast': 'proxy',
                'intersiteBumTrafficAllow': False,
                'l2Stretch': True,
                'subnets': [
                {
                    'ip': '10.101.0.254/24',
                    'description': '10.101.0.254/24',
                    'scope': 'public',
                    'shared': False,
                    'noDefaultGateway': False
                }
                ],
                'vrfRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/vrfs/Hybrid-VRF'
            }
            ],
            'contracts': [
            {
                'name': 'Web-to-DB',
                'displayName': 'Web-to-DB',
                'contractRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/contracts/Web-to-DB',
                'filterRelationships': [
                {
                    'filterRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/filters/Any',
                    'directives': [
                    'none'
                    ]
                }
                ],
                'scope': 'context',
                'filterType': 'bothWay',
                'filterRelationshipsProviderToConsumer': [],
                'filterRelationshipsConsumerToProvider': []
            },
            {
                'name': 'Web-to-Internet',
                'displayName': 'Web-to-Internet',
                'contractRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/contracts/Web-to-Internet',
                'filterRelationships': [
                {
                    'filterRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/filters/Any',
                    'directives': [
                    'none'
                    ]
                }
                ],
                'scope': 'context',
                'filterType': 'bothWay',
                'filterRelationshipsProviderToConsumer': [],
                'filterRelationshipsConsumerToProvider': []
            }
            ],
            'filters': [
            {
                'name': 'Any',
                'displayName': 'Any',
                'filterRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/filters/Any',
                'entries': [
                {
                    'name': 'Any',
                    'displayName': 'Any',
                    'description': '',
                    'etherType': 'unspecified',
                    'arpFlag': 'unspecified',
                    'ipProtocol': 'unspecified',
                    'matchOnlyFragments': False,
                    'stateful': False,
                    'sourceFrom': 'unspecified',
                    'sourceTo': 'unspecified',
                    'destinationFrom': 'unspecified',
                    'destinationTo': 'unspecified',
                    'tcpSessionRules': [
                    'unspecified'
                    ]
                }
                ]
            }
            ],
            'externalEpgs': [
            {
                'name': 'Internet',
                'displayName': 'Internet',
                'extEpgType': 'cloud',
                'vrfRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/vrfs/Hybrid-VRF',
                'subnets': [],
                'contractRelationships': [
                {
                    'relationshipType': 'consumer',
                    'contractRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/contracts/Web-to-Internet'
                }
                ],
                'preferredGroup': False,
                'externalEpgRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/externalEpgs/Internet',
                'l3outRef': '',
                'anpRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/anps/ANP'
            }
            ],
            'serviceGraphs': [],
            'intersiteL3outs': []
        }
        ],
        'sites': [
        {
            'siteId': newSite['id'],
            'templateName': 'Template 1',
            'anps': [
            {
                'anpRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/anps/ANP',
                'epgs': [
                {
                    'epgRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/anps/ANP/epgs/Web',
                    'domainAssociations': [],
                    'staticPorts': [],
                    'staticLeafs': [],
                    'uSegAttrs': [],
                    'subnets': [],
                    'selectors': []
                },
                {
                    'epgRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/anps/ANP/epgs/DB',
                    'domainAssociations': [],
                    'staticPorts': [
                    {
                        'type': 'vpc',
                        'path': 'topology/pod-1/protpaths-101-102/pathep-[HX-FI-A_PolGrp]',
                        'portEncapVlan': vlanId,
                        'deploymentImmediacy': 'immediate',
                        'mode': 'regular'
                    },
                    {
                        'type': 'vpc',
                        'path': 'topology/pod-1/protpaths-101-102/pathep-[HX-FI-B_PolGrp]',
                        'portEncapVlan': vlanId,
                        'deploymentImmediacy': 'immediate',
                        'mode': 'regular'
                    }
                    ],
                    'staticLeafs': [],
                    'uSegAttrs': [],
                    'subnets': [],
                    'selectors': []
                }
                ]
            }
            ],
            'vrfs': [],
            'bds': [],
            'contracts': [
            {
                'contractRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/contracts/Web-to-DB'
            },
            {
                'contractRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/contracts/Web-to-Internet'
            }
            ],
            'externalEpgs': [
            {
                'externalEpgRef': '/schemas/5cde7a5f2a0000d30186c9b4/templates/Template 1/externalEpgs/Internet',
                'l3outDn': '',
                'subnets': []
            }
            ],
            'serviceGraphs': [],
            'intersiteL3outs': []
        }
        ]
    }

    r = requests.get('{}/api/v1/schemas'.format(url), headers=headers, verify=False)
    schemas = r.json()['schemas']
    print(schemas)
    found = False
    for schema in schemas:
        if schema['displayName'] == newSchema['displayName']:
            newSchema['id'] = schema['id']
            found = True
            print('Schema ID: {}'.format(newSchema['id']))
            break

    if not found:
        print('Posting new Schema')
        print(newSchema)
        r = requests.post('{}/api/v1/schemas'.format(url), json=newSchema, headers=headers, verify=False)
        if r.ok:
            newSchema = r.json()
            print('Created new Schema')
            print('Schema ID: {}'.format(newSchema['id']))
        else:
            print(r.status_code)
            print(r.json())
            
    print('Pushing Schema to Site')
    r = requests.get('{}/api/v1/execute/schema/{}/template/Template%201'.format(url, newSchema['id']), headers=headers, verify=False)
    print(r.status_code)
    print(r.json())
    