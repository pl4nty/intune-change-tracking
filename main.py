from dotenv import load_dotenv
load_dotenv()

import aiohttp
import asyncio
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from azure.identity.aio import DefaultAzureCredential, ClientAssertionCredential
from msgraph_beta import GraphServiceClient
import requests

from kiota_abstractions.base_request_configuration import RequestConfiguration
from kiota_http.middleware.options import ResponseHandlerOption
from kiota_abstractions.native_response_handler import NativeResponseHandler

from msgraph_beta.generated.device_management.configuration_settings.configuration_settings_request_builder import ConfigurationSettingsRequestBuilder
from msgraph_beta.generated.security.microsoft_graph_security_run_hunting_query.microsoft_graph_security_run_hunting_query_request_builder import MicrosoftGraphSecurityRunHuntingQueryRequestBuilder
from msgraph_beta.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import RunHuntingQueryPostRequestBody

client = GraphServiceClient(DefaultAzureCredential(), ['https://graph.microsoft.com/.default'])
request_config = RequestConfiguration(
    options=[ResponseHandlerOption(NativeResponseHandler())],
)

# id_10699 -> id
def cleanDCv1Ids(setting):
    id = '_'.join(setting.get('id').split('_')[:-1])
    setting['id'] = id
    for child in setting.get('childSettings', []):
        cleanDCv1Ids(child)
    for option in setting.get('options', []):
        for child in option.get('children', []):
            cleanDCv1Ids(child)
    for column in setting.get('columns', []):
        if metadata := column.get('metadata'):
            cleanDCv1Ids(metadata)

async def main():
    # Setting status errors
    async with aiohttp.ClientSession() as session, session.get('https://intune.microsoft.com/signin/idpRedirect.js') as resp:
        versions = await resp.text()
        versions = re.search(r'\"extensionsPageVersion\":({[^}]+})', versions).group(1)
        versions = json.loads(versions)

        root = 'https://afd-v2.hosting.portal.azure.net'
        root_devicesettings = f'{root}/intunedevicesettings/Content/{versions.get('Microsoft_Intune_DeviceSettings')[0]}/Scripts/DeviceConfiguration'

        # map setting error codes to descriptions
        async with session.get(f'{root_devicesettings}/Blades/DevicePoliciesStatus/SettingStatus.js') as resp:
            data = await resp.text()
            data = re.search(r'SettingStatusErrorMap = ({[^}]+})', data).group(1)
            data = json.loads(data, strict=False) # some strings have control characters
            with open('SettingStatusErrors.json', 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)

        # DCv1 policies
        output = 'DCv1'
        shutil.rmtree(output)
        for source in ['Configuration', 'Compliance']:
            os.makedirs(Path(output, source))
            async with session.get(f'{root_devicesettings}/Metadata/{source}Metadata.js') as resp:
                data = await resp.text()
                data = re.search(r'(?s)metadata = ({.+});', await resp.text()).group(1)
                data = json.loads(data)
                for family in data.values():
                    for setting in family:
                        # id_10699 -> id
                        id = '_'.join(setting.get('id').split('_')[:-1])
                        cleanDCv1Ids(setting)
                        path = Path(output, source, id).with_suffix('.json')
                        with open(path, 'w', encoding='utf-8') as f:
                            json.dump(setting, f, ensure_ascii=False, indent=4)

    data = await client.service_principals.with_url('https://graph.microsoft.com/beta/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints').get(request_configuration=request_config)
    value_array = data.json().get('value')
    sorted_value_array = sorted(value_array, key=lambda x: x['capability'])
    with open('Endpoints.json', 'w', encoding='utf-8') as f:
        json.dump(sorted_value_array, f, ensure_ascii=False, indent=4)

    # Service principals (Enterprise Apps)
    if os.path.exists('ServicePrincipals'):
        shutil.rmtree('ServicePrincipals')
    os.makedirs('ServicePrincipals')
    next = 'https://graph.microsoft.com/beta/servicePrincipals'
    while next is not None:
        data = await client.service_principals.with_url(next).get(request_configuration=request_config)
        data = data.json()
        for sp in data.get('value'):
            app_id = sp.get('appId')
            with open(f'ServicePrincipals/{app_id}.json', 'w', encoding='utf-8') as f:
                json.dump(sp, f, ensure_ascii=False, indent=4)
        next = data.get('@odata.nextLink')

    # Planned changes or new features in Microsoft Entra
    def assertion_product_changes():
        data = requests.post(f'https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}/oauth2/v2.0/token', {
            'client_id': '9d15ec9c-4104-48aa-9688-c907238f257b', # ChangeManagementHub
            'scope': 'https://graph.microsoft.com//.default openid profile offline_access',
            'grant_type': 'refresh_token',
            'brk_client_id': 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',
            'redirect_uri': 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://entra.microsoft.com',
            'refresh_token': os.environ['AZURE_CHANGEMGMT_RT']
        }, headers={'Origin': 'https://entra.microsoft.com'}).json() # can be any origin
        subprocess.run(['gh', 'secret', 'set', 'AZURE_CHANGEMGMT_RT', '--body', data['refresh_token'], '--repo', os.environ['REPO']])
        return data['access_token']
    customClient = GraphServiceClient(ClientAssertionCredential(os.environ['AZURE_TENANT_ID'], '9d15ec9c-4104-48aa-9688-c907238f257b', assertion_product_changes), ['https://graph.microsoft.com/.default'])
    if os.path.exists('ProductChanges'):
        shutil.rmtree('ProductChanges')
    os.makedirs('ProductChanges')
    next = 'https://graph.microsoft.com/beta/identity/productChanges'
    while next is not None:
        data = await customClient.identity.with_url(next).get(request_configuration=request_config)
        data = data.json()
        for change in data.get('value'):
            id = change.get('id')
            with open(f'ProductChanges/{id}.json', 'w', encoding='utf-8') as f:
                json.dump(e, f, ensure_ascii=False, indent=4)
        next = data.get('@odata.nextLink')

    for table in [
        'AlertEvidence',
        'AlertInfo',
        'BehaviorEntities',
        'BehaviorInfo',

        'AADSignInEventsBeta',
        'AADSpnSignInEventsBeta',
        'CloudAppEvents',
        'IdentityInfo',
        'IdentityLogonEvents',

        'EmailAttachmentInfo',
        'EmailEvents',
        'EmailPostDeliveryEvents',
        'EmailUrlInfo',
        'UrlClickEvents',

        'ExposureGraphEdges',
        'ExposureGraphNodes',
    ]:
        data = await client.security.microsoft_graph_security_run_hunting_query.post(request_configuration=request_config, body=RunHuntingQueryPostRequestBody(
            # match columns of 1P schema endpoint
            query=f'{table} | getschema | project Description="", Type=split(DataType, ".")[1], Entity="", Name=ColumnName'
        ))
        if data.json().get('results') is not None:
            with open(f'Defender/{table}.json', 'w', encoding='utf-8') as f:
                json.dump(data.json().get('results'), f, ensure_ascii=False, indent=4)

    # DCv2 policies eg Settings Catalog
    output = 'DCv2'
    shutil.rmtree(output)
    source = 'Settings'
    os.makedirs(Path(output, source))
    # kiota 1.9.1 started dropping deviceManagement from endpoint
    data = await client.device_management.with_url('https://graph.microsoft.com/beta/deviceManagement/configurationSettings').get(request_configuration=request_config)
    for item in data.json().get('value'):
        item.pop('version')
        item.pop('riskLevel', None)
        path = Path(output, source, item.get('id')).with_suffix('.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(item, f, ensure_ascii=False, indent=4)
    # backwards compat
    shutil.rmtree('settings')
    shutil.copytree(Path(output, source), 'settings')

    # DCv2 compliance
    source = 'Compliance'
    os.makedirs(Path(output, source))
    data = await client.device_management.with_url('https://graph.microsoft.com/beta/deviceManagement/complianceSettings').get(request_configuration=request_config)
    for item in data.json().get('value'):
        item.pop('version')
        path = Path(output, source, item.get('id')).with_suffix('.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(item, f, ensure_ascii=False, indent=4)

    source = 'Templates'
    os.makedirs(Path(output, source))
    # kiota 1.9.1 started dropping deviceManagement from endpoint
    data = await client.device_management.with_url('https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates').get(request_configuration=request_config)
    for item in data.json().get('value'):
        path = Path(output, source, item.get('id')).with_suffix('.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(item, f, ensure_ascii=False, indent=4)

asyncio.run(main())
