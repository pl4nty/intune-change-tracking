from msgraph_beta.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import RunHuntingQueryPostRequestBody
from msgraph_beta.generated.security.microsoft_graph_security_run_hunting_query.microsoft_graph_security_run_hunting_query_request_builder import MicrosoftGraphSecurityRunHuntingQueryRequestBuilder
from msgraph_beta.generated.device_management.configuration_settings.configuration_settings_request_builder import ConfigurationSettingsRequestBuilder
from kiota_abstractions.native_response_handler import NativeResponseHandler
from kiota_http.middleware.options import ResponseHandlerOption
from kiota_abstractions.base_request_configuration import RequestConfiguration
import requests
from msgraph_beta import GraphServiceClient
from azure.core.credentials import AccessToken
from azure.identity.aio import DefaultAzureCredential
from pathlib import Path
import time
import subprocess
import shutil
import re
import os
import json
import asyncio
import aiohttp
from dotenv import load_dotenv
load_dotenv()


def cleanDCv1Ids(setting):
    # id_10699 -> id
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
        versions = re.search(
            r'\"extensionsPageVersion\":({[^}]+})', versions).group(1)
        versions = json.loads(versions)

        root = 'https://afd-v2.hosting.portal.azure.net'
        root_devicesettings = f'{root}/intunedevicesettings/Content/{versions.get('Microsoft_Intune_DeviceSettings')[0]}/Scripts/DeviceConfiguration'

        # map setting error codes to descriptions
        async with session.get(f'{root_devicesettings}/Blades/DevicePoliciesStatus/SettingStatus.js') as resp:
            data = await resp.text()
            data = re.search(
                r'SettingStatusErrorMap = ({[^}]+})', data).group(1)
            # some strings have control characters
            data = json.loads(data, strict=False)
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

    client = GraphServiceClient(DefaultAzureCredential(), [
                                'https://graph.microsoft.com/.default'])
    request_config = RequestConfiguration(
        options=[ResponseHandlerOption(NativeResponseHandler())],
    )

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
                json.dump(data.json().get('results'), f,
                          ensure_ascii=False, indent=4)

    # DCv2 configurationSettings eg Settings Catalog
    output = 'DCv2'
    shutil.rmtree(output)
    source = 'Settings'
    os.makedirs(Path(output, source))
    # kiota 1.9.1 started dropping deviceManagement from endpoint
    data = await client.device_management.with_url('https://graph.microsoft.com/beta/deviceManagement/configurationSettings').get(request_configuration=request_config)
    for item in data.json().get('value'):
        item.pop('version')
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

    # DCv2 templates eg security baselines
    source = 'Templates'
    os.makedirs(Path(output, source))
    # kiota 1.9.1 started dropping deviceManagement from endpoint
    data = await client.device_management.with_url('https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates').get(request_configuration=request_config)
    for item in data.json().get('value'):
        path = Path(output, source, item.get('id')).with_suffix('.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(item, f, ensure_ascii=False, indent=4)

    # DCv2 inventorySettings eg Properties catalog
    client = GraphServiceClient(IbizaTokenCredential(
        os.environ['AZURE_INTUNEPORTAL_RT'],
        'Microsoft_Intune_DeviceSettings',
        'microsoft.graph'
    ), ['https://graph.microsoft.com/.default'])
    source = 'Inventory'
    os.makedirs(Path(output, source))
    data = await client.device_management.with_url('https://graph.microsoft.com/beta/deviceManagement/inventorySettings').get(request_configuration=request_config)
    for item in data.json().get('value'):
        item.pop('version')
        path = Path(output, source, item.get('id')).with_suffix('.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(item, f, ensure_ascii=False, indent=4)

    # could only find 24-hour SPA token :(
    # Planned changes or new features in Microsoft Entra via ChangeManagementHub client
    # client = GraphServiceClient(RefreshTokenCredential(
    #     '9d15ec9c-4104-48aa-9688-c907238f257b',
    #     'AZURE_CHANGEMGMT_RT',
    #     'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',
    #     'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://entra.microsoft.com'
    # ), ['https://graph.microsoft.com/.default'])

    # changes = []
    # next = 'https://graph.microsoft.com/beta/identity/productChanges'
    # while next is not None:
    #     data = await client.identity.with_url(next).get(request_configuration=request_config)
    #     data = data.json()
    #     changes.extend(data.get('value', []))
    #     next = data.get('@odata.nextLink')
    # with open('IdentityProductChanges.json', 'w', encoding='utf-8') as f:
    #     json.dump(changes, f, ensure_ascii=False, indent=4)

    # # Office Cloud Policy Service
    # token = RefreshTokenCredential(
    #     '3cf6df92-2745-4f6f-bbcf-19b59bcdb62a',
    #     'AZURE_OCPS_RT',
    # ).get_token('https://config.office.net//.default').token
    # headers = {'Authorization': f'Bearer {token}',
    #            'User-Agent': 'github.com/pl4nty'}
    # for URL in [
    #     # 'https://clients.config.office.net/releases/v1.0/FileList/channelsForProductIds?productId=O365ProPlusRetail&productId=O365ProPlusEEANoTeamsRetail',
    #     # 'https://clients.config.office.net/onboarding/odata/v1.0/Agreementdata',
    #     'https://clients.config.office.net/odbhealth/v1.0/synchealth/reports/versioncount',
    #     'https://clients.config.office.net/releases/v1.0/FileList/languagesForProductIds?productId=O365ProPlusRetail',
    #     'https://config.office.com/appConfig/v1.0/userflights',
    #     # 'https://config.office.com/policyadmin/v1.0/policies',
    #     'https://clients.config.office.net/settings/v1.0/SettingsCatalog/Settings',
    #     'https://config.office.com/appConfig/v1.0/ServiceHealth',
    #     # 'https://config.office.com/onboarding/odata/v1.0/FeatureProvisiondata',
    #     'https://clients.config.office.net/releases/v1.0/OfficeReleases',
    #     # POST https://clients.config.office.net/intents/odata/v1.0/ComponentGroupIntent {"componentGroupId": "a4e9e0f7-28cc-4304-98bc-fe2cb31121e0", "adminSelection": "off"} controls WebView2 autoinstall, or 675c828d-2e53-4ace-9697-75c5264b31c4 for Teams
    # ]:
    #     data = requests.get(URL, headers=headers)
    #     with open(f'OCPS/{URL.split('/')[-1].split('?')[0]}.json', 'w', encoding='utf-8') as f:
    #         json.dump(data.json(), f, ensure_ascii=False, indent=4)

    # data = requests.get(
    #     'https://clients.config.office.net/onboarding/odata/v1.0/FeatureData', headers=headers)
    # with open(f'OCPS/FeatureData.json', 'w', encoding='utf-8') as f:
    #     json.dump(data.json()['value'], f, ensure_ascii=False, indent=4)

    # Teams Admin Center
    token = RefreshTokenCredential(
        '2ddfbe71-ed12-4123-b99b-d5fc8a062a79',
        'AZURE_TEAMS_RT',
    ).get_token('https://api.spaces.skype.com/.default').token
    headers = {'Authorization': f'Bearer {token}'}
    data = requests.post('https://authsvc.teams.microsoft.com/v1.0/authz', headers=headers).json()
    del data['tokens']
    with open(f'Teams/discovery.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    data = requests.get(
        'https://teams.microsoft.com/api/mt/part/au-01/beta/users/appsCatalog', headers=headers)
    with open(f'Teams/appsCatalog.json', 'w', encoding='utf-8') as f:
        json.dump(data.json(), f, ensure_ascii=False, indent=4)

    # M365 Admin Center via Teams
    token = RefreshTokenCredential(
        '2ddfbe71-ed12-4123-b99b-d5fc8a062a79',
        'AZURE_TEAMS_RT',
    ).get_token('https://portal.office.com/.default').token
    headers = {'Authorization': f'Bearer {token}'}
    for URL in [
        # 'https://admin.microsoft.com/api/concierge/GetConciergeConfig?appName=teamsadmincenter&culture=en-US',
        'https://admin.microsoft.com/admin/api/features/config',
        'https://admin.microsoft.com/admin/api/features/all',
        'https://admin.microsoft.com/fd/bcws/api/v1/IntraTenantPartner/getPartnerList',
        'https://admin.microsoft.com/fd/bsxcommerce/v1/ProductOffers/EligibleProductOffers?language=en-US',
    ]:
        data = requests.get(URL, headers=headers)
        with open(f'M365Admin/{URL.split('/')[-1].split('?')[0]}.json', 'w', encoding='utf-8') as f:
            json.dump(data.json(), f, ensure_ascii=False, indent=4)
    for pair in [
        ['https://admin.microsoft.com/fd/addins/api/availableApps?workloads=MetaOS,Teams', 'apps'],
        ['https://admin.microsoft.com/fd/edgeenterpriseextensionsmanagement/api/policies', 'policy_definitions'],
        ['https://admin.microsoft.com/fd/dms/odata/C2RReleaseInfo', 'value'],
        ['https://admin.microsoft.com/fd/bsxcommerce/v1/ProductOfferIndex?language=en-US', 'results'],
        ['https://admin.microsoft.com/fd/m365licensing/v3/licensedProducts', 'value'],
        ['https://admin.microsoft.com/fd/edgeenterpriseextensionsmanagement/api/sidebarExtensions', 'hub_apps'],
    ]:
        data = requests.get(pair[0], headers=headers)
        with open(f'M365Admin/{pair[0].split('/')[-1].split('?')[0]}.json', 'w', encoding='utf-8') as f:
            json.dump(data.json()[pair[1]], f, ensure_ascii=False, indent=4)
    data = requests.get(
        'https://admin.microsoft.com/admin/api/servicehealth/status/activeCM?showResolved=true', headers=headers).json()['ServiceStatus']
    flattened_data = []
    for service in data:
        flattened_data += service['MessagesByClassification']['Incidents']
        flattened_data += service['MessagesByClassification']['Advisories']
    with open('M365Admin/ServiceHealth.json', 'w', encoding='utf-8') as f:
        json.dump(flattened_data, f, ensure_ascii=False, indent=4)
    data = requests.get(
        'https://admin.microsoft.com/api/concierge/GetConciergeConfig', headers=headers).json()
    data.pop('SessionID')
    with open(f'M365Admin/GetConciergeConfig.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    data = requests.get(
        'https://admin.microsoft.com/admin/api/messagecenter', headers=headers).json()['Messages']
    for item in data:
        item.pop('ActionRequiredBySortValue', None)
    with open(f'M365Admin/messagecenter.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


class IbizaTokenCredential(object):
    def __init__(self, portalAuthorization, extensionName, resourceName):
        self._body = {
            'portalAuthorization': portalAuthorization,
            'extensionName': extensionName,
            'resourceName': resourceName,
            'tenant': os.environ["AZURE_TENANT_ID"]
        }

    def get_token(self, *scopes: str, claims=None, tenant_id=None, **kwargs):
        data = requests.post('https://intune.microsoft.com/api/DelegationToken', json=self._body,
                             # authHeader is null without portalId
                             cookies={'portalId': 'f4a17c62-20c9-44b4-bde0-9206b1578bd2'}).json()
        subprocess.run(['gh', 'secret', 'set', 'AZURE_INTUNEPORTAL_RT', '--body',
                       data['portalAuthorization'], '--repo', os.environ['REPO']])

        token = data['value']['authHeader'].split()[1]
        return AccessToken(token, expires_on=data['value']['expiresAt'])


class RefreshTokenCredential(object):
    def __init__(self, client_id, token_envvar, brk_client_id=None, redirect_uri=None):
        self._headers = {
            'Origin': 'https://microsoft.com'
        }
        self._body = {
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'refresh_token': os.environ[token_envvar],
        }
        self._token_envvar = token_envvar

        if brk_client_id is not None:
            self._body['brk_client_id'] = brk_client_id
            self._body['redirect_uri'] = redirect_uri

    def get_token(self, *scopes: str, claims=None, tenant_id=None, **kwargs):
        self._body['scope'] = scopes
        data = requests.post(
            f'https://login.microsoftonline.com/{os.environ["AZURE_TENANT_ID"]}/oauth2/v2.0/token', self._body, headers=self._headers).json()

        if 'refresh_token' not in data:
            print(data)
            raise Exception('token refresh failed')
        self._body['refresh_token'] = data['refresh_token']
        subprocess.run(['gh', 'secret', 'set', self._token_envvar,
                       '--body', data['refresh_token'], '--repo', os.environ['REPO']])

        return AccessToken(token=data['access_token'], expires_on=int(time.time()+data['expires_in']))


asyncio.run(main())
