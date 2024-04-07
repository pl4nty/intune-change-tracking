from dotenv import load_dotenv
load_dotenv()

import aiohttp
import asyncio
import json
import os
import re
import shutil
from pathlib import Path

from azure.identity.aio import DefaultAzureCredential
from msgraph_beta import GraphServiceClient
from kiota_abstractions.native_response_handler import NativeResponseHandler
from kiota_http.middleware.options import ResponseHandlerOption

from msgraph_beta.generated.device_management.configuration_settings.configuration_settings_request_builder import ConfigurationSettingsRequestBuilder

client = GraphServiceClient(DefaultAzureCredential(), ['https://graph.microsoft.com/.default'])

async def main():
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
                        path = Path(output, source, id).with_suffix('.json')
                        with open(path, 'w', encoding='utf-8') as f:
                            json.dump(setting, f, ensure_ascii=False, indent=4)

    # DCv2 policies eg Settings Catalog
    output = 'DCv2'
    shutil.rmtree(output)
    query_params = ConfigurationSettingsRequestBuilder.ConfigurationSettingsRequestBuilderGetQueryParameters(
        top=10
    )
    request_config = ConfigurationSettingsRequestBuilder.ConfigurationSettingsRequestBuilderGetRequestConfiguration(
        options=[ResponseHandlerOption(NativeResponseHandler())],
        # query_parameters=query_params
    )

    source = 'Settings'
    os.makedirs(Path(output, source))
    data = await client.device_management.configuration_settings.get(request_configuration=request_config)
    for item in data.json().get('value'):
        item.pop('version')
        path = Path(output, source, item.get('id')).with_suffix('.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(item, f, ensure_ascii=False, indent=4)

    # backwards compat
    shutil.rmtree('settings')
    shutil.copytree(Path(output, source), 'settings')

    source = 'Templates'
    os.makedirs(Path(output, source))
    data = await client.device_management.configuration_policy_templates.get(request_configuration=request_config)
    for item in data.json().get('value'):
        path = Path(output, source, item.get('id')).with_suffix('.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(item, f, ensure_ascii=False, indent=4)

asyncio.run(main())
