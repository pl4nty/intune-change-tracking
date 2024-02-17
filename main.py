from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import os
from pathlib import Path

from azure.identity.aio import DefaultAzureCredential
from msgraph_beta import GraphServiceClient
from kiota_abstractions.native_response_handler import NativeResponseHandler
from kiota_http.middleware.options import ResponseHandlerOption

from msgraph_beta.generated.device_management.configuration_settings.configuration_settings_request_builder import ConfigurationSettingsRequestBuilder

client = GraphServiceClient(DefaultAzureCredential(), ['https://graph.microsoft.com/.default'])

async def main():
    output = 'settings'

    query_params = ConfigurationSettingsRequestBuilder.ConfigurationSettingsRequestBuilderGetQueryParameters(
        top=10
    )
    request_config = ConfigurationSettingsRequestBuilder.ConfigurationSettingsRequestBuilderGetRequestConfiguration(
        options=[ResponseHandlerOption(NativeResponseHandler())],
        # query_parameters=query_params
    )
    settings = await client.device_management.configuration_settings.get(request_configuration=request_config)
    
    os.makedirs(output, exist_ok=True)
    for setting in settings.json()['value']:
        setting.pop('version')
        path = Path(output, setting['id']).with_suffix('.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(setting, f, ensure_ascii=False, indent=4)

asyncio.run(main())
