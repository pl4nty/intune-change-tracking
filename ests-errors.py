import asyncio
import aiohttp
import csv
from bs4 import BeautifulSoup

async def fetch_error_message(code, session):
    try:
        async with session.get('https://login.microsoftonline.com/error', params={'code': code}, timeout=10) as response:
            response.raise_for_status()
            text = await response.text()
            soup = BeautifulSoup(text, 'html.parser')
            message_tag = soup.find('td', string='Message')
            remediation_tag = soup.find('td', string='Remediation')

            message = message_tag.find_next_sibling('td').text.strip() if message_tag else None
            remediation = remediation_tag.find_next_sibling('td').text.strip() if remediation_tag else None

            if message:
                return code, message, remediation
            return None
    except Exception as e:
        print(f"Error processing code {code}: {e}")
        return None

async def main():
    ERROR_CODE_RANGE = range(0, 10000000)
    OUTPUT_FILENAME = 'ests-errors.csv'

    results = []

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_error_message(code, session) for code in ERROR_CODE_RANGE]
        for result in await asyncio.gather(*tasks):
            if result:
                error_code, message, remediation = result
                results.append((error_code, message, remediation))

    # Sort the results by error code
    results.sort(key=lambda x: x[0])

    # Write the sorted results to the CSV file
    with open(OUTPUT_FILENAME, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Code', 'Message', 'Remediation'])
        writer.writerows(results)

if __name__ == '__main__':
    asyncio.run(main())
