import requests
import pprint
from base64 import b64encode

client_id = 'user+name'
client_secret = 'p@ssw^rd'
base_url = ''

encoded_client_creds = b64encode(f'{client_id}:{client_secret}'.encode('ascii'))

basic_auth = {
        'Authorization' : 'Basic ' + encoded_client_creds.decode('ascii')
}

pprint.pprint(basic_auth)

response = requests.post(
        f'{base_url}/bc/idp/token',
        headers={'Content-Type': 'application/x-www-form-urlencoded', **basic_auth},
        data={'grant_type': 'client_credentials'},
)


response.status_code
token_info = response.json()
pprint.pprint(token_info)
