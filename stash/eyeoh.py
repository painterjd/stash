
import datetime
import keyring
import json
import requests
import stash.util

STASH_CONTAINER_NAME = "stash_container"

def do_auth(username, apikey, use_cache=True):

    if use_cache:
        token_expires = keyring.get_password('stash', 'tokenexpires')
        token = keyring.get_password('stash', 'token')
        ep_text = keyring.get_password('stash', 'endpoints')

        if token_expires and token and ep_text:
            expires_date = stash.util.parse_iso_8601(token_expires)
            now = datetime.datetime.utcnow()

            if now < expires_date:
                # we should be good, just re-use the
                # token
                return token, json.loads(ep_text)

    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    hdrs = {
        'Content-Type': 'application/json'
    }

    body = {
        "auth":
        {
            "RAX-KSKEY:apiKeyCredentials":
            {
                "username": username,
                "apiKey": apikey
            }
        }
    }

    resp = requests.post(url, data=json.dumps(body), headers=hdrs)

    if resp.ok:
        output = resp.json()

        token = output['access']['token']['id']
        expires_text = output['access']['token']['expires']

        # Cache the token and expiry in the keyring
        keyring.set_password('stash', 'tokenexpires', expires_text)
        keyring.set_password('stash', 'token', token)

        # now find the block storage endpoints
        sc = output['access']['serviceCatalog']


        # Find all of the object store endpoints
        os_endpoints = [service['endpoints'] for
            service in sc if service['type'] == 'object-store'][0]

        ep_text = json.dumps(os_endpoints)
        keyring.set_password('stash', 'endpoints', ep_text)

        return token, os_endpoints

    elif resp.status_code == 401:
        print (Fore.RED, "Invalid username/API key?")
        return False

def has_stash_container(token, url):

    url = url + '/' + STASH_CONTAINER_NAME

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.head(url, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to check for stash container")

def create_stash_container(token, url):

    url = url + '/' + STASH_CONTAINER_NAME

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.put(url, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to create stash container")

def file_exists(token, url, filename):
    """Shares the specified file"""

    print ("Sharing '{0}' from your stash".format(filename))

    url = url + '/' + STASH_CONTAINER_NAME
    url = url + '/' + stash.util.encode_filename(filename)

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.head(url, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to stash a file")

def read_temp_url_key(token, url):

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.head(url, headers=hdrs)

    if output.ok:
        return output.headers.get('X-Account-Meta-Temp-Url-Key')

