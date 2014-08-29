
import datetime
import keyring
import json
import requests
import stash.util
import sys
import os

STASH_CONTAINER_NAME = "stash"
STASH_CONTAINER_VERSIONS = "stash_versions__"

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
        'X-Auth-Token': token,
        'X-Versions-Location': STASH_CONTAINER_VERSIONS
    }

    output = requests.put(url, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to create stash container")

def create_stash_versions_container(token, url):

    url = url + '/' + STASH_CONTAINER_VERSIONS

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

def container_stats(token, url, container):

    url = url + '/' + container

    hdrs = {
        'X-Auth-Token': token
    }

    response = requests.head(url, headers=hdrs)

    if response.status_code == 404:
        return 0, 0
    elif response.ok:
        object_count = int(response.headers.get('x-container-object-count')) or 0
        byte_count = int(response.headers.get('x-container-bytes-used')) or 0

        return object_count, byte_count
    else:  # something else happened
        raise Exception("Unable to create stash container")

def delete_container(token, url, container):

    url = url + '/' + STASH_CONTAINER_VERSIONS

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.delete(url, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to delete container")

def delete_stash_containers(token, url):

    object_count, byte_count = container_stats(token, url,
        STASH_CONTAINER)

    object_count, byte_count = container_stats(token, url,
        STASH_CONTAINER_VERSIONS)

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

class upload_in_chunks(object):
    def __init__(self, filename, chunksize=1 << 13):
        self.filename = filename
        self.chunksize = chunksize
        self.totalsize = os.path.getsize(filename)
        self.readsofar = 0

    def __iter__(self):

        _, filename_only = os.path.split(self.filename)

        with open(self.filename, 'rb') as file:
            while True:
                data = file.read(self.chunksize)
                if not data:
                    sys.stderr.write("\n")
                    break
                self.readsofar += len(data)
                percent = self.readsofar * 100 / self.totalsize
                sys.stderr.write("\r{fname}: {percent:3.0f}%".format(fname=filename_only,
                    percent=percent))

                yield data

    def __len__(self):
        return self.totalsize

class IterableToFileAdapter(object):
    def __init__(self, iterable):
        self.iterator = iter(iterable)
        self.length = len(iterable)

    def read(self, size=-1): # TBD: add buffer for `len(data) > size` case
        return next(self.iterator, b'')

    def __len__(self):
        return self.length
