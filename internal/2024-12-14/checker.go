import json
import sys
from base64 import b64decode, b64encode
from pathlib import Path
from typing import Any

from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from requests import Session

from cdm.cdm import Cdm


disable_warnings(InsecureRequestWarning)


PSSH = 'AAAAaXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAEkIARIQb2sbmIT4PQuGahvYrKOQ0hoIY2FzdGxhYnMiIGV5SmhjM05sZEVsa0lqb2lZV2RsYm5RdE16STNJbjA9MgdkZWZhdWx0'
DRM_TODAY_LICENSE_URL = 'https://lic.staging.drmtoday.com/license-proxy-widevine/cenc/?assetId=agent-327'


class DeviceChecker:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_drmtoday_response(self, challenge: bytes) -> tuple[str | None, dict[str, Any]]:
        res = self.session.post(
            url=DRM_TODAY_LICENSE_URL,
            headers={
                'Origin': 'https://demo.castlabs.com',
                'Referer': 'https://demo.castlabs.com/',
                'dt-custom-data': b64encode(json.dumps({
                    'userId': 'purchase',
                    'sessionId': 'default',
                    'merchant': 'client_dev'
                }).encode()),
            },
            data=challenge,
            timeout=10,
        )

        resp_code = res.headers.get('x-dt-resp-code')
        client_info = res.headers['x-dt-client-info']

        return resp_code, json.loads(b64decode(client_info))

    def check(self, client_id_path: Path, private_key_path: Path):
        device_folder = client_id_path.parent

        cdm = Cdm(client_id_path, private_key_path)

        print('[+] Getting challenge')
        challenge, client_id = cdm.get_challenge(PSSH)
        client_id_info, capabilities = cdm.parse_client_id(client_id)

        print(f'[+] Checking device: {device_folder}')
        code, client_info = self.get_drmtoday_response(challenge)

        status = self.get_status(code)
        security_level = client_info['secLevel']
        manufacturer = client_info.get('manufacturer')
        model = client_info.get('model')

        system_id = client_id_info['SystemId']
        client_id_info.pop('SystemId')

        full_infos = {
            'Status': status,
            'SecurityLevel': f'LEVEL_{security_level}',
            'SystemID': system_id
        }

        if manufacturer is not None:
            full_infos['Manufacturer'] = manufacturer

        if model is not None:
            full_infos['Model'] = model

        full_infos.update({
            'ClientIdInfo': client_id_info,
            'Capabilities': capabilities
        })

        print('DEVICE STATUS:')
        print(json.dumps(full_infos, indent=4))

    @staticmethod
    def get_status(resp_code: str | None) -> str:
        return {
            '0': 'ACTIVE',
            None: 'UNKNOWN',
            '40001': 'REVOKED',
            '40002': 'SERIAL REVOKED',
            '40003': 'REVOKED'
        }.get(resp_code, 'UNKNOWN')


def main(args):
    client_id_path = Path(args[1])
    private_key_path = Path(args[2])

    session = Session()
    session.verify = False

    checker = DeviceChecker(session)

    checker.check(client_id_path, private_key_path)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('USAGE: py checker.py "path/to/client_id" "path/to/private_key"')
        sys.exit(1)

    main(sys.argv)
