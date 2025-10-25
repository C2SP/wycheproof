#!/usr/bin/env python3

import json
from pathlib import Path


def main():
    script_dir = Path(__file__).parent.parent
    testvectors_dir = script_dir / 'testvectors_v1'

    json_files = list(testvectors_dir.glob('*.json'))

    for json_file in json_files:
        # AES-FF1 tests include inputs expressed as a list of integers and escaped
        # non-printable characters that format poorly. For now we ignore these 
        # files for reformatting.
        if not json_file.name.startswith('aes_ff1_'):
            reformat_json_file(json_file)


def reformat_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    data = json.loads(content)
    formatted_content = json.dumps(data, indent=2, separators=(',', ': '), ensure_ascii=False)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(formatted_content)
        f.write('\n')


if __name__ == '__main__':
    main()
