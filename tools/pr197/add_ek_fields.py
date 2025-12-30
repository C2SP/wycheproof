import json
import sys
import os
from pathlib import Path

def insert_after(d, pos, new_key, new_value):
    if new_key in d:
        d[new_key] = new_value
        return
    assert pos in d, f"Key '{pos}' not found in dict"
    items = list(d.items())
    d.clear()
    for k, v in items:
        d[k] = v
        if k == pos:
            d[new_key] = new_value

def process_file(json_path):
    json_path = Path(json_path)

    ek_txt_path = json_path.parent / (json_path.stem + ".ek.txt")

    if not ek_txt_path.exists():
        print(f"warning: {ek_txt_path} does not exist")
        os.exit(1)

    with open(ek_txt_path) as f:
        ek_lines = f.read().splitlines()

    with open(json_path) as f:
        j = json.load(f)

    line_index = 0
    for test_group in j["testGroups"]:
        if "tests" not in test_group:
            continue

        for test in test_group["tests"]:
            if "tcId" in test:
                test["tcId"] = test["tcId"] + 1

            if line_index < len(ek_lines):
                ek_value = ek_lines[line_index].strip()
                if ek_value:  # Only add if not empty
                    insert_after(test, "seed", "ek", ek_value)

            line_index += 1

    with open(json_path, "w") as f:
        json.dump(j, f, indent=2, separators=(",", ": "), ensure_ascii=False)
        f.write("\n")

    print(f"Processed {json_path}: updated {line_index} test cases")

def main():
    files = [
        "testvectors_v1/mlkem_512_decaps_seed_test.json",
        "testvectors_v1/mlkem_768_decaps_seed_test.json",
        "testvectors_v1/mlkem_1024_decaps_seed_test.json",
    ]

    for file_path in files:
        process_file(file_path)

if __name__ == "__main__":
    main()
