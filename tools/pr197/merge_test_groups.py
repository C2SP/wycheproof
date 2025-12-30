import json
import sys
import os
from pathlib import Path


def merge_test_groups(target_path, source_path):
    target_path = Path(target_path)
    source_path = Path(source_path)

    if not target_path.exists():
        print(f"error: target file {target_path} does not exist")
        os.exit(1)

    if not source_path.exists():
        print(f"error: source file {source_path} does not exist")
        os.exit(1)

    with open(target_path) as f:
        target_data = json.load(f)

    with open(source_path) as f:
        source_data = json.load(f)

    source_test_groups = source_data.get("testGroups", [])

    if not source_test_groups:
        print(f"warning: no test groups found in {source_path}")
        os.exit(1)

    if "testGroups" not in target_data:
        target_data["testGroups"] = []

    original_count = len(target_data["testGroups"])
    target_data["testGroups"].extend(source_test_groups)
    new_count = len(target_data["testGroups"])

    with open(target_path, "w") as f:
        json.dump(target_data, f, indent=2, separators=(",", ": "), ensure_ascii=False)
        f.write("\n")

    print(f"Merged {source_path.name} into {target_path.name}: "
          f"{original_count} → {new_count} test groups")


def main():
    pairs = [
        ("testvectors_v1/mlkem_512_test.json", "testvectors_v1/mlkem_512_decaps_seed_test.json"),
        ("testvectors_v1/mlkem_768_test.json", "testvectors_v1/mlkem_768_decaps_seed_test.json"),
        ("testvectors_v1/mlkem_1024_test.json", "testvectors_v1/mlkem_1024_decaps_seed_test.json"),
    ]

    for target, source in pairs:
        merge_test_groups(target, source)

if __name__ == "__main__":
    main()
