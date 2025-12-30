import json
import sys
import os
from pathlib import Path


def merge_encaps_test_groups(target_path, source_path):
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

    max_tc_id = 0
    for test_group in target_data["testGroups"]:
        if "tests" in test_group:
            for test in test_group["tests"]:
                if "tcId" in test:
                    max_tc_id = max(max_tc_id, test["tcId"])

    tc_id_offset = max_tc_id

    for test_group in source_test_groups:
        if "tests" in test_group:
            for test in test_group["tests"]:
                if "tcId" in test:
                    test["tcId"] = test["tcId"] + tc_id_offset

    original_count = len(target_data["testGroups"])
    target_data["testGroups"].extend(source_test_groups)
    new_count = len(target_data["testGroups"])

    if "numberOfTests" in target_data and "numberOfTests" in source_data:
        target_data["numberOfTests"] = target_data["numberOfTests"] + source_data["numberOfTests"]

    with open(target_path, "w") as f:
        json.dump(target_data, f, indent=2, separators=(",", ": "), ensure_ascii=False)
        f.write("\n")

    print(f"Merged {source_path.name} into {target_path.name}: "
          f"{original_count} → {new_count} test groups, "
          f"tcId offset: {tc_id_offset}, "
          f"new numberOfTests: {target_data['numberOfTests']}")


def main():
    pairs = [
        ("testvectors_v1/mlkem_512_encaps_test.json", "testvectors_v1/mlkem_512_encaps_seed_test.json"),
        ("testvectors_v1/mlkem_768_encaps_test.json", "testvectors_v1/mlkem_768_encaps_seed_test.json"),
        ("testvectors_v1/mlkem_1024_encaps_test.json", "testvectors_v1/mlkem_1024_encaps_seed_test.json"),
    ]

    for target, source in pairs:
        merge_encaps_test_groups(target, source)

if __name__ == "__main__":
    main()
