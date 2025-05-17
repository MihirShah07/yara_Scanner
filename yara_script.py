import os
import subprocess
import json

def run_yara(file_to_check, rules_folder="rules"):
    # Validate the file existence
    if not os.path.isfile(file_to_check):
        return json.dumps({"error": f"File '{file_to_check}' not found."}, indent=4)

    print(f"\n{file_to_check} signature matches in:\n")

    # Dictionary to store the output
    yara_results = {
        "file_checked": file_to_check,
        "matches": []
    }

    # Iterate through all .yar and .yara files in the folder
    for rule_file in os.listdir(rules_folder):
        if rule_file.endswith(".yar") or rule_file.endswith(".yara"):
            rule_path = os.path.join(rules_folder, rule_file)

            # YARA command
            command = f"/opt/yara-4.1.0/yara -s {rule_path} {file_to_check}"

            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)

                if result.stdout:
                    print(f"📌 Matched in: {rule_file}")
                    matches = []
                    lines = result.stdout.strip().split('\n')

                    for line in lines:
                        if line.startswith("RULE"):
                            current_rule = line.split(":")[1].strip()
                        else:
                            parts = line.split(": ")
                            if len(parts) == 2:
                                offset, condition = parts
                                condition =  condition.strip()
                                matches.append(condition)

                    # Store results in dictionary
                    yara_results["matches"].append({
                        "Rule": rule_file,
                        "Conditions": matches
                    })

            except Exception as e:
                print(f"Error running YARA on {rule_file}: {e}")

    # Return results as JSON string
    # return json.dumps(yara_results, indent=4)
    return yara_results
