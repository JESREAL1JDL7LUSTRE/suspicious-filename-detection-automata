import os

# Pattern → DFA mapping (original ones)
pattern_map = {
    "exe": ("executable", 0, ".exe"),
    "scr": ("screensaver", 1, ".scr"),
    "bat": ("batch_file", 2, ".bat"),
    "vbs": ("vbscript", 3, ".vbs"),
    "update": ("mimic_legitimate", 4, ".txt"),
    "password": ("deceptive_password", 5, ".txt"),
    "stealer": ("deceptive_stealer", 6, ".txt"),
    "setup": ("deceptive_setup", 7, ".txt"),
    "patch": ("deceptive_patch", 8, ".txt"),
}

# Additional SAFE mock file types (no DFA mapping)
extra_files = [
    (".py",  "python_script"),
    (".txt", "generic_text"),
    (".md",  "markdown_doc")
]

try:
    file_count = int(input("How many files per pattern? "))
except ValueError:
    print("Please enter a valid integer.")
    exit()

output_dir = "mock_files"
os.makedirs(output_dir, exist_ok=True)

total_files = 0

# Generate DFA-related files
for pattern, (description, dfa_id, extension) in pattern_map.items():
    for i in range(1, file_count + 1):
        filename = f"{pattern}_{i}{extension}"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("[PATTERN -> DFA MAPPING]\n")
            f.write(f"Pattern: {pattern}\n")
            f.write(f"Description: {description}\n")
            f.write(f"DFA ID: {dfa_id}\n")
            f.write(f"Instance: {i}\n")
            f.write("\nSAFE MOCK FILE — contains no real executable code.\n")

        total_files += 1

# Generate extra miscellaneous mock files
for ext, category in extra_files:
    for i in range(1, file_count + 1):
        filename = f"extra_{category}_{i}{ext}"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("[EXTRA MOCK FILE]\n")
            f.write(f"Category: {category}\n")
            f.write(f"Extension: {ext}\n")
            f.write(f"Instance: {i}\n")
            f.write("\nSAFE MOCK FILE — just placeholder text.\n")

        total_files += 1

print(f"Generated {total_files} mock files in '{output_dir}'")