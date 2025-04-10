ompile_ksy.py</path>
$content>
import os
import subprocess
import os
import subprocess
import pathlib

# Define the source and target directories
current_dir = pathlib.Path('.')
ksy_dir = current_dir / 'ksy_definitions/'
generated_dir = current_dir / 'generated_ksy/'

# Create the generated directory if it doesn't exist
if not generated_dir.exists():
    generated_dir.mkdir()

# Ensure __init__.py exists in the generated directory
init_py_path = generated_dir / '__init__.py'
if not init_py_path.exists():
    with open(init_py_path, 'w') as f:
        pass  # Create an empty file

# Function to compile a .ksy file into a .py module
def compile_ksy(ksy_file):
    try:
        # Construct the paths
        ksy_path = ksy_dir / ksy_file
        py_path = generated_dir / f"{ksy_file.split('.')[0]}.py"

        # Check if .py file exists and is older than .ksy file
        if py_path.exists() and ksy_path.stat().st_mtime < py_path.stat().st_mtime:
            print(f"Skipping {ksy_file} as the .py file is newer.")
            return

        # Compile the .ksy file using kaitai-struct-compiler
        command = f"kaitai-struct-compiler {ksy_path} -t python -o {py_path}"
        subprocess.run(command, shell=True, check=True)

        print(f"Successfully compiled {ksy_file} into {py_path.name}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to compile {ksy_file}: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Scan for .ksy files and compile them
for file in os.listdir(ksy_dir):
    if file.endswith('.ksy'):
        compile_ksy(file)

print("Compilation complete.")