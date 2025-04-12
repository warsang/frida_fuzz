# Installation Guide

This guide will help you set up your environment and install all dependencies for this project, including the `pywfa` package (Wavefront Alignment algorithm).

---

## 1. Setting Up a Virtual Environment

It is recommended to use a Python virtual environment to avoid conflicts with system packages.

**On Windows:**
```sh
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```sh
python3 -m venv venv
source venv/bin/activate
```

---

## 2. Installing Required Packages

Once your virtual environment is activated, install all dependencies using:

```sh
pip install -r requirements.txt
```

This will install all required packages, including `pywfa`.

---

## 3. Special Considerations

### Windows

- Ensure you have a C++ compiler installed (e.g., Visual Studio Build Tools) for packages with native extensions like `pywfa`.
- If you encounter errors related to missing compilers, install [Build Tools for Visual Studio](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

### macOS

- You may need to install Xcode Command Line Tools:
  ```sh
  xcode-select --install
  ```

### Linux

- Ensure you have Python development headers and a C/C++ compiler:
  ```sh
  sudo apt-get update
  sudo apt-get install build-essential python3-dev
  ```

---

## 4. Troubleshooting Tips

- **pip not found:** Use `python -m pip` or `python3 -m pip` instead of `pip`.
- **Compiler errors:** Make sure you have the necessary build tools for your OS (see above).
- **Permission errors:** Try running the install command with elevated permissions, or use a virtual environment.
- **pywfa install fails:** Check that your pip, setuptools, and wheel are up to date:
  ```sh
  pip install --upgrade pip setuptools wheel
  ```

If you continue to have issues, consult the documentation for the specific package or open an issue on the project's repository.

---

## 5. Deactivating the Virtual Environment

When you're done working, you can deactivate the virtual environment with:

```sh
deactivate
```

---