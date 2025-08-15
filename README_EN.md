# SysHideTools
## System-Level Hiding Utility

[中文](README.md)
[English](README_EN.md)

### Project Introduction
SysHideTools is a self-developed system-level hiding utility implemented in C++, specifically designed for Windows platforms. This tool provides powerful process hiding, window hiding, and file hiding capabilities, aiming to help users protect their privacy and enhance system security.

### Features
- **File Hiding**: Provides deep hiding functionality for files and folders, beyond the standard Windows hidden attribute
- **System-Level Operations**: Implemented through kernel-level techniques, offering higher privileges and stealth
- **Lightweight Design**: Small in size, low resource consumption, and efficient operation

### System Requirements
- Operating System: Windows 7/8/10/11 (32-bit or 64-bit)
- Compilation Environment: Visual Studio 2017 or later
- Dependencies: No external dependency libraries, purely native API implementation

### Compilation and Execution
1. Clone or download the project to your local machine
2. Open the `main1.sln` file in Visual Studio 2022
3. Select the appropriate compilation configuration (Debug/Release, x86/x64)
4. Compile the project
5. Run the generated executable file

### Usage Instructions
1. After running the program, a concise interface will be displayed
2. Follow the prompts to execute different hiding functions
3. To view hidden files, go to File Explorer -> Options -> View -> Advanced settings, and uncheck "Hide protected operating system files"

### Project Structure
```
├── log.ico           # Program icon
├── main1.cpp         # Main source code file
├── main1.h           # Header file containing function declarations and macros
├── main1.rc          # Resource file
├── main1.sln         # Visual Studio solution file
├── main1.vcxproj     # Visual Studio project file
├── main1.vcxproj.filters  # Project filters file
├── main1.vcxproj.user     # User-specific project settings file
└── README.md         # Project description document
```

### Development Plan
- Add more hiding strategies and anti-detection mechanisms
- Support more Windows versions and system architectures
- Optimize performance and stability
- Implement self-detection without relying on external operations
- Achieve true system-level hiding

### License
This project is licensed under the Apache 2.0 License. See the LICENSE file for details.

---
**Note**: This tool is for learning and research purposes only. Do not use it for illegal activities. The author is not responsible for any consequences caused by improper use.

### Author's Words
- This is a small tool made in my spare time, and there is still much room for improvement