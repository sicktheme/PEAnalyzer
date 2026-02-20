Portable Executable (PE) file analyzer with Qt-based GUI.  
Analyze Windows executable files (.exe, .dll, .sys) with detailed structure information.

## Features
- 📋 **Complete PE Structure Parsing**
  - DOS Header
  - NT Headers (File & Optional)
  - Section Headers
  - Data Directories

  **Import Table Analysis**
  - List all imported DLLs
  - Show imported functions with names/ordinals
  - Hint information

   **Export Table Analysis**
  - All exported functions
  - Ordinals and RVAs
  - Name resolution

  **Professional Qt GUI**
  - Tree-based navigation
  - Detailed tables
  - Dark theme support
  - Cross-platform (Windows, macOS, Linux)

## Screenshots
[Main Window](docs/images/header.jpg)
*Main interface with PE structure tree*

[Import Table](docs/images/import.jpg)
*Detailed import analysis*

[Sections](docs/images/sections.jpg)
*Section analysis*

## 🚀 Getting Started
### Prerequisites

- Qt 6.x or higher
- C++17 compatible compiler
- CMake 3.16+ (optional)

### Building from Source

#bash
# Clone the repository
git clone https://github.com/sicktheme/PEAnalyzer.git
cd PEAnalyzer

# Build with qmake
qmake PEAnalyzer.pro
make

# Or with CMake
mkdir build && cd build
cmake ..
cmake --build .
