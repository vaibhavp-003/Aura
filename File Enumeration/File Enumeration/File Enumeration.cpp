#include <iostream>
#include <filesystem>
using namespace std;
using namespace filesystem;

namespace fs = std::filesystem;

int main() {
    // Specify the drive to enumerate
    fs::path drive_path = "D:/Softwares";

    // Loop over the drive contents
    for (const auto& entry : fs::directory_iterator(drive_path)) {
        // Check if the entry is a directory
        if (entry.is_directory()) {
            // If it's a directory, print its name
            std::cout << "Directory: " << entry.path().filename() << std::endl;

            // Loop over the directory contents
            for (const auto& dir_entry : fs::directory_iterator(entry.path())) {
                // Check if the entry is a directory or file
                if (dir_entry.is_directory()) {
                    // If it's a directory, print its name
                    std::cout << "    Directory: " << dir_entry.path().filename() << std::endl;
                }
                else {
                    // If it's a file, print its name and size
                    std::cout << "    File: " << dir_entry.path().filename() << " ("
                        << fs::file_size(dir_entry.path()) << " bytes)" << std::endl;
                }
            }
        }
        else {
            // If it's a file, print its name and size
            std::cout << "File: " << entry.path().filename() << " ("
                << fs::file_size(entry.path()) << " bytes)" << std::endl;
        }
    }

    return 0;
}
