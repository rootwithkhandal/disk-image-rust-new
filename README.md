# Image Mounter - Autopsy Python Plugin

This project has been rebuilt as an Autopsy Data Source Ingest Module using Python (Jython). 
It automatically mounts data source images to the local filesystem using OS-native tools when the ingest module runs.

## Features
- **Cross-platform**: Mounts on Windows (`Mount-DiskImage`), macOS (`hdiutil`), and Linux (`losetup`) automatically during ingest.
- **Data Source Ingest**: Runs when an image is added to Autopsy.

## Installation

1. Copy the `autopsy_plugin` directory to your Autopsy Python modules folder.
   - **Windows**: `%APPDATA%\autopsy\python_modules\`
   - **Linux/macOS**: `~/.autopsy/dev/python_modules/`
2. Restart Autopsy.
3. The plugin will be available under **Tools > Python Plugins** and during the Ingest Module selection wizard as **Image Mounter**.

## Usage

1. Add a Data Source to your case in Autopsy.
2. In the "Configure Ingest Modules" step, check the box for **Image Mounter**.
3. The module will run and automatically mount the image to your OS filesystem. You can check the Autopsy messages (bottom right corner) for success or error logs.

## Note on Legacy Code
The previous Rust-based CLI version of `imgmount` is now deprecated. You can safely remove the `src/`, `target/`, and Rust build files (`Cargo.toml`, etc.) from this repository.
