# ForgeLens Memory Imager

ForgeLens Memory Imager is a high-performance, cross-platform memory forensics framework and acquisition tool. It provides a robust engine for dumping and analyzing volatile memory with full forensic capabilities. The project is built in Rust to ensure memory safety, speed, and excellent cross-platform compatibility.

## 🚀 Features

- **High-Performance Analysis Engine**: The core is built with Rust and Rayon to leverage multicore processors for analyzing massive memory dumps efficiently.
- **Versatile Interfaces**:
  - **CLI**: A powerful command-line interface for scripting and headless environments.
  - **TUI Dashboard**: A responsive terminal-based dashboard for progress monitoring.
  - **Desktop App**: A premium cross-platform graphical application powered by Tauri.
- **Modular Architecture**: Pluggable data-source modules for acquiring memory from files, serial devices, and other supported sources.
- **Deep Forensics**: Capable of interpreting binary data formats, finding artifacts, and conducting structured memory analysis using crates like `goblin` and `memmap2`.

## 📦 Project Structure

The workspace is divided into several crates, each with a specific responsibility:

- **`forgelens-core`**: The high-performance volatile memory dump analysis engine.
- **`forgelens-acquire`**: Modules for raw memory acquisition and dumping.
- **`forgelens-cli`**: The command-line forensic scanner (`nvmdump`).
- **`forgelens-gui`**: A lightweight terminal dashboard/GUI for monitoring memory imaging progress.
- **`forgelens-tauri`**: A premium, cross-platform desktop application built with Tauri.

## 🛠️ Getting Started

### Prerequisites

- [Rust Toolchain](https://rustup.rs/) (stable)
- [mise](https://mise.jdx.dev/) (optional, but highly recommended for task management)

### Building from Source

You can build the entire workspace using Cargo or the predefined `mise` tasks.

```bash
# Using standard Cargo
cargo build --workspace --release

# Using mise
mise build
```

## ⚙️ Usage

The framework can be launched in multiple ways depending on your needs. The project uses `mise.toml` for easy command execution:

- **CLI Forensic Scanner**:
  ```bash
  mise cli
  # or: cargo run --bin forgelens-cli
  ```

- **Terminal GUI Dashboard**:
  ```bash
  mise gui
  # or: cargo run --bin forgelens-gui
  ```

- **Tauri Desktop App (Development)**:
  ```bash
  mise tauri
  # or: cargo tauri dev
  ```

### Testing and Linting

We maintain a strict code quality standard. To run the test suite and linters:

```bash
# Run all tests
mise test

# Run formatter and linter (clippy)
mise lint
```

## 🤝 Contributing

Contributions are welcome! Please ensure that any changes are formatted and pass the linting checks (`mise lint`) before opening a pull request.

## 📄 License

*(Add appropriate license information here)*
