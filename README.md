# SafeCrypt

SafeCrypt is a command-line tool for securely encrypting and decrypting files and folders using AES-256-GCM encryption. The tool leverages Argon2 for key derivation to ensure strong encryption and secure password-based key management. The encrypted files can be stored either as individual files or within a ZIP container for easy distribution.

## Features

- **AES-256-GCM Encryption**: Secure encryption using AES in GCM mode, ensuring confidentiality and integrity.
- **Argon2 Key Derivation**: Uses Argon2 for generating strong keys from passwords with configurable iterations, memory, and parallelism.
- **File and Folder Support**: Encrypts individual files, entire folders, or creates encrypted ZIP containers.
- **Password-protected Key Management**: Option to use password-protected keys for encryption and decryption.
- **Cross-platform**: Can be run on any platform where Go is supported.

## Prerequisites

- Go 1.20+ must be installed.

## Compilation

To compile the SafeCrypt program, clone the repository and build the project:

1. Clone the repository:

```bash
git clone https://github.com/mshafiee/safecrypt.git
cd safecrypt
```

2. Compile the program:

```bash
go build -o safecrypt main.go
```

This will generate a binary named `safecrypt` in the current directory.

## Usage

### Command-line Options

```bash
Usage:
  ./safecrypt --cmd <encrypt|decrypt> --input <file_path|folder_path|zip_path> [options]

Options:
  --cmd <encrypt|decrypt>                   Specify whether to encrypt or decrypt the input.
  --input <file_path|folder_path|zip_path>  The file, folder, or ZIP file to encrypt or decrypt.
  --keypath <keyfile_path>                  Path to the key file (password-protected).
  --output <output_path>                    Output file, folder, or ZIP file for encrypted/decrypted files (optional).
  --usezip                                  Store encrypted files in a ZIP container.
  --help, -h                                Display help message.
```

### Examples

#### Encrypt a single file

```bash
./safecrypt --cmd encrypt --input /path/to/file.txt --keypath /path/to/keyfile
```

This will encrypt the file and generate an `.enc` encrypted version.

#### Decrypt a single file

```bash
./safecrypt --cmd decrypt --input /path/to/file.txt.enc --keypath /path/to/keyfile
```

This will decrypt the previously encrypted `.enc` file.

#### Encrypt a folder

```bash
./safecrypt --cmd encrypt --input /path/to/folder --keypath /path/to/keyfile
```

This command will encrypt all files in the folder, generating `.enc` encrypted files for each file.

#### Decrypt a folder

```bash
./safecrypt --cmd decrypt --input /path/to/folder --keypath /path/to/keyfile
```

This will decrypt previously encrypted `.enc` files in the folder.

#### Encrypt a folder into a ZIP container

```bash
./safecrypt --cmd encrypt --input /path/to/folder --usezip --keypath /path/to/keyfile
```

This will encrypt all files and store them in a single ZIP file.

#### Decrypt a ZIP container

```bash
./safecrypt --cmd decrypt --input /path/to/zipfile.zip --keypath /path/to/keyfile
```

This will extract and decrypt the contents of the ZIP file.

## Key Management

SafeCrypt uses password-based key encryption to securely manage encryption keys. You can either specify an existing key or generate a new one.

### Generate a new key

When you run the encryption command without specifying a key file, SafeCrypt will prompt for a password and generate a new key file:

```bash
Generated new encrypted key file: generated_keyfile
```

### Use an existing key

To use an existing key for encryption or decryption, provide the path to the key file using the `--keypath` option.

## Security Considerations

- **Strong Password**: Always use a strong password when encrypting your key files.
- **Key Protection**: Keep your key file secure, as it is required for decrypting the data.
- **Encryption Algorithm**: AES-GCM provides authenticated encryption, ensuring both confidentiality and integrity of your files.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Repository

For more details and to contribute, visit the project repository: [SafeCrypt GitHub Repository](https://github.com/mshafiee/safecrypt.git)
