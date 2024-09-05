package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	saltSize     = 32        // Salt size
	ivSize       = 12        // IV size for AES-GCM
	keySize      = 32        // 256-bit key size
	iterations   = 3         // Argon2 iterations
	memory       = 64 * 1024 // Argon2 memory usage in KB
	threads      = 4         // Argon2 parallelism
	outputExtEnc = ".enc"    // Extension for encrypted files
	outputExtDec = ".dec"    // Extension for decrypted files
	keyFilePerms = 0600      // Permissions for key file
)

func about() {
	fmt.Println("SafeCrypt - Secure Encrypt/Decrypt Tool (https://github.com/mshafiee/safecrypt)")
	fmt.Println("This tool allows you to securely encrypt and decrypt folders using AES-256-GCM.")
}

func usage() {
	about()
	fmt.Println("\nUsage:")
	fmt.Println("  safecrypt --cmd <encrypt|decrypt> --input <file_path|folder_path|zip_path> [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  --cmd <encrypt|decrypt>                   Specify whether to encrypt or decrypt the input.")
	fmt.Println("  --input <file_path|folder_path|zip_path>  The file, folder, or zip file to encrypt or decrypt.")
	fmt.Println("  --keypath <keyfile_path>                  Path to the key file (password protected).")
	fmt.Println("  --output <output_path>                    Output file, folder, or zip file for encrypted/decrypted files (optional).")
	fmt.Println("  --usezip                                  Store encrypted files in a zip container.")
	fmt.Println("  --help, -h                                Display help message.")
}

func deriveKey(password, salt []byte) []byte {
	// Using Argon2 to derive the encryption key
	return argon2.IDKey(password, salt, iterations, memory, threads, keySize)
}

func encryptKey(key, password []byte) ([]byte, error) {
	// Encrypt the generated key with the user's password
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("failed to generate salt for key encryption")
	}

	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, errors.New("failed to generate IV for key encryption")
	}

	derivedKey := deriveKey(password, salt)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, errors.New("failed to create AES cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to create AES-GCM cipher")
	}

	ciphertext := aesGCM.Seal(nil, iv, key, nil)

	// Return salt + IV + encrypted key
	return append(append(salt, iv...), ciphertext...), nil
}

func decryptKey(encryptedKey, password []byte) ([]byte, error) {
	if len(encryptedKey) < saltSize+ivSize {
		return nil, errors.New("invalid encrypted key length")
	}

	salt := encryptedKey[:saltSize]
	iv := encryptedKey[saltSize : saltSize+ivSize]
	ciphertext := encryptedKey[saltSize+ivSize:]

	derivedKey := deriveKey(password, salt)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, errors.New("failed to create AES cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to create AES-GCM cipher")
	}

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt key")
	}

	return plaintext, nil
}

func promptPassword() ([]byte, error) {
	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, errors.New("failed to read password")
	}
	return bytePassword, nil
}

func getKey(keyPath string, isEncrypt bool) ([]byte, error) {
	if keyPath != "" {
		// Read the key from file and decode the base64
		encryptedKeyBase64, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, errors.New("failed to read key file")
		}

		// Decode from base64
		encryptedKey, err := base64.StdEncoding.DecodeString(string(encryptedKeyBase64))
		if err != nil {
			return nil, errors.New("failed to decode base64 key")
		}

		// Prompt for password to decrypt the key
		password, err := promptPassword()
		if err != nil {
			return nil, errors.New("failed to get password")
		}

		// Decrypt the key using the password
		key, err := decryptKey(encryptedKey, password)
		if err != nil {
			return nil, errors.New("failed to decrypt key file")
		}

		fmt.Printf("Using decrypted key from file: %s\n", keyPath)
		return key, nil
	}

	if isEncrypt {
		return generateKeyFile("generated_keyfile")
	} else {
		return nil, errors.New("a key must be provided for decryption")
	}
}

func generateKeyFile(keyFilePath string) ([]byte, error) {
	// Check if the key file already exists
	if _, err := os.Stat(keyFilePath); err == nil {
		// File exists, verify if it's a valid base64 encoded key
		existingKeyBase64, err := ioutil.ReadFile(keyFilePath)
		if err != nil {
			return nil, errors.New("failed to read existing key file")
		}

		// Decode the existing key from base64
		encryptedKey, err := base64.StdEncoding.DecodeString(string(existingKeyBase64))
		if err != nil {
			return nil, errors.New("existing key file is not in base64 format or is corrupted")
		}

		// Prompt for password to decrypt the key
		fmt.Println("Using existing key file. Please enter the password for key decryption.")
		password, err := promptPassword()
		if err != nil {
			return nil, errors.New("failed to get password for key decryption")
		}

		// Decrypt the key using the provided password
		key, err := decryptKey(encryptedKey, password)
		if err != nil {
			return nil, errors.New("failed to decrypt existing key file")
		}

		fmt.Printf("Successfully decrypted and using existing key file: %s\n", keyFilePath)
		return key, nil // Return the decrypted key
	} else if !os.IsNotExist(err) {
		// Some other error occurred while checking if the file exists
		return nil, errors.New("failed to check if key file exists")
	}

	// If the file doesn't exist, proceed with generating a new key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("failed to generate encryption key")
	}

	// Prompt for password to encrypt the key
	password, err := promptPassword()
	if err != nil {
		return nil, errors.New("failed to get password for key encryption")
	}

	// Encrypt the key using the password
	encryptedKey, err := encryptKey(key, password)
	if err != nil {
		return nil, errors.New("failed to encrypt key")
	}

	// Encode the encrypted key in base64
	base64Key := base64.StdEncoding.EncodeToString(encryptedKey)

	// Write the base64-encoded key to file
	err = ioutil.WriteFile(keyFilePath, []byte(base64Key), keyFilePerms)
	if err != nil {
		return nil, errors.New("failed to write encrypted key file")
	}

	fmt.Printf("Generated new encrypted key file: %s\n", keyFilePath)
	return key, nil
}

func encryptFile(inputPath, outputPath string, key []byte) error {
	plaintext, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return errors.New("failed to read input file")
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return errors.New("failed to generate salt")
	}

	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return errors.New("failed to generate IV")
	}

	derivedKey := deriveKey(key, salt)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return errors.New("failed to create AES cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("failed to create AES-GCM cipher")
	}

	ciphertext := aesGCM.Seal(nil, iv, plaintext, nil)

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return errors.New("failed to create output file")
	}
	defer outputFile.Close()

	_, err = outputFile.Write(salt)
	if err != nil {
		return errors.New("failed to write salt to output file")
	}
	_, err = outputFile.Write(iv)
	if err != nil {
		return errors.New("failed to write IV to output file")
	}
	_, err = outputFile.Write(ciphertext)
	if err != nil {
		return errors.New("failed to write ciphertext to output file")
	}
	return nil
}

func decryptFile(inputPath, outputPath string, key []byte) error {
	ciphertext, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return errors.New("failed to read input file")
	}

	if len(ciphertext) < saltSize+ivSize {
		return errors.New("invalid ciphertext length")
	}

	salt := ciphertext[:saltSize]
	iv := ciphertext[saltSize : saltSize+ivSize]
	ciphertext = ciphertext[saltSize+ivSize:]

	derivedKey := deriveKey(key, salt)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return errors.New("failed to create AES cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("failed to create AES-GCM cipher")
	}

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return errors.New("decryption failed")
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return errors.New("failed to create output file")
	}
	defer outputFile.Close()

	_, err = outputFile.Write(plaintext)
	if err != nil {
		return errors.New("failed to write plaintext to output file")
	}
	return nil
}

func processFiles(inputDir, outputDir string, key []byte, encrypt bool) error {
	err := filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return errors.New("failed to access file or directory")
		}

		relativePath, err := filepath.Rel(inputDir, path)
		if err != nil {
			return errors.New("failed to resolve relative path")
		}

		outputPath := filepath.Join(outputDir, relativePath)
		if info.IsDir() {
			return os.MkdirAll(outputPath, os.ModePerm)
		}

		if encrypt {
			outputPath += outputExtEnc
			return encryptFile(path, outputPath, key)
		} else if strings.HasSuffix(path, outputExtEnc) {
			outputPath = strings.TrimSuffix(outputPath, outputExtEnc)
			return decryptFile(path, outputPath, key)
		}

		return nil
	})
	return err
}

// Process encryption into a zip container
func processFilesToZip(inputDir, zipFilePath string, key []byte) error {
	zipFile, err := os.Create(zipFilePath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to access path: %v", err)
		}

		if info.IsDir() {
			return nil // Skip directories
		}

		relativePath, err := filepath.Rel(inputDir, path)
		if err != nil {
			return fmt.Errorf("failed to resolve relative path: %v", err)
		}

		// Encrypt the file
		encryptedFile, err := encryptFileToBytes(path, key)
		if err != nil {
			return err
		}

		// Write to ZIP archive
		zipFileWriter, err := zipWriter.Create(relativePath + outputExtEnc)
		if err != nil {
			return fmt.Errorf("failed to add file to zip: %v", err)
		}

		_, err = zipFileWriter.Write(encryptedFile)
		if err != nil {
			return fmt.Errorf("failed to write encrypted file to zip: %v", err)
		}

		return nil
	})

	return err
}

// Encrypt file and return encrypted bytes
func encryptFileToBytes(inputPath string, key []byte) ([]byte, error) {
	plaintext, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %v", err)
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}

	derivedKey := deriveKey(key, salt)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %v", err)
	}

	ciphertext := aesGCM.Seal(nil, iv, plaintext, nil)

	// Return salt + IV + ciphertext
	return append(append(salt, iv...), ciphertext...), nil
}

// Decrypt files from a ZIP container
func decryptFilesFromZip(zipFilePath, outputDir string, key []byte) error {
	zipFile, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %v", err)
	}
	defer zipFile.Close()

	for _, file := range zipFile.File {
		// Get the output path where the file will be written
		outputPath := filepath.Join(outputDir, strings.TrimSuffix(file.Name, outputExtEnc))

		// If the file is a directory, create it
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(outputPath, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create directory: %v", err)
			}
			continue
		}

		// If the file is not a directory, ensure its parent directory exists
		if err := os.MkdirAll(filepath.Dir(outputPath), os.ModePerm); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}

		// Open the file in the zip archive for reading
		zipFileReader, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in zip: %v", err)
		}
		defer zipFileReader.Close()

		// Read the encrypted content from the zip file
		encryptedData, err := ioutil.ReadAll(zipFileReader)
		if err != nil {
			return fmt.Errorf("failed to read encrypted file from zip: %v", err)
		}

		// Decrypt the file and write it to the output path
		err = decryptBytesToFile(encryptedData, outputPath, key)
		if err != nil {
			return fmt.Errorf("failed to decrypt file: %v", err)
		}
	}

	return nil
}

// Decrypt bytes and write the result to a file
func decryptBytesToFile(encryptedData []byte, outputPath string, key []byte) error {
	if len(encryptedData) < saltSize+ivSize {
		return fmt.Errorf("invalid encrypted data length")
	}

	salt := encryptedData[:saltSize]
	iv := encryptedData[saltSize : saltSize+ivSize]
	ciphertext := encryptedData[saltSize+ivSize:]

	derivedKey := deriveKey(key, salt)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM cipher: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	err = ioutil.WriteFile(outputPath, plaintext, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to write decrypted file: %v", err)
	}

	return nil
}

func isZipFile(inputPath string) (bool, error) {
	fileInfo, err := os.Stat(inputPath)
	if err != nil {
		return false, fmt.Errorf("error checking file: %w", err)
	}
	if fileInfo.IsDir() {
		return false, nil
	}

	file, err := os.Open(inputPath)
	if err != nil {
		return false, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	zipSignature := []byte{0x50, 0x4B, 0x03, 0x04}
	fileHeader := make([]byte, 4)

	if _, err := file.Read(fileHeader); err != nil {
		return false, fmt.Errorf("error reading file header: %w", err)
	}

	if string(fileHeader) == string(zipSignature) {
		return true, nil
	}

	return false, nil
}

func cleanInputPath(inputPath string) string {
	if runtime.GOOS == "windows" {
		// For Windows, trim all trailing backslashes
		return strings.TrimRight(inputPath, "\\")
	} else {
		// For Unix-like systems, trim all trailing forward slashes
		return strings.TrimRight(inputPath, "/")
	}
}

func main() {
	command := flag.String("cmd", "encrypt", "encrypt or decrypt")
	keyPath := flag.String("keypath", "", "path to key file")
	inputPath := flag.String("input", "", "file, folder, or zip file to encrypt/decrypt")
	outputDir := flag.String("output", "", "output file, folder, or zip file")
	useZip := flag.Bool("usezip", false, "store encrypted files in a zip container")
	showHelp := flag.Bool("help", false, "display help message")

	flag.Parse()

	if *showHelp || len(os.Args) == 1 {
		usage()
		return
	}

	if *inputPath == "" {
		fmt.Println("Error: input path is required.")
		flag.Usage()
		os.Exit(1)
	}

	// Clean input path to remove any trailing slashes
	cleanInputPath := cleanInputPath(*inputPath)

	isEncrypt := (*command == "encrypt")

	// Get the encryption/decryption key
	key, err := getKey(*keyPath, isEncrypt)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	// Set default output directory or file if not provided
	if *outputDir == "" {
		if isEncrypt {
			fileInfo, err := os.Stat(cleanInputPath)
			if err != nil {
				fmt.Printf("Error: Failed to access input path - %s\n", err)
				os.Exit(1)
			}

			if fileInfo.IsDir() {
				*outputDir = cleanInputPath + outputExtEnc
			} else {
				// For files, explicitly append .enc to the output file path
				*outputDir = cleanInputPath + outputExtEnc
			}
		} else {
			*outputDir = strings.TrimSuffix(cleanInputPath, outputExtEnc) + outputExtDec
		}
	}

	// Check if the input path is a file or directory
	fileInfo, err := os.Stat(cleanInputPath)
	if err != nil {
		fmt.Printf("Error: Failed to access input path - %s\n", err)
		os.Exit(1)
	}

	if fileInfo.IsDir() {
		// Handle encryption or decryption for directories
		if isEncrypt {
			if *useZip {
				fmt.Printf("Encrypting folder '%s' into a zip container...\n", cleanInputPath)
				err = processFilesToZip(cleanInputPath, *outputDir+".zip", key)
			} else {
				fmt.Printf("Encrypting folder '%s'...\n", cleanInputPath)
				err = processFiles(cleanInputPath, *outputDir, key, true)
			}
		} else {
			fmt.Printf("Decrypting folder '%s'...\n", cleanInputPath)
			err = processFiles(cleanInputPath, *outputDir, key, false)
		}
	} else {
		// Handle single file encryption/decryption
		if isEncrypt {
			fmt.Printf("Encrypting file '%s'...\n", cleanInputPath)
			err = encryptFile(cleanInputPath, *outputDir, key)
		} else {
			// Check if the input file is a zip file for decryption
			var isZip bool
			isZip, err = isZipFile(cleanInputPath)
			if err != nil {
				fmt.Printf("Error detecting ZIP file: %s\n", err)
				os.Exit(1)
			}

			if isZip {
				fmt.Printf("Decrypting zip file '%s'...\n", cleanInputPath)
				err = decryptFilesFromZip(cleanInputPath, *outputDir, key)
			} else {
				fmt.Printf("Decrypting file '%s'...\n", cleanInputPath)
				if strings.HasSuffix(cleanInputPath, outputExtEnc) {
					*outputDir = strings.TrimSuffix(cleanInputPath, outputExtEnc)
				}
				err = decryptFile(cleanInputPath, *outputDir, key)
			}
		}
	}

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Process completed successfully. Output stored in: '%s'\n", *outputDir)
}
