import os
import base64
import logging
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Set up logging for detailed terminal output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureDataTool:
    """
    Core class for high-level data encryption and integrity operations.
    Focuses on AES-256 GCM encryption and SHA-256 hashing.
    """
    def __init__(self):
        # Use a consistent, high-security backend
        self.backend = default_backend()
        logging.info(Fore.GREEN + "SecureDataTool initialized successfully. Cryptographic backend ready.")

    @staticmethod
    def generate_key(password: str, salt: bytes) -> bytes:
        """
        Generates a 32-byte (256-bit) cryptographic key using PBKDF2.
        This ensures the encryption key is derived securely from a user password.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # AES-256 key length
            salt=salt,
            iterations=480000, # High iteration count for security
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def generate_salt() -> bytes:
        """Generates a secure, random salt for key derivation."""
        return os.urandom(16)
    
    @staticmethod
    def generate_nonce() -> bytes:
        """Generates a secure, random Nonce (Initialization Vector) for GCM."""
        # AES GCM uses 96-bit (12-byte) nonce
        return os.urandom(12)

    def encrypt_data(self, data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypts data using AES-256 in Galois/Counter Mode (GCM).
        GCM provides both confidentiality and authentication (via a tag).
        """
        nonce = self.generate_nonce()
        
        # Cipher setup
        cipher = Cipher(
            algorithms.AES(key), 
            modes.GCM(nonce), 
            backend=self.backend
        )
        encryptor = cipher.encryptor()

        # Encryption and Tag generation
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag

        logging.info(Fore.YELLOW + f"Data encrypted. Ciphertext size: {len(ciphertext)} bytes. Authentication Tag generated.")
        return ciphertext, nonce, tag

    def decrypt_data(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypts data using AES-256 GCM and verifies the authentication tag.
        Raises an error if the data has been tampered with (integrity failure).
        """
        try:
            cipher = Cipher(
                algorithms.AES(key), 
                modes.GCM(nonce, tag), 
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decryption and tag verification
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            logging.info(Fore.GREEN + "Decryption successful. Data integrity verified (GCM Tag match).")
            return plaintext
        except Exception as e:
            logging.error(Fore.RED + Style.BRIGHT + f"Integrity Check FAILED. The data may have been tampered with or the key is incorrect. Error: {e}")
            raise PermissionError("Data integrity check failed.")

    def calculate_sha256(self, data: bytes) -> str:
        """
        Calculates a high-performance SHA-256 hexadecimal hash of the data.
        This provides a quick, secondary integrity check.
        """
        hasher = hashes.Hash(hashes.SHA256(), backend=self.backend)
        hasher.update(data)
        hex_digest = hasher.finalize().hex()
        logging.info(f"SHA-256 Digest calculated: {hex_digest[:16]}... (Full length: {len(hex_digest)} chars)")
        return hex_digest

# --- Secondary Utility Class for Logging/Integrity Tracking ---

class IntegrityLogger:
    """
    Utility to simulate secure logging and track data state changes, 
    aligning with professional development standards for auditing.
    """
    def __init__(self, log_file_path="integrity_log.txt"):
        self.log_file_path = log_file_path
        self._initialize_log()
        logging.info(Fore.CYAN + f"IntegrityLogger initialized. Logs saved to: {self.log_file_path}")

    def _initialize_log(self):
        """Ensure the log file exists and is writable."""
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, 'w') as f:
                f.write("--- Data Integrity Log Initialization ---\n")
                f.write(f"Timestamp: {logging.Formatter().formatTime(os.stat(self.log_file_path).st_mtime)}\n")

    def log_operation(self, operation_type: str, data_hash: str, status: str = "SUCCESS"):
        """Logs a data operation with the calculated hash and status."""
        log_entry = f"[{logging.Formatter().formatTime(None)}] Operation: {operation_type:<15} | Hash: {data_hash} | Status: {status}\n"
        
        with open(self.log_file_path, 'a') as f:
            f.write(log_entry)
        
        logging.info(Fore.CYAN + f"Log entry recorded: {operation_type} - {status}")