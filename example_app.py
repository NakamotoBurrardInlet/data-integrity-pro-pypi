import sys
import os
import time
from colorama import init, Fore, Style
# This import assumes the package 'data-integrity-pro' has been installed 
# via 'pip install data-integrity-pro'
# For demonstration, we simulate the import path:
try:
    from data_integrity_pro.integrity_pro import SecureDataTool, IntegrityLogger
except ImportError:
    # Fallback for running the example directly without full pip install
    sys.path.append(os.path.join(os.path.dirname(__file__), 'data_integrity_pro'))
    from integrity_pro import SecureDataTool, IntegrityLogger


# --- Main Interactive Application ---

def main_application():
    """
    High-level application demonstrating data encryption, decryption, and integrity logging.
    """
    init(autoreset=True)
    print(Fore.MAGENTA + Style.BRIGHT + "\n--- Data Integrity Pro: Secure Encryption Demonstrator ---")
    print(Fore.MAGENTA + "A high-performance system designed for secure data handling.")
    
    # 1. Initialization
    security_tool = SecureDataTool()
    logger = IntegrityLogger(log_file_path="security_audit.log")

    # 2. Key and Data Setup
    user_password = input(Fore.YELLOW + "\n[INPUT] Enter a strong master password (e.g., 'SecurePhrase123'): ")
    
    # Generate a unique salt for this application instance and key derivation
    salt = SecureDataTool.generate_salt()
    encryption_key = security_tool.generate_key(user_password, salt)
    
    # Data to be protected
    original_data = (
        "This is sensitive configuration data for the terminal application. "
        "It must be protected with AES-256 GCM to ensure both confidentiality and integrity."
    ).encode('utf-8')
    
    print(Fore.CYAN + f"\n[INFO] Original Data Size: {len(original_data)} bytes.")

    # 3. Pre-Encryption Integrity Check (Hashing)
    original_hash = security_tool.calculate_sha256(original_data)
    logger.log_operation("PRE_ENCRYPT_HASH", original_hash)
    
    # 4. Encryption Phase
    print(Fore.YELLOW + "\n[PHASE] Beginning High-Performance Encryption...")
    try:
        ciphertext, nonce, tag = security_tool.encrypt_data(original_data, encryption_key)
        
        # Log the encryption event
        encrypted_hash = security_tool.calculate_sha256(ciphertext)
        logger.log_operation("ENCRYPT_SUCCESS", encrypted_hash)

        # Demonstrate serialized output (saving to storage)
        serialized_data = base64.b64encode(salt + nonce + tag + ciphertext)
        print(Fore.GREEN + f"[RESULT] Data successfully encrypted and serialized for storage.")
        print(Fore.GREEN + f"[SERIAL] Length of serialized data: {len(serialized_data)} bytes.")
        
    except Exception as e:
        print(Fore.RED + f"[ERROR] Encryption failed: {e}")
        return

    # 5. Decryption and Integrity Verification Phase
    print(Fore.YELLOW + "\n" + "="*50)
    print(Fore.YELLOW + "[PHASE] Beginning Decryption and Integrity Check...")
    
    # Simulate loading data from storage and de-serializing
    # Split the base64 data back into its components: salt (16), nonce (12), tag (16), ciphertext (remaining)
    raw_data = base64.b64decode(serialized_data)
    
    # Re-extract components
    simulated_salt = raw_data[0:16]
    simulated_nonce = raw_data[16:28]
    simulated_tag = raw_data[28:44]
    simulated_ciphertext = raw_data[44:]
    
    # Re-derive the key using the stored salt and master password
    decryption_key = security_tool.generate_key(user_password, simulated_salt)
    
    # Decrypt and verify
    try:
        decrypted_data = security_tool.decrypt_data(
            simulated_ciphertext, 
            decryption_key, 
            simulated_nonce, 
            simulated_tag
        )
        
        # Post-Decryption Integrity Check
        final_hash = security_tool.calculate_sha256(decrypted_data)
        logger.log_operation("DECRYPT_SUCCESS", final_hash)
        
        if final_hash == original_hash:
            print(Fore.GREEN + Style.BRIGHT + "\n[VERIFIED] Original Hash and Final Hash MATCH! Data integrity is 100%.")
        else:
            print(Fore.RED + Style.BRIGHT + "\n[FAILURE] Hash MISMATCH! Data was compromised.")
            
        print(Fore.GREEN + "\n[OUTPUT] Decrypted Data:")
        print(Fore.WHITE + Style.DIM + decrypted_data.decode('utf-8'))

    except PermissionError:
        logger.log_operation("DECRYPT_FAILURE", "N/A", status="FAILED")
        print(Fore.RED + Style.BRIGHT + "\n[CRITICAL FAILURE] Decryption failed due to data tampering or incorrect password.")
    except Exception as e:
        print(Fore.RED + f"[ERROR] An unexpected error occurred during decryption: {e}")

# Call the application main loop
if __name__ == "__main__":
    main_application()