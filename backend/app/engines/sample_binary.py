"""
Sample Binary Generator and Test Target for Q-Guardian-v2
Generates a realistic test binary artifact containing ML-KEM-768 NTT constants,
AES S-box tables, and legacy MD5 constants for demo/testing.
"""

import os
import struct
from app.engines.binary_scanner import (
    ML_KEM_NTT_ZETAS_16,
    AES_SBOX_16,
    MD5_INIT_CONSTANTS
)

def generate_sample_crypto_binary(output_path: str = "sample_pqc_target.bin") -> str:
    """Creates a mock compiled ELF/PE binary image with real crypto constants."""
    # Fake ELF Header (64-bit x86-64)
    elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    elf_header += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 64, 3, 2)
    
    # Section 1: Fake .text code
    text_segment = b"\x90\x90\x90\x90\x48\x31\xc0\xc3" * 16
    text_segment += b"EVP_KEM_fetch\x00OQS_KEM_new\x00ML-KEM-768\x00"
    
    # Section 2: .rodata containing ML-KEM NTT constants, AES S-box, MD5 constants
    rodata_segment = b"\x00" * 32
    rodata_segment += b"--- BEGIN ML-KEM NTT TABLE ---"
    rodata_segment += ML_KEM_NTT_ZETAS_16
    rodata_segment += b"--- END NTT TABLE ---"
    rodata_segment += b"\x00" * 16
    rodata_segment += AES_SBOX_16
    rodata_segment += b"\x00" * 16
    rodata_segment += MD5_INIT_CONSTANTS
    rodata_segment += b"\x00" * 32

    full_binary = elf_header + text_segment + rodata_segment
    
    with open(output_path, "wb") as f:
        f.write(full_binary)
        
    return output_path

if __name__ == "__main__":
    path = generate_sample_crypto_binary()
    print(f"Generated sample binary: {path} ({os.path.getsize(path)} bytes)")
