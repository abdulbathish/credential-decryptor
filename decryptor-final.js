const crypto = require('crypto');
const fs = require('fs');
const forge = require('node-forge');

// Default configuration
const DEFAULT_CONFIG = {
  p12Path: './partner.p12',
  p12Password: 'mosip123',
  inputFilePath: './encrypted-data.txt',
  outputFilePath: './decrypted-output.txt',
  verbose: false
};

/**
 * Credential Partner decryption
 * Decrypts MOSIP-encrypted data using a P12 keystore
 */
class MOSIPDecryptor {
  constructor(options = {}) {
    this.p12Path = options.p12Path || DEFAULT_CONFIG.p12Path;
    this.p12Password = options.p12Password || DEFAULT_CONFIG.p12Password;
    this.inputFilePath = options.inputFilePath || DEFAULT_CONFIG.inputFilePath;
    this.outputFilePath = options.outputFilePath || DEFAULT_CONFIG.outputFilePath;
    this.verbose = options.verbose !== undefined ? options.verbose : DEFAULT_CONFIG.verbose;
    
    this.VERSION_RSA_2048 = Buffer.from('VER_R2');
    this.KEY_SPLITTER = '#KEY_SPLITTER#';
    this.THUMBPRINT_LENGTH = 32;
  }

  /**
   * Process full decryption workflow
   */
  decrypt() {
    try {
      const privateKey = this.extractPrivateKeyFromP12();
      const encryptedData = this.readAndDecodeData();
      
      const keySplitterIndex = this.getSplitterIndex(encryptedData);
      if (keySplitterIndex === -1) {
        throw new Error('KEY_SPLITTER not found in data');
      }
      
      const splitterLength = Buffer.from(this.KEY_SPLITTER).length;
      const encryptedKeyPart = encryptedData.slice(0, keySplitterIndex);
      const encryptedContentPart = encryptedData.slice(keySplitterIndex + splitterLength);
      
      const encryptedSessionKey = encryptedKeyPart.slice(
        this.VERSION_RSA_2048.length + this.THUMBPRINT_LENGTH
      );
      const sessionKey = this.decryptSessionKey(privateKey, encryptedSessionKey);
      
      const AAD_SIZE = 32;
      const NONCE_LENGTH = 12;
      const aad = encryptedContentPart.slice(0, AAD_SIZE);
      const nonce = aad.slice(0, NONCE_LENGTH);
      const ciphertext = encryptedContentPart.slice(AAD_SIZE);
      
      const decryptedData = this.decryptContent(sessionKey, ciphertext, nonce, aad);
      
      if (this.outputFilePath) {
        fs.writeFileSync(this.outputFilePath, decryptedData);
        if (this.verbose) {
          console.log(`Decrypted data saved to ${this.outputFilePath}`);
        }
      }
      
      return decryptedData;
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Extract private key from P12 keystore
   */
  extractPrivateKeyFromP12() {
    if (!fs.existsSync(this.p12Path)) {
      throw new Error(`P12 keystore file not found at ${this.p12Path}`);
    }
    
    try {
      if (this.verbose) {
        console.log(`Reading P12 file: ${this.p12Path}`);
      }
      
      const p12Buffer = fs.readFileSync(this.p12Path);
      const p12Der = forge.util.createBuffer(p12Buffer);
      const p12Asn1 = forge.asn1.fromDer(p12Der);
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, this.p12Password);
      
      const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
      const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
      
      if (!keyBag || !keyBag.key) {
        throw new Error('No private key found in P12 file');
      }
      
      const privatePem = forge.pki.privateKeyToPem(keyBag.key);
      const privateKey = crypto.createPrivateKey(privatePem);
      
      if (this.verbose) {
        console.log(`Private key extracted successfully`);
      }
      
      return privateKey;
    } catch (error) {
      throw new Error(`Failed to extract private key from P12: ${error.message}`);
    }
  }

  /**
   * Read and decode encrypted data
   */
  readAndDecodeData() {
    if (!fs.existsSync(this.inputFilePath)) {
      throw new Error(`Input file not found at ${this.inputFilePath}`);
    }
    
    const encryptedBase64 = fs.readFileSync(this.inputFilePath, 'utf8').trim();
    
    if (this.verbose) {
      console.log(`Read ${encryptedBase64.length} characters from input file`);
    }
    
    try {
      return Buffer.from(encryptedBase64, 'base64');
    } catch (standardError) {
      const standardBase64 = encryptedBase64.replace(/-/g, '+').replace(/_/g, '/');
      return Buffer.from(standardBase64, 'base64');
    }
  }

  /**
   * Find KEY_SPLITTER in data
   */
  getSplitterIndex(data) {
    const keySplitterBytes = Buffer.from(this.KEY_SPLITTER);
    const keySplitterFirstByte = keySplitterBytes[0];
    let keyDemiliterIndex = 0;
    
    for (let i = 0; i < data.length; i++) {
      if (data[i] === keySplitterFirstByte) {
        // Check if the full splitter matches
        if (i + keySplitterBytes.length <= data.length) {
          const potentialSplitter = data.slice(i, i + keySplitterBytes.length);
          if (Buffer.compare(potentialSplitter, keySplitterBytes) === 0) {
            return i;
          }
        }
      }
      keyDemiliterIndex++;
    }
    
    return -1;
  }

  /**
   * Decrypt session key using RSA
   */
  decryptSessionKey(privateKey, encryptedSessionKey) {
    try {
      return crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, encryptedSessionKey);
    } catch (oaepError) {
      return crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, encryptedSessionKey);
    }
  }

  /**
   * Decrypt content using AES-GCM
   */
  decryptContent(key, ciphertext, nonce, aad) {
    const AUTH_TAG_SIZE = 16;
    
    const authTag = ciphertext.slice(ciphertext.length - AUTH_TAG_SIZE);
    const actualCiphertext = ciphertext.slice(0, ciphertext.length - AUTH_TAG_SIZE);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(actualCiphertext),
      decipher.final()
    ]);
    
    return decrypted.toString('utf8');
  }
}

/**
 * Command line interface
 */
function main() {
  const args = process.argv.slice(2);
  
  // Check for node-forge
  try {
    require.resolve('node-forge');
  } catch (e) {
    console.error('\nError: node-forge package not installed');
    console.error('\nPlease install it using:');
    console.error('npm install node-forge');
    return;
  }
  
  // Display help if requested
  if (args.includes('-h') || args.includes('--help')) {
    console.log(`
MOSIP P12 Decryptor

Usage:
  node decryptor.js [options]

Options:
  -i, --input <file>     Input file with encrypted data (default: encrypted-data.txt)
  -o, --output <file>    Output file for decrypted data (default: decrypted-output.txt)
  -p, --p12 <file>       P12 keystore file (default: partner.p12)
  -w, --password <pass>  P12 keystore password (default: mosip123)
  -v, --verbose          Show verbose output
  -h, --help             Show this help message
    `);
    return;
  }

  // Parse arguments
  const options = { ...DEFAULT_CONFIG };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '-i' || arg === '--input') {
      options.inputFilePath = args[++i];
    } else if (arg === '-o' || arg === '--output') {
      options.outputFilePath = args[++i];
    } else if (arg === '-p' || arg === '--p12') {
      options.p12Path = args[++i];
    } else if (arg === '-w' || arg === '--password') {
      options.p12Password = args[++i];
    } else if (arg === '-v' || arg === '--verbose') {
      options.verbose = true;
    }
  }

  // Run decryption
  console.log('MOSIP P12 Decryptor');
  console.log('=================');
  
  try {
    if (options.verbose) {
      console.log(`P12 file: ${options.p12Path}`);
      console.log(`Input: ${options.inputFilePath}`);
      console.log(`Output: ${options.outputFilePath}`);
    }
    
    const decryptor = new MOSIPDecryptor(options);
    const decryptedData = decryptor.decrypt();
    
    console.log('\nDecryption successful!');
    
    if (options.verbose) {
      const previewLength = Math.min(200, decryptedData.length);
      console.log(`\nPreview (first ${previewLength} chars):`);
      console.log('-'.repeat(50));
      console.log(decryptedData.substring(0, previewLength) + (decryptedData.length > previewLength ? '...' : ''));
      console.log('-'.repeat(50));
    }
    
    console.log(`\nDecrypted data saved to: ${options.outputFilePath}`);
  } catch (error) {
    console.error(`\nError: ${error.message}`);
  }
}

// Run if executed directly
if (require.main === module) {
  main();
}

module.exports = MOSIPDecryptor;