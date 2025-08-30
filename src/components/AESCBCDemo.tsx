import React, { useState } from 'react';
import { AlertCircle, Key, Lock, Copy, Info } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';

const AESCBCDemo = () => {
  const [input, setInput] = useState('Hello, this is a test message for AES-CBC encryption!');
  const [passphrase, setPassphrase] = useState('mySecretPassword');
  const [mode, setMode] = useState('encrypt');
  const [results, setResults] = useState<any>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);

  // Utility functions for AES-CBC implementation
  const stringToBytes = (str: string) => new TextEncoder().encode(str);
  const bytesToHex = (bytes: Uint8Array) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const hexToBytes = (hex: string) => new Uint8Array(hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []);
  const bytesToString = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

  // PKCS#7 padding
  const addPadding = (data: Uint8Array, blockSize = 16) => {
    const paddingLength = blockSize - (data.length % blockSize);
    const padding = new Uint8Array(paddingLength).fill(paddingLength);
    const padded = new Uint8Array(data.length + paddingLength);
    padded.set(data);
    padded.set(padding, data.length);
    return padded;
  };

  const removePadding = (data: Uint8Array) => {
    const paddingLength = data[data.length - 1];
    return data.slice(0, data.length - paddingLength);
  };

  // XOR operation for CBC
  const xorBytes = (a: Uint8Array, b: Uint8Array) => {
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i];
    }
    return result;
  };

  // Simple key derivation (educational - not cryptographically secure)
  const deriveKey = async (passphrase: string) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(passphrase);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer).slice(0, 16); // AES-128 key
  };

  // Generate random IV
  const generateIV = () => {
    return crypto.getRandomValues(new Uint8Array(16));
  };

  // Simplified AES encryption simulation for educational demo
  const simulateAESEncrypt = async (block: Uint8Array, key: Uint8Array) => {
    // This is a simplified simulation for educational purposes
    // In reality, this would be proper AES encryption
    const result = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      result[i] = (block[i] + key[i % key.length]) % 256;
    }
    return result;
  };

  const simulateAESDecrypt = async (block: Uint8Array, key: Uint8Array) => {
    const result = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      result[i] = (block[i] - key[i % key.length] + 256) % 256;
    }
    return result;
  };

  // Simplified AES-CBC encryption for educational purposes
  const encryptAESCBC = async (plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array) => {
    const blocks: Uint8Array[] = [];
    const encryptedBlocks: Uint8Array[] = [];
    let previousBlock = iv;

    // Split into 16-byte blocks
    for (let i = 0; i < plaintext.length; i += 16) {
      blocks.push(plaintext.slice(i, i + 16));
    }

    for (let i = 0; i < blocks.length; i++) {
      const xorResult = xorBytes(blocks[i], previousBlock);
      const encrypted = await simulateAESEncrypt(xorResult, key);
      encryptedBlocks.push(encrypted);
      previousBlock = encrypted;
    }

    return { blocks, encryptedBlocks };
  };

  const processAES = async () => {
    setIsProcessing(true);
    setCurrentStep(0);
    
    try {
      if (mode === 'encrypt') {
        // Step 1: Key derivation
        setCurrentStep(1);
        await new Promise(resolve => setTimeout(resolve, 500));
        const derivedKey = await deriveKey(passphrase);
        
        // Step 2: Padding
        setCurrentStep(2);
        await new Promise(resolve => setTimeout(resolve, 500));
        const plainBytes = stringToBytes(input);
        const paddedBytes = addPadding(plainBytes);
        
        // Step 3: IV generation
        setCurrentStep(3);
        await new Promise(resolve => setTimeout(resolve, 500));
        const iv = generateIV();
        
        // Step 4: Block encryption
        setCurrentStep(4);
        await new Promise(resolve => setTimeout(resolve, 500));
        const { blocks, encryptedBlocks } = await encryptAESCBC(paddedBytes, derivedKey, iv);
        
        // Combine IV + encrypted blocks for final result
        const finalCiphertext = new Uint8Array(iv.length + encryptedBlocks.reduce((acc, block) => acc + block.length, 0));
        finalCiphertext.set(iv, 0);
        let offset = iv.length;
        for (const block of encryptedBlocks) {
          finalCiphertext.set(block, offset);
          offset += block.length;
        }
        
        setResults({
          mode: 'encrypt',
          derivedKey: bytesToHex(derivedKey),
          iv: bytesToHex(iv),
          paddedText: bytesToString(paddedBytes),
          plaintextBlocks: blocks.map(block => bytesToHex(block)),
          ciphertextBlocks: encryptedBlocks.map(block => bytesToHex(block)),
          finalResult: bytesToHex(finalCiphertext)
        });
      } else {
        // Decryption process
        try {
          const cipherBytes = hexToBytes(input);
          const derivedKey = await deriveKey(passphrase);
          const iv = cipherBytes.slice(0, 16);
          const encryptedData = cipherBytes.slice(16);
          
          const blocks = [];
          const decryptedBlocks = [];
          let previousBlock = iv;
          
          // Split encrypted data into blocks
          for (let i = 0; i < encryptedData.length; i += 16) {
            blocks.push(encryptedData.slice(i, i + 16));
          }
          
          // Decrypt each block
          for (let i = 0; i < blocks.length; i++) {
            const decrypted = await simulateAESDecrypt(blocks[i], derivedKey);
            const xorResult = xorBytes(decrypted, previousBlock);
            decryptedBlocks.push(xorResult);
            previousBlock = blocks[i];
          }
          
          // Combine and remove padding
          const combinedDecrypted = new Uint8Array(decryptedBlocks.reduce((acc, block) => acc + block.length, 0));
          let offset = 0;
          for (const block of decryptedBlocks) {
            combinedDecrypted.set(block, offset);
            offset += block.length;
          }
          
          const unpaddedData = removePadding(combinedDecrypted);
          const plaintext = bytesToString(unpaddedData);
          
          setResults({
            mode: 'decrypt',
            derivedKey: bytesToHex(derivedKey),
            iv: bytesToHex(iv),
            ciphertextBlocks: blocks.map(block => bytesToHex(block)),
            plaintextBlocks: decryptedBlocks.map(block => bytesToHex(block)),
            finalResult: plaintext
          });
        } catch (error) {
          alert('Invalid ciphertext format. Please enter valid hex string.');
        }
      }
    } catch (error) {
      console.error('Processing error:', error);
      alert('An error occurred during processing.');
    }
    
    setCurrentStep(5);
    setIsProcessing(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const StepIndicator = ({ step, title, active, completed }: { step: number; title: string; active: boolean; completed: boolean }) => (
    <div className={`flex items-center p-4 rounded-lg border-2 transition-all duration-300 ${
      active ? 'border-crypto-primary bg-crypto-primary/10 shadow-elegant' : 
      completed ? 'border-crypto-success bg-crypto-success/10' : 
      'border-border bg-card'
    }`}>
      <div className={`w-10 h-10 rounded-full flex items-center justify-center mr-4 font-semibold transition-all duration-300 ${
        active ? 'bg-crypto-primary text-primary-foreground scale-110' : 
        completed ? 'bg-crypto-success text-primary-foreground' : 
        'bg-muted text-muted-foreground'
      }`}>
        {step}
      </div>
      <span className={`font-medium transition-colors duration-300 ${
        active ? 'text-crypto-primary font-semibold' : 
        completed ? 'text-crypto-success' : 
        'text-muted-foreground'
      }`}>
        {title}
      </span>
    </div>
  );

  const BlockVisualization = ({ title, blocks, color }: { title: string; blocks: string[]; color: string }) => (
    <Card className="overflow-hidden shadow-card">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center text-lg">
          <div className={`w-3 h-3 rounded-full mr-3 ${color}`}></div>
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {blocks.map((block, index) => (
            <div key={index} className="bg-muted/50 p-3 rounded-lg font-mono text-xs border">
              <div className="text-muted-foreground mb-2 font-medium">Block {index + 1}:</div>
              <div className="text-foreground break-all leading-relaxed">{block}</div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="min-h-screen bg-gradient-surface">
      <div className="container mx-auto p-6 space-y-8">
        <Card className="shadow-elegant overflow-hidden">
          <CardHeader className="bg-gradient-primary text-primary-foreground">
            <div className="flex items-center space-x-4">
              <div className="p-3 bg-white/20 rounded-lg">
                <Lock size={32} />
              </div>
              <div>
                <CardTitle className="text-3xl font-bold">AES-CBC Educational Demo</CardTitle>
                <p className="text-primary-foreground/80 mt-1">Interactive cryptography learning tool</p>
              </div>
            </div>
          </CardHeader>
          
          <CardContent className="p-6 space-y-6">
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>
                <span className="font-medium">Educational Purpose Only:</span> This demo uses simplified AES implementation for learning. It visualizes the AES-CBC encryption process step-by-step, including key derivation, padding, IV generation, and block chaining.
              </AlertDescription>
            </Alert>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-2">
                <Label htmlFor="mode">Encryption Mode</Label>
                <Select value={mode} onValueChange={setMode}>
                  <SelectTrigger className="shadow-input">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="encrypt">Encrypt</SelectItem>
                    <SelectItem value="decrypt">Decrypt</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="passphrase" className="flex items-center">
                  <Key className="mr-2 h-4 w-4" />
                  Passphrase
                </Label>
                <Input
                  id="passphrase"
                  type="text"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter passphrase"
                  className="shadow-input"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="input">
                {mode === 'encrypt' ? 'Plaintext' : 'Ciphertext (Hex)'}
              </Label>
              <Textarea
                id="input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={mode === 'encrypt' ? 'Enter text to encrypt...' : 'Enter hex ciphertext to decrypt...'}
                className="min-h-32 shadow-input"
              />
            </div>

            <Button
              onClick={processAES}
              disabled={isProcessing || !input || !passphrase}
              className="w-full bg-gradient-primary hover:opacity-90 shadow-elegant transition-all duration-300"
              size="lg"
            >
              {isProcessing ? 'Processing...' : (mode === 'encrypt' ? 'Encrypt' : 'Decrypt')}
            </Button>
          </CardContent>
        </Card>

        {isProcessing && (
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle className="text-xl">Processing Steps</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <StepIndicator 
                step={1} 
                title="Key Derivation" 
                active={currentStep === 1} 
                completed={currentStep > 1} 
              />
              <StepIndicator 
                step={2} 
                title={mode === 'encrypt' ? "Text Padding" : "Block Extraction"} 
                active={currentStep === 2} 
                completed={currentStep > 2} 
              />
              <StepIndicator 
                step={3} 
                title="IV Processing" 
                active={currentStep === 3} 
                completed={currentStep > 3} 
              />
              <StepIndicator 
                step={4} 
                title={mode === 'encrypt' ? "Block Encryption" : "Block Decryption"} 
                active={currentStep === 4} 
                completed={currentStep > 4} 
              />
              <StepIndicator 
                step={5} 
                title="Complete" 
                active={currentStep === 5} 
                completed={currentStep > 5} 
              />
            </CardContent>
          </Card>
        )}

        {results && (
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle className="text-xl">Results</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="bg-gradient-card shadow-sm">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="font-medium text-crypto-primary">Derived Key (128-bit)</h4>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(results.derivedKey)}
                        className="hover:bg-crypto-primary/10"
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="font-mono text-xs break-all bg-muted/50 p-3 rounded border">
                      {results.derivedKey}
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-gradient-card shadow-sm">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="font-medium text-crypto-secondary">Initialization Vector (IV)</h4>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(results.iv)}
                        className="hover:bg-crypto-secondary/10"
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="font-mono text-xs break-all bg-muted/50 p-3 rounded border">
                      {results.iv}
                    </div>
                  </CardContent>
                </Card>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {results.mode === 'encrypt' ? (
                  <>
                    <BlockVisualization 
                      title="Plaintext Blocks" 
                      blocks={results.plaintextBlocks} 
                      color="bg-crypto-success"
                    />
                    <BlockVisualization 
                      title="Ciphertext Blocks" 
                      blocks={results.ciphertextBlocks} 
                      color="bg-crypto-error"
                    />
                  </>
                ) : (
                  <>
                    <BlockVisualization 
                      title="Ciphertext Blocks" 
                      blocks={results.ciphertextBlocks} 
                      color="bg-crypto-error"
                    />
                    <BlockVisualization 
                      title="Decrypted Blocks" 
                      blocks={results.plaintextBlocks} 
                      color="bg-crypto-success"
                    />
                  </>
                )}
              </div>

              <Card className="bg-gradient-primary/5 border-crypto-info shadow-sm">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="font-medium text-crypto-info">
                      {results.mode === 'encrypt' ? 'Final Ciphertext (with IV)' : 'Decrypted Plaintext'}
                    </h4>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyToClipboard(results.finalResult)}
                      className="hover:bg-crypto-info/10"
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className={`p-4 rounded-lg border bg-card ${
                    results.mode === 'encrypt' ? 'font-mono text-xs break-all' : 'text-sm'
                  }`}>
                    {results.finalResult}
                  </div>
                </CardContent>
              </Card>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default AESCBCDemo;