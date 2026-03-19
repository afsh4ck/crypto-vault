import { useState, useCallback, useEffect, useMemo } from 'react';
import { ShieldStar, Lock, LockOpen, UploadSimple, DownloadSimple, Lightning, Eye, EyeSlash, X, CaretDown, Sun, Moon } from '@phosphor-icons/react';

type Mode = 'encrypt' | 'decrypt';
type Algorithm = 'AES-GCM-256' | 'AES-GCM-128';
type Theme = 'dark' | 'light';

const ALGORITHMS: { value: Algorithm; label: string; description: string }[] = [
  { value: 'AES-GCM-256', label: 'AES-256-GCM', description: 'Recommended - Authenticated encryption' },
  { value: 'AES-GCM-128', label: 'AES-128-GCM', description: 'Fast - Authenticated encryption' },
];

function App() {
  const [mode, setMode] = useState<Mode>('encrypt');
  const [theme, setTheme] = useState<Theme>('dark');
  const [algorithm, setAlgorithm] = useState<Algorithm>('AES-GCM-256');
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [status, setStatus] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [showAlgoDropdown, setShowAlgoDropdown] = useState(false);
  const [animatedTitle, setAnimatedTitle] = useState('');
  const [titleAnimated, setTitleAnimated] = useState(false);

  // Pre-generate matrix rain data once so re-renders don't scramble it
  const matrixColumns = useMemo(() =>
    Array.from({ length: 80 }, (_, i) => ({
      left: `${(i / 80) * 100}%`,
      delay: `${Math.random() * 5}s`,
      duration: `${8 + Math.random() * 10}s`,
      chars: Array.from({ length: 40 }, () =>
        String.fromCharCode(0x30A0 + Math.floor(Math.random() * 96))
      ),
    })),
  []);

  useEffect(() => {
    const savedTheme = localStorage.getItem('crypto-vault-theme') as Theme;
    if (savedTheme) setTheme(savedTheme);
  }, []);

  // Title decrypt-style animation on first load
  useEffect(() => {
    if (titleAnimated) return;
    const final = 'Crypto Vault';
    let mounted = true;

    const randomChar = () => {
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+<>?";
      return chars[Math.floor(Math.random() * chars.length)];
    };

    const sleep = (ms: number) => new Promise(res => setTimeout(res, ms));

    (async () => {
      const arr = Array.from(final).map(() => ' ');
      for (let i = 0; i < final.length; i++) {
        if (!mounted) return;
        if (final[i] === ' ') {
          arr[i] = ' ';
          setAnimatedTitle(arr.join(''));
          await sleep(30);
          continue;
        }
        const rounds = 6 + Math.floor(Math.random() * 6);
        for (let r = 0; r < rounds; r++) {
          arr[i] = randomChar();
          setAnimatedTitle(arr.join(''));
          await sleep(25 + Math.random() * 40);
        }
        arr[i] = final[i];
        setAnimatedTitle(arr.join(''));
        await sleep(40);
      }
      setTitleAnimated(true);
    })();

    return () => { mounted = false; };
  }, [titleAnimated]);

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    localStorage.setItem('crypto-vault-theme', newTheme);
  };

  const getKeyLength = (algo: string): number => {
    return algo.includes('128') ? 128 : 256;
  };

  // PBKDF2 iterations: 600,000 per OWASP 2024+ recommendation
  // Legacy files (format v1) used 100,000 — handled via iterationCount param
  const PBKDF2_ITERATIONS = 600_000;
  const PBKDF2_ITERATIONS_LEGACY = 100_000;

  const deriveKey = async (
    password: string,
    salt: BufferSource,
    algo: string,
    iterations: number = PBKDF2_ITERATIONS,
  ): Promise<CryptoKey> => {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: getKeyLength(algo) },
      false,
      ['encrypt', 'decrypt']
    );
  };

  // New encrypted file format (versioned):
  // [4 bytes magic 'CVLT'][1 byte version][1 byte algoId][16 bytes salt][1 byte ivLen][iv][4 bytes metadataLen][metadata UTF-8][ciphertext]
  // v2: PBKDF2 600k iterations, AES-GCM only
  const encryptFile = async (fileData: ArrayBuffer, password: string, algo: Algorithm): Promise<ArrayBuffer> => {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12)); // GCM
    const key = await deriveKey(password, salt, algo); // uses 600k iterations

    // metadata (not secret) but included as AAD for AES-GCM so it's authenticated
    const metadata = {
      originalName: file?.name || 'unknown',
      mimeType: file?.type || 'application/octet-stream',
      size: file?.size || fileData.byteLength,
      timestamp: Date.now(),
    };
    const metadataJson = JSON.stringify(metadata);
    const metadataBytes = encoder.encode(metadataJson);

    const algoParams: any = { name: 'AES-GCM', iv, additionalData: metadataBytes };

    const encrypted = await crypto.subtle.encrypt(algoParams, key, fileData);

    const algoId = ALGORITHMS.findIndex(a => a.value === algo);

    // build header
    const magic = new TextEncoder().encode('CVLT');
    const version = new Uint8Array([2]); // v2: 600k PBKDF2 iterations
    const algoIdArr = new Uint8Array([algoId]);
    const ivLen = new Uint8Array([iv.length]);
    const metadataLenBuf = new Uint8Array(4);
    const metaLen = metadataBytes.length;
    // big-endian uint32
    metadataLenBuf[0] = (metaLen >>> 24) & 0xff;
    metadataLenBuf[1] = (metaLen >>> 16) & 0xff;
    metadataLenBuf[2] = (metaLen >>> 8) & 0xff;
    metadataLenBuf[3] = (metaLen) & 0xff;

    const encryptedBytes = new Uint8Array(encrypted);

    const result = new Uint8Array(
      magic.length + version.length + algoIdArr.length + salt.length + ivLen.length + iv.length + metadataLenBuf.length + metaLen + encryptedBytes.length
    );

    let offset = 0;
    result.set(magic, offset); offset += magic.length;
    result.set(version, offset); offset += version.length;
    result.set(algoIdArr, offset); offset += algoIdArr.length;
    result.set(salt, offset); offset += salt.length;
    result.set(ivLen, offset); offset += ivLen.length;
    result.set(iv, offset); offset += iv.length;
    result.set(metadataLenBuf, offset); offset += metadataLenBuf.length;
    result.set(metadataBytes, offset); offset += metaLen;
    result.set(encryptedBytes, offset);

    return result.buffer;
  };

  // decryptFile supports both old (legacy) and new versioned format
  const decryptFile = async (encryptedData: ArrayBuffer, password: string): Promise<{ data: ArrayBuffer; metadata?: any }> => {
    const data = new Uint8Array(encryptedData);
    const decoder = new TextDecoder();

    // check magic for new format (CVLT)
    if (data.length >= 4 && decoder.decode(data.slice(0,4)) === 'CVLT') {
      let offset = 4;
      const version = data[offset]; offset += 1;
      // v1 = 100k PBKDF2 iterations, v2+ = 600k
      const iterations = version >= 2 ? PBKDF2_ITERATIONS : PBKDF2_ITERATIONS_LEGACY;
      const algoId = data[offset]; offset += 1;
      const algo = ALGORITHMS[algoId]?.value || 'AES-GCM-256';
      const salt = data.slice(offset, offset + 16); offset += 16;
      const ivLen = data[offset]; offset += 1;
      const iv = data.slice(offset, offset + ivLen); offset += ivLen;
      const metaLen = (data[offset] << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | (data[offset+3]);
      offset += 4;
      const metadataBytes = data.slice(offset, offset + metaLen); offset += metaLen;
      const metadataJson = decoder.decode(metadataBytes);
      let metadata = null;
      try { metadata = JSON.parse(metadataJson); } catch { metadata = null; }

      const ciphertext = data.slice(offset);

      const key = await deriveKey(password, salt, algo as Algorithm, iterations);

      const algoParams: any = { name: 'AES-GCM', iv, additionalData: metadataBytes };

      const plain = await crypto.subtle.decrypt(algoParams, key, ciphertext);
      return { data: plain, metadata };
    }

    // legacy format (pre-CVLT header) — backwards compatibility
    const algoId = data[0];
    // AES-CBC (was index 2) is now rejected — Padding Oracle attack surface
    if (algoId === 2) {
      throw new Error(
        'AES-CBC files are no longer supported. CBC is vulnerable to Padding Oracle attacks. ' +
        'Please re-encrypt the file using the current version of Crypto Vault (AES-GCM).'
      );
    }

    const algo = ALGORITHMS[algoId]?.value || 'AES-GCM-256';
    const salt = data.slice(1, 17);
    const iv = data.slice(17, 17 + 12); // GCM iv = 12 bytes
    const ciphertext = data.slice(17 + 12);

    // Legacy files used 100k iterations
    const key = await deriveKey(password, salt, algo, PBKDF2_ITERATIONS_LEGACY);

    const algoParams = { name: 'AES-GCM', iv };
    const plain = await crypto.subtle.decrypt(algoParams, key, ciphertext);
    return { data: plain };
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
      setStatus({ type: 'info', message: `> FILE_LOADED: ${droppedFile.name}` });
    }
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
      setStatus({ type: 'info', message: `> FILE_LOADED: ${selectedFile.name}` });
    }
  };

  const clearFile = () => {
    setFile(null);
    setStatus(null);
  };

  const processFile = async () => {
    if (!file || !password) {
      setStatus({ type: 'error', message: '> ERROR: File and password required' });
      return;
    }

    setProcessing(true);
    setStatus({ type: 'info', message: `> INITIATING_${mode.toUpperCase()}ION...` });

    try {
      const fileData = await file.arrayBuffer();
      let processedData: ArrayBuffer;
      let outputName: string;

      if (mode === 'encrypt') {
        processedData = await encryptFile(fileData, password, algorithm);
        outputName = `${file.name}.encrypted`;
        setStatus({ type: 'success', message: `> ENCRYPTION_COMPLETE: File secured with ${ALGORITHMS.find(a => a.value === algorithm)?.label}` });
      } else {
        const result = await decryptFile(fileData, password);
        processedData = result.data;
        outputName = result.metadata?.originalName || file.name.replace(/\.encrypted$/, '') || 'decrypted_file';
        setStatus({ type: 'success', message: '> DECRYPTION_COMPLETE: File restored successfully' });
      }

      const blob = new Blob([processedData]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = outputName;
      a.click();
      URL.revokeObjectURL(url);

    } catch (err: any) {
      const cbcRejected = err?.message?.includes('AES-CBC');
      setStatus({
        type: 'error',
        message: cbcRejected
          ? '> REJECTED: This file was encrypted with AES-CBC (deprecated). Re-encrypt it with AES-GCM using a previous version first.'
          : mode === 'decrypt'
            ? '> DECRYPTION_FAILED: Invalid password or corrupted file'
            : '> ENCRYPTION_FAILED: Process error occurred'
      });
    } finally {
      setProcessing(false);
    }
  };

  const isDark = theme === 'dark';

  return (
    <div className={`min-h-screen font-sans transition-colors duration-300 ${
      isDark
        ? 'bg-gradient-to-br from-[#040408] via-[#071f0a] to-[#0a0a0f] text-[#17FF35]'
        : 'bg-gradient-to-br from-emerald-50 to-emerald-200 text-gray-800'
    }`}>
      {/* Matrix rain effect background */}
      <div className={`fixed inset-0 overflow-hidden pointer-events-none ${
        isDark ? 'opacity-20' : 'opacity-[0.15]'
      }`}>
        {matrixColumns.map((col, i) => (
          <div
            key={i}
            className={`absolute text-xs animate-matrix-rain ${
              isDark ? 'text-[#17FF35]' : 'text-green-800'
            }`}
            style={{
              left: col.left,
              animationDelay: col.delay,
              animationDuration: col.duration,
            }}
          >
            {col.chars.map((char, j) => (
              <div key={j} className="opacity-70">
                {char}
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* Scanlines - only in dark mode */}
  {isDark && <div className="fixed inset-0 pointer-events-none bg-scanlines opacity-[0.06]" />}

      {/* Glow effect */}
      <div className={`fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full blur-3xl pointer-events-none ${
        isDark ? 'bg-[#17FF35]/10' : 'bg-emerald-500/20'
      }`} />

      <div className="relative z-10 container mx-auto px-4 py-8 max-w-2xl">
        {/* Theme Toggle */}
        <div className="flex justify-end mb-4">
          <button
            onClick={toggleTheme}
            className={`relative w-16 h-8 rounded-full p-1 transition-all duration-300 ${
              isDark
                ? 'bg-gray-700 shadow-[0_0_15px_rgba(23,255,53,0.3)]'
                : 'bg-emerald-200 shadow-lg'
            }`}
          >
            <div className={`absolute top-1 w-6 h-6 rounded-full flex items-center justify-center transition-all duration-300 ${
              isDark
                ? 'left-1 bg-gray-900'
                : 'left-9 bg-white'
            }`}>
              {isDark ? (
                <span className="text-[#17FF35]"><Moon size={16} /></span>
              ) : (
                <span className="text-amber-500"><Sun size={16} /></span>
              )}
            </div>
          </button>
        </div>

        {/* Header */}
        <header className="text-center mb-12">
            <div className="flex items-center justify-center gap-3 mb-4">
            <span className={`animate-pulse ${isDark ? 'text-[#17FF35]' : 'text-emerald-600'}`}><ShieldStar size={48} weight="duotone" /></span>
            <h1 className={`text-5xl font-bold tracking-wider ${isDark ? 'text-[#17FF35]' : 'text-emerald-700'}`}>
              {animatedTitle || 'Crypto Vault'}
            </h1>
          </div>
          <p className={`text-sm tracking-widest ${isDark ? 'text-[#17FF35]/70' : 'text-emerald-600'}`}>
            [ SECURE ENCRYPTION SYSTEM ]
          </p>
          <div className={`mt-2 text-xs ${isDark ? 'text-[#17FF35]/40' : 'text-gray-500'}`}>
            Developed by{' '}
            <a
              href="https://www.instagram.com/afsh4ck/"
              target="_blank"
              rel="noopener noreferrer"
              className={`underline transition-colors ${isDark ? 'text-[#17FF35] hover:text-[#17FF35]/80' : 'text-emerald-600 hover:text-emerald-500'}`}
            >
              afsh4ck
            </a>
          </div>
        </header>

        {/* Mode Toggle */}
        <div className="flex justify-center mb-8">
          <div className={`rounded-2xl p-1.5 flex gap-1 ${
            isDark
              ? 'bg-[#0d0d15] border border-[#17FF35]/20'
              : 'bg-white shadow-lg border border-gray-200'
          }`}>
            <button
              onClick={() => setMode('encrypt')}
              className={`px-6 py-3 rounded-xl flex items-center gap-2 transition-all duration-300 ${
                mode === 'encrypt'
                  ? isDark
                    ? 'bg-[#17FF35]/20 text-[#17FF35] shadow-[0_0_20px_rgba(23,255,53,0.3)]'
                    : 'bg-emerald-500 text-white shadow-lg'
                  : isDark
                    ? 'text-[#17FF35]/40 hover:text-[#17FF35]'
                    : 'text-gray-500 hover:text-emerald-600'
              }`}
            >
              <Lock size={16} />
              ENCRYPT
            </button>
            <button
              onClick={() => setMode('decrypt')}
              className={`px-6 py-3 rounded-xl flex items-center gap-2 transition-all duration-300 ${
                mode === 'decrypt'
                  ? isDark
                    ? 'bg-[#17FF35]/20 text-[#17FF35] shadow-[0_0_20px_rgba(23,255,53,0.3)]'
                    : 'bg-emerald-500 text-white shadow-lg'
                  : isDark
                    ? 'text-[#17FF35]/40 hover:text-[#17FF35]'
                    : 'text-gray-500 hover:text-emerald-600'
              }`}
            >
              <LockOpen size={16} />
              DECRYPT
            </button>
          </div>
        </div>

        {/* Main Card */}
        <div className={`backdrop-blur rounded-[16px] p-8 transition-all duration-300 ${
          isDark
            ? 'bg-[#0d0d15]/80 border border-[#17FF35]/15 shadow-[0_0_50px_rgba(23,255,53,0.1)]'
            : 'bg-white/80 border border-gray-200 shadow-xl'
        }`}>

          {/* Algorithm Selector - Only show in encrypt mode */}
          {mode === 'encrypt' && (
            <div className="mb-6">
              <label className={`block text-sm mb-2 tracking-wider ${isDark ? 'text-[#17FF35]/70' : 'text-gray-600'}`}>
                &gt; ENCRYPTION_ALGORITHM:
              </label>
              <div className="relative">
                <button
                  onClick={() => setShowAlgoDropdown(!showAlgoDropdown)}
                  className={`w-full rounded-[16px] px-4 py-3 text-left flex items-center justify-between transition-colors ${
                    isDark
                      ? 'bg-[#0a0a0f] border border-[#17FF35]/20 text-[#17FF35] hover:border-[#17FF35]/50'
                      : 'bg-gray-50 border border-gray-200 text-gray-700 hover:border-emerald-400'
                  }`}
                >
                  <div>
                    <span className="font-medium">{ALGORITHMS.find(a => a.value === algorithm)?.label}</span>
                    <span className={`text-sm ml-2 ${isDark ? 'text-[#17FF35]/40' : 'text-gray-500'}`}>
                      {ALGORITHMS.find(a => a.value === algorithm)?.description}
                    </span>
                  </div>
                  <span className={`transition-transform inline-flex ${showAlgoDropdown ? 'rotate-180' : ''} ${isDark ? 'text-[#17FF35]/70' : 'text-gray-400'}`}><CaretDown size={20} /></span>
                </button>

                {showAlgoDropdown && (
                  <div className={`absolute top-full left-0 right-0 mt-2 rounded-[16px] overflow-hidden z-20 ${
                    isDark
                      ? 'bg-[#0a0a0f] border border-[#17FF35]/20'
                      : 'bg-white border border-gray-200 shadow-xl'
                  }`}>
                    {ALGORITHMS.map((algo) => (
                      <button
                        key={algo.value}
                        onClick={() => {
                          setAlgorithm(algo.value);
                          setShowAlgoDropdown(false);
                        }}
                        className={`w-full px-4 py-3 text-left transition-colors ${
                          algorithm === algo.value
                            ? isDark ? 'bg-[#17FF35]/20 text-[#17FF35]' : 'bg-emerald-50 text-emerald-700'
                            : isDark ? 'text-[#17FF35] hover:bg-[#17FF35]/10' : 'text-gray-700 hover:bg-gray-50'
                        }`}
                      >
                        <div className="font-medium">{algo.label}</div>
                        <div className={`text-sm ${isDark ? 'text-[#17FF35]/40' : 'text-gray-500'}`}>{algo.description}</div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* File Drop Zone */}
          <div
            onDrop={handleDrop}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            className={`relative border-2 border-dashed rounded-[16px] p-12 text-center transition-all duration-300 cursor-pointer mb-6 ${
              dragOver
                ? isDark
                  ? 'border-[#17FF35] bg-[#17FF35]/10 shadow-[0_0_30px_rgba(23,255,53,0.2)]'
                  : 'border-emerald-500 bg-emerald-50'
                : file
                  ? isDark
                    ? 'border-[#17FF35]/50 bg-[#17FF35]/5'
                    : 'border-emerald-400 bg-emerald-50/50'
                  : isDark
                    ? 'border-[#17FF35]/20 hover:border-[#17FF35]/50'
                    : 'border-gray-300 hover:border-emerald-400'
            }`}
          >
            <input
              type="file"
              onChange={handleFileSelect}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <span className={`mx-auto mb-4 block w-fit ${
              file
                ? isDark ? 'text-[#17FF35]' : 'text-emerald-500'
                : isDark ? 'text-[#17FF35]/40' : 'text-gray-400'
            }`}><UploadSimple size={48} /></span>
            {file ? (
              <div>
                <p className={`text-lg ${isDark ? 'text-[#17FF35]' : 'text-emerald-700'}`}>{file.name}</p>
                <p className={`text-sm mt-1 ${isDark ? 'text-[#17FF35]/40' : 'text-gray-500'}`}>
                  {(file.size / 1024).toFixed(2)} KB | {file.type || 'unknown type'}
                </p>
              </div>
            ) : (
              <div>
                <p className={isDark ? 'text-[#17FF35]' : 'text-gray-600'}>DROP_FILE_HERE</p>
                <p className={`text-sm mt-2 ${isDark ? 'text-[#17FF35]/40' : 'text-gray-400'}`}>or click to browse</p>
              </div>
            )}
          </div>

          {/* Clear File Button */}
          {file && (
            <button
              onClick={clearFile}
              className={`w-full mb-6 py-3 rounded-full border transition-colors flex items-center justify-center gap-2 ${
                isDark
                  ? 'border-red-900/50 text-red-400 hover:bg-red-500/10'
                  : 'border-red-200 text-red-500 hover:bg-red-50 no-green-glow focus:outline-none focus:ring-0'
              }`}
            >
              <X size={16} />
              CLEAR_FILE
            </button>
          )}

          {/* Password Input */}
          <div className="mb-6">
            <label className={`block text-sm mb-2 tracking-wider ${isDark ? 'text-[#17FF35]/70' : 'text-gray-600'}`}>
              &gt; ENCRYPTION_KEY:
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter secure password..."
                className={`w-full rounded-[16px] px-4 py-3 transition-all ${
                  isDark
                    ? 'bg-[#0a0a0f] border border-[#17FF35]/20 text-[#17FF35] placeholder-[#17FF35]/30 focus:border-[#17FF35] focus:shadow-[0_0_20px_rgba(23,255,53,0.2)]'
                    : 'bg-gray-50 border border-gray-200 text-gray-800 placeholder-gray-400 focus:border-emerald-500 focus:shadow-lg'
                } focus:outline-none`}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className={`absolute right-3 top-1/2 -translate-y-1/2 transition-colors ${
                  isDark ? 'text-[#17FF35]/40 hover:text-[#17FF35]' : 'text-gray-400 hover:text-emerald-600'
                }`}
              >
                {showPassword ? <EyeSlash size={20} /> : <Eye size={20} />}
              </button>
            </div>
            {password && (
              <div className="mt-2 flex items-center gap-2">
                <div className={`flex-1 h-1.5 rounded-full overflow-hidden ${isDark ? 'bg-[#0a0a0f]' : 'bg-gray-200'}`}>
                  <div
                    className={`h-full transition-all duration-300 rounded-full ${
                      password.length < 6 ? 'w-1/4 bg-red-500' :
                      password.length < 10 ? 'w-2/4 bg-yellow-500' :
                      password.length < 14 ? 'w-3/4 bg-[#17FF35]/70' : 'w-full bg-[#17FF35]'
                    }`}
                  />
                </div>
                <span className={`text-xs ${isDark ? 'text-[#17FF35]/40' : 'text-gray-500'}`}>
                  {password.length < 6 ? 'WEAK' : password.length < 10 ? 'MEDIUM' : password.length < 14 ? 'STRONG' : 'SECURE'}
                </span>
              </div>
            )}
          </div>

          {/* Process Button */}
          <button
            onClick={processFile}
            disabled={!file || !password || processing}
            className={`w-full py-4 rounded-full font-bold tracking-wider flex items-center justify-center gap-3 transition-all duration-300 ${
              !file || !password || processing
                ? isDark
                  ? 'bg-[#17FF35]/10 text-[#17FF35]/30 cursor-not-allowed'
                  : 'bg-gray-200 text-gray-400 cursor-not-allowed'
                : isDark
                  ? 'bg-[#17FF35]/20 text-[#17FF35] border border-[#17FF35]/50 hover:bg-[#17FF35]/30 hover:shadow-[0_0_30px_rgba(23,255,53,0.3)] active:scale-[0.98]'
                  : 'bg-emerald-500 text-white hover:bg-emerald-600 shadow-lg hover:shadow-xl active:scale-[0.98]'
            }`}
          >
            {processing ? (
              <>
                <span className="animate-pulse"><Lightning size={20} /></span>
                PROCESSING...
              </>
            ) : mode === 'encrypt' ? (
              <>
                <Lock size={20} />
                ENCRYPT_FILE
              </>
            ) : (
              <>
                <LockOpen size={20} />
                DECRYPT_FILE
              </>
            )}
          </button>

          {/* Status Output */}
          {status && (
            <div className={`mt-6 p-4 rounded-[16px] border ${
              status.type === 'success'
                ? isDark ? 'bg-[#17FF35]/10 border-[#17FF35]/30 text-[#17FF35]' : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                : status.type === 'error'
                  ? isDark ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-red-50 border-red-200 text-red-600'
                  : isDark ? 'bg-[#17FF35]/5 border-[#17FF35]/15 text-[#17FF35]' : 'bg-gray-50 border-gray-200 text-gray-600'
            }`}>
              <div className="flex items-start gap-2">
                <span className="mt-0.5 flex-shrink-0"><DownloadSimple size={16} /></span>
                <code className="text-sm">{status.message}</code>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <footer className={`mt-8 text-center text-xs ${isDark ? 'text-[#17FF35]/30' : 'text-gray-400'}`}>
          <p>[ AES-GCM · PBKDF2-600K · AUTHENTICATED ENCRYPTION ]</p>
          <p className="mt-1">All processing happens locally in your browser</p>
        </footer>
      </div>
    </div>
  );
}

export default App;
