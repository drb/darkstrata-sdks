/**
 * @darkstrata/shield - Device fingerprint collection
 *
 * Collects browser and device characteristics to create a stable,
 * unique fingerprint for device recognition.
 */

import { sha256, simpleHash } from './crypto.js';
import {
  FingerprintStatus,
  type DeviceFingerprint,
  type FingerprintComponents,
  type FingerprintSignals,
  type FingerprintAnomalies,
} from './types.js';

// Declare WebKit AudioContext for Safari
declare global {
  interface Window {
    webkitAudioContext?: typeof AudioContext;
  }
}

/**
 * Get current time in milliseconds (with fallback for environments without performance API)
 */
function now(): number {
  return typeof performance !== 'undefined' && performance.now
    ? performance.now()
    : Date.now();
}

/**
 * Collect all fingerprint components and generate device fingerprint
 */
export async function collectFingerprint(): Promise<DeviceFingerprint> {
  try {
    const start = now();

    // Collect signals first (used by multiple components)
    const signals = collectSignals();

    // Collect component hashes in parallel where possible
    const [canvas, webgl, audio, fonts] = await Promise.all([
      getCanvasFingerprint(),
      getWebGLFingerprint(signals),
      getAudioFingerprint(),
      getFontFingerprint(),
    ]);

    const hardware = getHardwareFingerprint(signals);
    const browser = getBrowserFingerprint(signals);

    const components: FingerprintComponents = {
      canvas,
      webgl,
      audio,
      fonts,
      hardware,
      browser,
    };

    // Detect anomalies
    const anomalies = detectAnomalies(signals);

    // Generate final fingerprint ID
    const fingerprintId = await hashComponents(components);

    const generationTimeMs = now() - start;

    return {
      fingerprintId,
      confidence: calculateConfidence(components, anomalies),
      generatedAt: Date.now(),
      generationTimeMs,
      components,
      signals,
      anomalies,
    };
  } catch {
    // Safety net: return degraded fingerprint rather than crashing customer site
    const signals = collectSignals();
    return {
      fingerprintId: FingerprintStatus.ERROR,
      confidence: 0,
      generatedAt: Date.now(),
      generationTimeMs: 0,
      components: {
        canvas: FingerprintStatus.ERROR,
        webgl: FingerprintStatus.ERROR,
        audio: FingerprintStatus.ERROR,
        fonts: FingerprintStatus.ERROR,
        hardware: FingerprintStatus.ERROR,
        browser: FingerprintStatus.ERROR,
      },
      signals,
      anomalies: {
        headlessDetected: false,
        automationDetected: false,
        vmDetected: false,
        spoofingDetected: false,
      },
    };
  }
}

/**
 * Canvas fingerprinting
 *
 * Renders text and shapes, then hashes the result.
 * Different GPUs/drivers produce subtly different outputs.
 */
async function getCanvasFingerprint(): Promise<string> {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 280;
    canvas.height = 60;
    const ctx = canvas.getContext('2d');

    if (!ctx) return FingerprintStatus.UNSUPPORTED;

    // Draw text with various styles
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#f60';
    ctx.fillRect(100, 1, 62, 20);

    ctx.fillStyle = '#069';
    ctx.font = '15px Arial';
    ctx.fillText('DarkStrata,canvas:fp', 2, 15);

    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.font = '18px Georgia';
    ctx.fillText('DarkStrata,canvas:fp', 4, 37);

    // Draw shapes
    ctx.beginPath();
    ctx.arc(50, 50, 10, 0, Math.PI * 2);
    ctx.closePath();
    ctx.fill();

    const dataUrl = canvas.toDataURL();
    return sha256(dataUrl);
  } catch {
    return FingerprintStatus.ERROR;
  }
}

/**
 * WebGL fingerprinting
 *
 * Collects GPU vendor, renderer, and capabilities.
 */
async function getWebGLFingerprint(signals: FingerprintSignals): Promise<string> {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

    // Accept both WebGL1 and WebGL2 contexts
    if (!gl) return FingerprintStatus.UNSUPPORTED;

    // Type guard for WebGL context methods
    const glContext = gl as WebGLRenderingContext;

    const debugInfo = glContext.getExtension('WEBGL_debug_renderer_info');

    const vendor = debugInfo
      ? glContext.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
      : glContext.getParameter(glContext.VENDOR);

    const renderer = debugInfo
      ? glContext.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
      : glContext.getParameter(glContext.RENDERER);

    // Store raw values for anomaly detection
    signals.webglVendor = String(vendor ?? '');
    signals.webglRenderer = String(renderer ?? '');

    const data = {
      vendor,
      renderer,
      version: glContext.getParameter(glContext.VERSION),
      shadingLanguageVersion: glContext.getParameter(glContext.SHADING_LANGUAGE_VERSION),
      maxTextureSize: glContext.getParameter(glContext.MAX_TEXTURE_SIZE),
      maxVertexAttribs: glContext.getParameter(glContext.MAX_VERTEX_ATTRIBS),
      maxVertexUniformVectors: glContext.getParameter(glContext.MAX_VERTEX_UNIFORM_VECTORS),
      maxFragmentUniformVectors: glContext.getParameter(glContext.MAX_FRAGMENT_UNIFORM_VECTORS),
      extensions: (glContext.getSupportedExtensions() ?? []).sort().join(','),
    };

    return sha256(JSON.stringify(data));
  } catch {
    return FingerprintStatus.ERROR;
  }
}

/**
 * Audio fingerprinting
 *
 * Uses AudioContext to generate a fingerprint based on
 * how the browser processes audio signals.
 */
async function getAudioFingerprint(): Promise<string> {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return FingerprintStatus.UNSUPPORTED;

    const audioContext = new AudioContextClass();
    const oscillator = audioContext.createOscillator();
    const analyser = audioContext.createAnalyser();
    const gainNode = audioContext.createGain();
    const compressor = audioContext.createDynamicsCompressor();

    // Configure nodes
    oscillator.type = 'triangle';
    oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);

    compressor.threshold.setValueAtTime(-50, audioContext.currentTime);
    compressor.knee.setValueAtTime(40, audioContext.currentTime);
    compressor.ratio.setValueAtTime(12, audioContext.currentTime);
    compressor.attack.setValueAtTime(0, audioContext.currentTime);
    compressor.release.setValueAtTime(0.25, audioContext.currentTime);

    gainNode.gain.setValueAtTime(0, audioContext.currentTime); // Mute output

    // Connect nodes
    oscillator.connect(compressor);
    compressor.connect(analyser);
    analyser.connect(gainNode);
    gainNode.connect(audioContext.destination);

    oscillator.start(0);

    // Wait for processing
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Get frequency data
    const frequencyData = new Float32Array(analyser.frequencyBinCount);
    analyser.getFloatFrequencyData(frequencyData);

    oscillator.stop();
    await audioContext.close();

    // Use subset of frequency data for fingerprint
    const subset = Array.from(frequencyData.slice(0, 100));
    return sha256(subset.join(','));
  } catch {
    return FingerprintStatus.UNSUPPORTED;
  }
}

/**
 * Font fingerprinting
 *
 * Detects which fonts are installed by measuring text rendering differences.
 */
async function getFontFingerprint(): Promise<string> {
  try {
    const baseFonts = ['monospace', 'sans-serif', 'serif'] as const;
    const testFonts = [
      'Arial',
      'Arial Black',
      'Calibri',
      'Cambria',
      'Comic Sans MS',
      'Consolas',
      'Courier New',
      'Georgia',
      'Helvetica',
      'Impact',
      'Lucida Console',
      'Palatino Linotype',
      'Segoe UI',
      'Tahoma',
      'Times New Roman',
      'Trebuchet MS',
      'Verdana',
      // Extended list
      'Monaco',
      'Menlo',
      'Ubuntu',
      'Cantarell',
      'Fira Sans',
      'Roboto',
      'Open Sans',
      'Lato',
      'Source Sans Pro',
    ];

    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    if (!ctx) return FingerprintStatus.UNSUPPORTED;

    // Get baseline widths
    const baselineWidths: Record<string, number> = {};
    for (const baseFont of baseFonts) {
      ctx.font = `${testSize} ${baseFont}`;
      const measurement = ctx.measureText(testString);
      baselineWidths[baseFont] = measurement?.width ?? 0;
    }

    // Test each font
    const detectedFonts: string[] = [];
    for (const font of testFonts) {
      let detected = false;
      for (const baseFont of baseFonts) {
        ctx.font = `${testSize} "${font}", ${baseFont}`;
        const measurement = ctx.measureText(testString);
        const width = measurement?.width ?? 0;
        if (width !== baselineWidths[baseFont]) {
          detected = true;
          break;
        }
      }
      if (detected) {
        detectedFonts.push(font);
      }
    }

    return sha256(detectedFonts.sort().join(','));
  } catch {
    return FingerprintStatus.ERROR;
  }
}

/**
 * Hardware fingerprinting
 *
 * Collects CPU cores, memory, screen properties, etc.
 */
function getHardwareFingerprint(signals: FingerprintSignals): string {
  try {
    // Safely access screen object (may not exist in some environments)
    const screenObj = typeof screen !== 'undefined' ? screen : null;

    const data = {
      cpuCores: navigator.hardwareConcurrency ?? 0,
      deviceMemory: (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? null,
      maxTouchPoints: navigator.maxTouchPoints ?? 0,
      screenWidth: screenObj?.width ?? 0,
      screenHeight: screenObj?.height ?? 0,
      screenAvailWidth: screenObj?.availWidth ?? 0,
      screenAvailHeight: screenObj?.availHeight ?? 0,
      colourDepth: screenObj?.colorDepth ?? 0,
      pixelDepth: screenObj?.pixelDepth ?? 0,
      devicePixelRatio: window.devicePixelRatio ?? 1,
    };

    // Update signals
    signals.cpuCores = data.cpuCores;
    signals.deviceMemory = data.deviceMemory;
    signals.screenResolution = [data.screenWidth, data.screenHeight];
    signals.colourDepth = data.colourDepth;
    signals.maxTouchPoints = data.maxTouchPoints;
    signals.touchSupport = data.maxTouchPoints > 0;
    signals.hardwareConcurrency = data.cpuCores;

    return simpleHash(JSON.stringify(data));
  } catch {
    return FingerprintStatus.ERROR;
  }
}

/**
 * Safely get timezone string
 */
function getTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return '';
  }
}

/**
 * Browser fingerprinting
 *
 * Collects user agent, language, timezone, etc.
 */
function getBrowserFingerprint(signals: FingerprintSignals): string {
  try {
    const data = {
      userAgent: navigator.userAgent ?? '',
      language: navigator.language ?? '',
      languages: navigator.languages?.slice() ?? [navigator.language ?? 'en'],
      platform: navigator.platform ?? '',
      cookieEnabled: navigator.cookieEnabled ?? false,
      doNotTrack: navigator.doNotTrack ?? null,
      timezone: getTimezone(),
      timezoneOffset: new Date().getTimezoneOffset(),
    };

    // Update signals
    signals.language = data.language;
    signals.languages = data.languages;
    signals.platform = data.platform;
    signals.timezone = data.timezone;
    signals.timezoneOffset = data.timezoneOffset;
    signals.userAgent = data.userAgent;

    return simpleHash(JSON.stringify(data));
  } catch {
    return FingerprintStatus.ERROR;
  }
}

/**
 * Collect raw signals for server-side analysis
 */
function collectSignals(): FingerprintSignals {
  return {
    screenResolution: [0, 0],
    colourDepth: 0,
    timezone: '',
    timezoneOffset: 0,
    language: '',
    languages: [],
    platform: '',
    cpuCores: 0,
    deviceMemory: null,
    touchSupport: false,
    maxTouchPoints: 0,
    webglVendor: '',
    webglRenderer: '',
    hardwareConcurrency: 0,
    userAgent: '',
  };
}

/**
 * Detect anomalies that indicate automation, headless browsers, etc.
 */
function detectAnomalies(signals: FingerprintSignals): FingerprintAnomalies {
  const anomalies: FingerprintAnomalies = {
    headlessDetected: false,
    automationDetected: false,
    vmDetected: false,
    spoofingDetected: false,
  };

  // Headless browser detection
  const hasWebdriver = 'webdriver' in navigator && (navigator as Navigator & { webdriver?: boolean }).webdriver;
  const chromeWithoutChrome =
    !(window as Window & { chrome?: unknown }).chrome && /Chrome/.test(navigator.userAgent);
  const noPluginsOnDesktop =
    navigator.plugins?.length === 0 && !/Mobile|Android/.test(navigator.userAgent);

  if (hasWebdriver || chromeWithoutChrome || noPluginsOnDesktop) {
    anomalies.headlessDetected = true;
  }

  // Automation framework detection
  const win = window as Window & {
    _phantom?: unknown;
    __nightmare?: unknown;
    callPhantom?: unknown;
    Cypress?: unknown;
    __selenium_evaluate?: unknown;
    __webdriver_script_fn?: unknown;
  };
  const doc = document as Document & {
    __selenium_unwrapped?: unknown;
    __webdriver_evaluate?: unknown;
    $cdc_asdjflasutopfhvcZLmcfl_?: unknown;
  };

  if (
    win._phantom ||
    win.__nightmare ||
    win.callPhantom ||
    win.Cypress ||
    win.__selenium_evaluate ||
    win.__webdriver_script_fn ||
    doc.__selenium_unwrapped ||
    doc.__webdriver_evaluate ||
    doc.$cdc_asdjflasutopfhvcZLmcfl_ ||
    hasWebdriver
  ) {
    anomalies.automationDetected = true;
  }

  // VM detection (heuristic)
  const renderer = signals.webglRenderer?.toLowerCase() || '';
  if (
    renderer.includes('swiftshader') ||
    renderer.includes('llvmpipe') ||
    renderer.includes('virtualbox') ||
    renderer.includes('vmware') ||
    renderer.includes('parallels') ||
    renderer.includes('qemu') ||
    renderer.includes('hyper-v') ||
    renderer.includes('xen')
  ) {
    anomalies.vmDetected = true;
    // SwiftShader/LLVMpipe also indicates headless
    if (renderer.includes('swiftshader') || renderer.includes('llvmpipe')) {
      anomalies.headlessDetected = true;
    }
  }

  // UA/Platform spoofing detection
  const ua = navigator.userAgent.toLowerCase();
  const platform = navigator.platform.toLowerCase();

  if (ua.includes('windows') && !platform.includes('win')) {
    anomalies.spoofingDetected = true;
  }
  if (ua.includes('macintosh') && !platform.includes('mac')) {
    anomalies.spoofingDetected = true;
  }
  if (ua.includes('linux') && !platform.includes('linux') && !ua.includes('android')) {
    anomalies.spoofingDetected = true;
  }

  // Impossible hardware values
  if (signals.cpuCores === 0 || signals.cpuCores > 128) {
    anomalies.spoofingDetected = true;
  }

  // Mobile UA without touch support
  if (/mobile|android|iphone|ipad/i.test(ua)) {
    if (signals.maxTouchPoints === 0) {
      anomalies.spoofingDetected = true;
    }
  }

  return anomalies;
}

/**
 * Calculate confidence score based on component availability and anomalies
 */
function calculateConfidence(
  components: FingerprintComponents,
  anomalies: FingerprintAnomalies
): number {
  let confidence = 1.0;

  // Reduce confidence for missing/unsupported components
  if (components.canvas === FingerprintStatus.UNSUPPORTED || components.canvas === FingerprintStatus.ERROR) {
    confidence -= 0.2;
  }
  if (components.webgl === FingerprintStatus.UNSUPPORTED || components.webgl === FingerprintStatus.ERROR) {
    confidence -= 0.15;
  }
  if (components.audio === FingerprintStatus.UNSUPPORTED) {
    confidence -= 0.1;
  }
  if (components.fonts === FingerprintStatus.UNSUPPORTED) {
    confidence -= 0.1;
  }

  // Reduce confidence for anomalies
  if (anomalies.headlessDetected) confidence -= 0.2;
  if (anomalies.vmDetected) confidence -= 0.1;

  return Math.max(0, Math.min(1, confidence));
}

/**
 * Hash all components to generate final fingerprint ID
 */
async function hashComponents(components: FingerprintComponents): Promise<string> {
  const componentString = Object.values(components).sort().join('|');
  return sha256(componentString);
}
