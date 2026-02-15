/**
 * Prompt Injection Detector
 * 
 * Standalone library for detecting various forms of prompt injection attacks:
 * - Direct instruction override attempts
 * - Indirect prompt injection via special tokens
 * - Encoding and obfuscation attempts
 * - Context manipulation
 */

export type ThreatLevel = 1 | 2 | 3 | 4;

export interface DetectionConfig {
  patterns?: RegExp[];
  customRules?: Array<{
    pattern: RegExp;
    confidence: number;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
}

export interface SecurityEvent {
  id: string;
  sessionId: string;
  timestamp: string;
  threatLevel: ThreatLevel;
  details: Record<string, any>;
}

export interface DetectionResult {
  detector: string;
  detected: boolean;
  threatLevel: ThreatLevel;
  confidence: number;
  matchedPatterns?: string[];
  reason?: string;
  processingTime?: number;
}

export class PromptInjectionDetector {
  private config: DetectionConfig;
  
  // Default patterns for prompt injection detection
  private readonly defaultPatterns: RegExp[] = [
    // Direct override attempts
    /ignore\s+(previous|above|all|your)\s+(instructions?|rules?|commands?|prompt)/i,
    /forget\s+(everything|all|your)\s+(instructions?|rules?|system|guidelines)/i,
    /disregard\s+(all|your|previous)\s+(instructions?|rules?)/i,
    /new\s+(system\s+)?instructions?/i,
    /override\s+(your|system)\s+(instructions?|rules?)/i,
    
    // Role manipulation
    /you\s+are\s+(now|no\s+longer|a|free|not\s+bound)/i,
    /act\s+as\s+(if|though)\s+(you|it)/i,
    /pretend\s+(to|you\s+are|you)/i,
    /roleplay\s+as/i,
    
    // System prompt extraction
    /show\s+(me\s+)?(your\s+)?(system\s+)?prompt/i,
    /what\s+are\s+your\s+(system\s+)?instructions/i,
    /reveal\s+(your|system)\s+(prompt|instructions)/i,
    /tell\s+me\s+about\s+your\s+(system\s+)?prompt/i,
    
    // Bypass attempts
    /BYPASS/i,
    /hack/i,
    /exploit/i,
    
    // Special token injection
    /<\|/,
    /\|>/,
    /\[INST\]/,
    /\[\/INST\]/,
    /<<SYS>>/,
    /<<\/SYS>>/,
    
    // DAN-style attacks
    / DAN /i,
    /do\s+anything\s+now/i,
    /developer\s+mode/i,
    /devmode/i,
  ];

  constructor(config: DetectionConfig = {}) {
    this.config = config;
  }

  /**
   * Analyze a message for prompt injection patterns
   */
  analyze(
    message: string,
    sessionHistory: SecurityEvent[] = []
  ): DetectionResult {
    const startTime = Date.now();
    const matchedPatterns: string[] = [];
    let maxConfidence = 0;

    // Get patterns to check (config or default)
    const patterns = this.config.patterns || this.defaultPatterns;

    // Check against all patterns
    for (const pattern of patterns) {
      const re = new RegExp(pattern.source, pattern.flags);
      if (re.test(message)) {
        matchedPatterns.push(pattern.source);
        maxConfidence = Math.max(maxConfidence, this.getPatternConfidence(pattern));
      }
    }

    // Check for encoding attempts
    if (this.hasEncodingAttempts(message)) {
      matchedPatterns.push('encoding_attempt');
      maxConfidence = Math.max(maxConfidence, 0.7);
    }

    // Check for indirect injection via special markers
    const indirectIndicators = this.checkIndirectInjection(message);
    if (indirectIndicators.length > 0) {
      matchedPatterns.push(...indirectIndicators);
      maxConfidence = Math.max(maxConfidence, 0.6);
    }

    // Check session history for escalation patterns
    const escalationScore = this.calculateSessionEscalation(sessionHistory);
    if (escalationScore > 0.5) {
      matchedPatterns.push('session_escalation');
      maxConfidence = Math.max(maxConfidence, escalationScore);
    }

    const detected = matchedPatterns.length > 0;
    const threatLevel = this.calculateThreatLevel(detected, maxConfidence);
    const processingTime = Date.now() - startTime;

    return {
      detector: 'prompt_injection',
      detected,
      threatLevel,
      confidence: maxConfidence,
      matchedPatterns: matchedPatterns.length > 0 ? matchedPatterns : undefined,
      reason: detected ? this.generateReason(matchedPatterns) : undefined,
      processingTime
    };
  }

  /**
   * Get confidence score for a pattern based on its severity
   */
  private getPatternConfidence(pattern: RegExp): number {
    const patternStr = pattern.source.toLowerCase();
    
    // Critical patterns (highest confidence)
    if (/ignore\s+(all|previous)|forget\s+everything|BYPASS|devmode/i.test(patternStr)) {
      return 0.95;
    }
    
    // High severity patterns
    if (/show.*prompt|reveal.*instructions|system\s*prompt/i.test(patternStr)) {
      return 0.9;
    }
    
    // Medium severity patterns
    if (/new\s+instructions|you\s+are\s+(now|free)|roleplay/i.test(patternStr)) {
      return 0.75;
    }
    
    // Lower severity - potential but not definite
    return 0.5;
  }

  /**
   * Check for encoding/obfuscation attempts
   */
  private hasEncodingAttempts(message: string): boolean {
    const encodingPatterns = [
      /base64/i,
      /\b[a-zA-Z0-9+/]{20,}={0,2}\b/,
      /\\x[0-9a-f]{2}/i,
      /\\u[0-9a-f]{4}/i,
      /%[0-9a-f]{2}/i,
      /&#x[0-9a-f]+;/i,
      /\u200b|\u200c|\u200d/i,
    ];

    return encodingPatterns.some(p => p.test(message));
  }

  /**
   * Check for indirect injection markers
   */
  private checkIndirectInjection(message: string): string[] {
    const indicators: string[] = [];
    
    if (/<\|[a-z_]+\|>/i.test(message)) {
      indicators.push('special_token_detected');
    }
    
    if (/\[INST\]|\[\/INST\]/i.test(message)) {
      indicators.push('instruction_tags');
    }
    
    if (/<<SYS>>|<<\/SYS>>/i.test(message)) {
      indicators.push('system_message_markers');
    }
    
    return indicators;
  }

  /**
   * Calculate escalation score based on session history
   */
  private calculateSessionEscalation(sessionHistory: SecurityEvent[]): number {
    if (sessionHistory.length < 2) return 0;
    
    let escalationScore = 0;
    let previousThreatLevel = 1;
    
    for (const event of sessionHistory) {
      if (event.threatLevel > previousThreatLevel) {
        escalationScore += (event.threatLevel - previousThreatLevel) * 0.2;
      }
      previousThreatLevel = event.threatLevel;
    }
    
    escalationScore += Math.min(sessionHistory.length * 0.05, 0.3);
    
    return Math.min(escalationScore, 1.0);
  }

  /**
   * Calculate threat level based on detection and confidence
   */
  private calculateThreatLevel(detected: boolean, confidence: number): ThreatLevel {
    if (!detected) return 1;
    
    if (confidence >= 0.9) return 4;
    if (confidence >= 0.7) return 3;
    if (confidence >= 0.5) return 2;
    return 1;
  }

  /**
   * Generate human-readable reason for detection
   */
  private generateReason(matchedPatterns: string[]): string {
    const reasons: string[] = [];
    
    for (const pattern of matchedPatterns) {
      if (/ignore|forget|disregard/i.test(pattern)) {
        reasons.push('instruction_override_attempt');
      }
      if (/show.*prompt|reveal.*instructions/i.test(pattern)) {
        reasons.push('prompt_extraction_attempt');
      }
      if (/encoding/i.test(pattern)) {
        reasons.push('encoding_obfuscation_detected');
      }
      if (/token|marker/i.test(pattern)) {
        reasons.push('special_token_injection');
      }
      if (/escalation/i.test(pattern)) {
        reasons.push('session_escalation_pattern');
      }
    }
    
    return reasons.length > 0 ? reasons.join(', ') : 'suspicious_pattern_detected';
  }
}

// Export for use as library
export default PromptInjectionDetector;
