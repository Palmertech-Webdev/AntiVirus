import express from 'express';
import { Request, Response } from 'express';
import * as yaml from 'js-yaml';
import * as fs from 'fs';
import * as path from 'path';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// --- Sigma Engine Mock ---
interface SigmaRule {
  title: string;
  id: string;
  tags?: string[];
  logsource: {
    category?: string;
    product?: string;
  };
  detection: any;
}

const sigmaRules: SigmaRule[] = [];

function loadSigmaRules() {
  const rulesDir = path.join(__dirname, '../rules/sigma');
  if (fs.existsSync(rulesDir)) {
    const files = fs.readdirSync(rulesDir);
    for (const file of files) {
      if (file.endsWith('.yml') || file.endsWith('.yaml')) {
        try {
          const doc = yaml.load(fs.readFileSync(path.join(rulesDir, file), 'utf8')) as SigmaRule;
          sigmaRules.push(doc);
          console.log(`[Sigma] Loaded rule: ${doc.title}`);
        } catch (e) {
          console.error(`[Sigma] Failed to load rule ${file}:`, e);
        }
      }
    }
  }
}

function evaluateSigmaRules(telemetryData: any) {
  const alerts: any[] = [];
  const payload = telemetryData.payload;

  for (const rule of sigmaRules) {
    // Basic mock evaluator: check if commandLine contains all strings
    if (rule.detection && rule.detection.selection && rule.detection.selection['commandLine|contains|all']) {
      const stringsToMatch = rule.detection.selection['commandLine|contains|all'] as string[];
      const commandLine = payload.commandLine;

      if (commandLine && typeof commandLine === 'string') {
        const matchesAll = stringsToMatch.every((str) => commandLine.includes(str));
        
        if (matchesAll) {
          // Rule Matched! Generate Alert with MITRE ATT&CK tags
          const mitreTags = rule.tags?.filter(tag => tag.startsWith('attack.')) || [];
          
          const alert = {
            alertId: `alert-${Date.now()}`,
            timestamp: new Date().toISOString(),
            ruleName: rule.title,
            deviceId: telemetryData.deviceId,
            mitreTags: mitreTags,
            evidence: telemetryData
          };
          alerts.push(alert);
        }
      }
    }
  }

  return alerts;
}
// -------------------------

// Basic validation for the unified telemetry schema
function validateTelemetryPayload(payload: any): boolean {
  if (!payload || !payload.eventId || !payload.deviceId || !payload.timestamp || !payload.eventType || !payload.payload) {
    return false;
  }
  return true;
}

app.post('/api/v1/telemetry', (req: Request, res: Response) => {
  const telemetryData = req.body;

  if (!validateTelemetryPayload(telemetryData)) {
    console.warn(`[!] Received invalid telemetry payload`);
    res.status(400).json({ error: 'Invalid telemetry schema' });
    return;
  }

  console.log(`[+] Received ${telemetryData.eventType} from device ${telemetryData.deviceId}`);

  // Evaluate Behavioral Engine (Sigma)
  const alerts = evaluateSigmaRules(telemetryData);
  
  if (alerts.length > 0) {
    console.log(`\n[!!!] THREAT DETECTED [!!!]`);
    alerts.forEach(alert => {
      console.log(`Rule: ${alert.ruleName}`);
      console.log(`MITRE ATT&CK: ${alert.mitreTags.join(', ')}`);
      console.log(`Device: ${alert.deviceId}\n`);
    });
  }

  res.status(200).json({ status: 'success', eventId: telemetryData.eventId, alertsGenerated: alerts.length });
});

app.listen(port, () => {
  loadSigmaRules();
  console.log(`Fenrir Unified Backend listening on port ${port}`);
});
