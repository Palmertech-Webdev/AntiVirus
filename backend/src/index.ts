import express from 'express';
import { Request, Response } from 'express';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

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
  console.log(JSON.stringify(telemetryData.payload, null, 2));

  // TODO: Add Sigma/YARA engine processing here

  res.status(200).json({ status: 'success', eventId: telemetryData.eventId });
});

app.listen(port, () => {
  console.log(`Fenrir Unified Backend listening on port ${port}`);
});
