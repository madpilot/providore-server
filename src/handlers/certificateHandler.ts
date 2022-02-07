import { Response } from "express";
import { HMACRequest, signPayload } from "../middleware/hmac";
import { Devices } from "../types";
import path from "path";
import { readFile } from "fs/promises";
import { logger } from "../logger";

export function certificateHandler(
  certificateStore: string,
  devices: Devices
): (req: HMACRequest, res: Response) => void {
  return async (req, res) => {
    if (!req.device) {
      res.sendStatus(404);
      return;
    }
    const device = devices[req.device];
    try {
      const filePath = path.join(certificateStore, `${req.device}.cert.pem`);
      res.contentType("application/x-pem-file");
      const data = await readFile(filePath);
      signPayload(res, data, device.secretKey);
      res.sendFile(filePath);
    } catch (err: any) {
      if (err.code === "ENOENT") {
        res.sendStatus(404);
      } else {
        logger.error(err.message);
        res.sendStatus(500);
      }
    }
  };
}
