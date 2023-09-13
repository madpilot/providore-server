import { Response } from "express";
import { HMACRequest, signPayload } from "../middleware/hmac";
import { Devices } from "../types";
import path from "path";
import { readFile } from "fs/promises";
import { logger } from "../logger";

export function configHandler(
  configStore: string,
  devices: Devices
): (req: HMACRequest, res: Response) => void {
  return async (req, res) => {
    if (!req.device) {
      logger.debug("No device in request");
      res.sendStatus(404);
      return;
    }

    const version = req.get("x-firmware-version");
    if (!version) {
      logger.debug("Missing X-Firmware-Version header");
      res.sendStatus(400);
      return;
    }
    const device = devices[req.device];
    const firmware = device.firmware.find((f) => f.version === version);

    if (!firmware) {
      logger.debug("Firmware version not found");
      res.sendStatus(404);
      return;
    }

    const filePath = path.join(configStore, req.device, `${firmware.config}`);

    try {
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
