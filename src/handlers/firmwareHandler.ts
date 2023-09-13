import { Response } from "express";
import { HMACRequest, signPayload } from "../middleware/hmac";
import { Devices } from "../types";
import path from "path";
import { readFile } from "fs/promises";
import { logger } from "../logger";
import { FirmwareParams } from "types";

export function firmwareHandler(
  firmwareStore: string,
  devices: Devices
): (req: HMACRequest<FirmwareParams>, res: Response) => void {
  return async (req, res) => {
    if (!req.device) {
      res.sendStatus(404);
      return;
    }
    const device = devices[req.device];
    if (!device) {
      res.sendStatus(404);
      return;
    }
    const version = req.params?.version || device.firmware.reverse()[0].version;
    if (!version) {
      res.sendStatus(404);
      return;
    }

    const firmware = device.firmware.find((f) => f.version === version);

    if (!firmware) {
      res.sendStatus(404);
      return;
    }

    const filePath = path.join(
      firmwareStore,
      firmware.type,
      firmware.version,
      firmware.file
    );

    try {
      const data = await readFile(filePath);
      signPayload(res, data, device.secretKey);
      res.contentType("application/octet-stream");
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

export function checkUpdateHandler(
  devices: Devices
): (req: HMACRequest, res: Response) => void {
  return async (req, res) => {
    if (!req.device) {
      res.sendStatus(404);
      return;
    }
    const device = devices[req.device];
    if (!device) {
      res.sendStatus(404);
      return;
    }
    const version = req.get("x-firmware-version");
    if (!version) {
      logger.debug("Missing X-Firmware-Version header");
      res.sendStatus(404);
      return;
    }

    const firmware = device.firmware.find((f) => f.version === version);

    if (!firmware) {
      logger.debug("Firmware not found");
      res.sendStatus(404);
      return;
    }

    if (firmware.next) {
      res.redirect(`/firmware?version=${firmware.next}`, 302);
    } else {
      res.sendStatus(204);
    }
  };
}
