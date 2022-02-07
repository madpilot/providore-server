import { OpenSSLConfig } from "config";
import { Response } from "express";
import { logger } from "../logger";
import { sign } from "../lib/openssl";
import { HMACRequest, signPayload } from "../middleware/hmac";
import { Devices } from "../types";

interface Params {
  csr?: string;
}

export function csrHandler(
  certificateStore: string,
  devices: Devices,
  openSSL: OpenSSLConfig
): (req: HMACRequest<Params>, res: Response) => void {
  return async (req, res) => {
    try {
      if (!req.device) {
        res.sendStatus(404);
        return;
      }
      const device = devices[req.device];
      if (!device) {
        logger.warn("CSR Handler: Device not found");
        res.sendStatus(404);
        return;
      }

      const csr = req.body;
      if (!csr) {
        logger.warn("CSR Handler: CSR param not set");
        res.sendStatus(404);
        return;
      }

      const certificate = await sign(
        csr,
        req.device,
        certificateStore,
        openSSL
      );

      res.contentType("application/x-pem-file");
      signPayload(res, certificate, device.secretKey);
      res.send(certificate);
    } catch (e: any) {
      console.log(e);
      logger.error(e.message);
      res.sendStatus(500);
    }
  };
}
