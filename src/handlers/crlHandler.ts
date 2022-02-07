import { OpenSSLConfig } from "config";
import { Request, Response } from "express";
import { dirname } from "path";

export function crlHandler(
  config: OpenSSLConfig
): (req: Request, res: Response) => void {
  return async (_req, res) => {
    if (!config.configFile) {
      throw new Error("No Open SSL config file set");
    }
    if (!config.passwordFile) {
      throw new Error("No Open SSL password file set");
    }

    const configDir = dirname(config.configFile);
    res.contentType("application/x-pem-file");
    res.sendFile(`${configDir}/crl.pem`);
  };
}
