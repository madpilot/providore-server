import express from "express";
import { hmacAuthorization } from "./middleware/hmac";
import { Devices } from "./types";
import { readFile } from "fs/promises";

import http from "http";
import https from "https";
import { certificateHandler } from "./handlers/certificateHandler";

import { csrHandler } from "./handlers/csrHandler";
import { crlHandler } from "./handlers/crlHandler";
import { Config } from "config";
import { logger } from "./logger";
import { text } from "body-parser";

const app = express();
async function loadDevices(configStore: string): Promise<Devices> {
  const data = await readFile(`${configStore}/devices.json`, {
    encoding: "utf-8"
  });
  return JSON.parse(data);
}

export async function startServer({
  webserver,
  configStore,
  certificateStore,
  openSSL
}: Config) {
  const { protocol, bind, port, sslCertPath, sslKeyPath, caCertPath, user } =
    webserver;

  try {
    const devices = await loadDevices(configStore);

    app.use(text({ defaultCharset: "utf-8" }));

    if (openSSL.configFile) {
      app.get("/certificates/crl.pem", crlHandler(openSSL));
    }

    app.use(hmacAuthorization(devices));

    if (certificateStore) {
      app.post(
        "/certificates/request",
        csrHandler(certificateStore, devices, openSSL)
      );
      app.get("/certificate", certificateHandler(certificateStore, devices));
    }

    if (protocol === "https") {
      if (!sslCertPath) {
        throw new Error(
          "Unable to start SSL server - no certificate file supplied"
        );
      }
      if (!sslKeyPath) {
        throw new Error(
          "Unable to start SSL server - no certificate key supplied"
        );
      }

      const cert = await readFile(sslCertPath);
      const key = await readFile(sslKeyPath);
      const ca = caCertPath ? await readFile(caCertPath) : undefined;
      const httpsServer = https.createServer(
        {
          cert,
          key,
          ca
        },
        app
      );
      httpsServer.listen(port, bind, () => {
        logger.info(`HTTPS server listening at ${protocol}://${bind}:${port}`);
        if (typeof user === "string") {
          logger.debug(`Setting user to ${user}`);
          process.setuid(user);
        }
      });
    } else {
      const httpServer = http.createServer(app);
      httpServer.listen(port, bind, () => {
        logger.info(`HTTP server listening at ${protocol}://${bind}:${port}`);
        if (typeof user === "string") {
          logger.debug(`Setting user to ${user}`);
          process.setuid(user);
        }
      });
    }
  } catch (e) {
    logger.error(e);
  }
}
