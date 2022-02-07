#!/usr/bin/env node
import commander, { Command } from "commander";
import { load } from "./config";
import { startServer } from "./server";
import { resolve } from "path";
import { logger, reconfigureLogger } from "./logger";
const program = new Command();
program.version("0.0.1");

program.option("-b, --bind <bind>", "IP Address to bind to");
program.option("-p, --port <port>", "TCP port to listen to");
program.option("--ssl <true|false>", "Enable SSL");
program.option(
  "--cert <path>",
  "Path to the TLS certificate. Required if SSL is enabled"
);
program.option(
  "--cert-key <path>",
  "Path to the TLS key. Required if SSL is enabled"
);
program.option("--cert-ca <path>", "Path to a TLS ca cert chain.");

program.option("-c, --config <path>", "Path to config file");

program.option("--config-store <path>", "Folder that stores device configs");
program.option("--firmware-store <path>", "Folder that stores device firmware");
program.option(
  "--certificate-store <path>",
  "Folder that stores device certificates"
);

async function bootstrap(options: commander.OptionValues) {
  if (typeof options.config !== "string") {
    throw new Error("Unable to find path to config file");
  }

  const config = await load(options.config);
  reconfigureLogger(logger, config.logging);
  const defaults = {
    webserver: {
      protocol: "http",
      bind: "0.0.0.0",
      port: 3000
    }
  };

  if (typeof options.ssl !== "undefined") {
    config.webserver.protocol = options.ssl ? "https" : "http";
  }

  if (typeof options.cert !== "undefined") {
    config.webserver.sslCertPath = options.cert;
  }

  if (typeof options.certKey !== "undefined") {
    config.webserver.sslKeyPath = options.certKey;
  }

  if (typeof options.certCa !== "undefined") {
    config.webserver.caCertPath = options.certCa;
  }

  if (typeof options.configStore !== "undefined") {
    config.configStore = options.configStore;
  }

  if (typeof options.certificateStore !== "undefined") {
    config.certificateStore = options.certificateStore;
  }

  if (typeof options.firmwareStore !== "undefined") {
    config.firmwareStore = options.firmwareStore;
  }

  if (config.webserver.sslCertPath) {
    config.webserver.sslCertPath = resolve(
      config.config,
      config.webserver.sslCertPath
    );
  }
  if (config.webserver.sslKeyPath) {
    config.webserver.sslKeyPath = resolve(
      config.config,
      config.webserver.sslKeyPath
    );
  }
  if (config.webserver.caCertPath) {
    config.webserver.caCertPath = resolve(
      config.config,
      config.webserver.caCertPath
    );
  }
  if (config.certificateStore) {
    config.certificateStore = resolve(config.config, config.certificateStore);
  }
  if (config.firmwareStore) {
    config.firmwareStore = resolve(config.config, config.firmwareStore);
  }

  if (config.openSSL.bin) {
    config.openSSL.bin = resolve(config.config, config.openSSL.bin);
  }
  if (config.openSSL.configFile) {
    config.openSSL.configFile = resolve(
      config.config,
      config.openSSL.configFile
    );
  }
  if (config.openSSL.passwordFile) {
    config.openSSL.passwordFile = resolve(
      config.config,
      config.openSSL.passwordFile
    );
  }

  startServer({
    ...defaults,
    ...config,
    webserver: {
      ...defaults.webserver,
      ...config.webserver
    },
    openSSL: {
      ...config.openSSL
    }
  });
}

program.parse(process.argv);

bootstrap(program.opts()).catch((e) => {
  if (process.env.DEBUG) {
    console.error(e);
  } else {
    console.error(e.message);
  }
});
