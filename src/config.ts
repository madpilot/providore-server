import { readFile, stat } from "fs/promises";
import { logger } from "./logger";
import { SyslogTransportOptions } from "winston-syslog";
import {
  ConsoleTransportOptions,
  FileTransportOptions
} from "winston/lib/winston/transports";
export interface HTTPConfig {
  protocol: "http" | "https";
  bind: string;
  port: number;
  sslCertPath?: string | undefined;
  sslKeyPath?: string | undefined;
  caCertPath?: string | undefined;
}

export interface StoreConfig {
  configStore: string;
  deviceStore: string | undefined;
  firmwareStore?: string | undefined;
  certificateStore?: string | undefined;
}

export interface LoggerConfig {
  syslog?: SyslogTransportOptions;
  file?: FileTransportOptions;
  console?: ConsoleTransportOptions;
}

export interface OpenSSLConfig {
  bin?: string;
  passwordFile?: string;
  configFile?: string;
}

export interface Config extends StoreConfig {
  config: string;
  webserver: HTTPConfig;
  logging: LoggerConfig;
  openSSL: OpenSSLConfig;
}

const CONFIG_PATHS = ["/etc/providore", `${process.env.HOME}/.providore`];

export async function resolveConfigPaths(
  filename: string,
  pathCascade = CONFIG_PATHS
): Promise<string | undefined> {
  while (pathCascade.length > 0) {
    try {
      const path = pathCascade.shift();
      await stat(`${path}/${filename}`);
      return `${path}/${filename}`;
    } catch (e: any) {
      if (e.code !== "ENOENT") {
        logger.warn(`Unable to resolve file ${e.message}`);
      }
    }
  }
  return undefined;
}

export async function load(config: string | undefined): Promise<Config> {
  const pathCascade = [...CONFIG_PATHS];
  let configFile: string | undefined;
  if (config) {
    configFile = config;
  } else {
    configFile = await resolveConfigPaths("config.json", pathCascade);
  }

  if (configFile) {
    const data = await readFile(configFile, {
      encoding: "utf-8"
    });
    return { ...JSON.parse(data), config: configFile };
  } else {
    throw new Error("Configuration file not found");
  }
}
