import { LoggerConfig } from "config";
import { Logger, createLogger } from "winston";

const winston = require("winston");
// eslint-disable-next-line no-unused-expressions
require("winston-syslog").Syslog;

export function reconfigureLogger(
  instance: Logger,
  config: LoggerConfig | undefined
) {
  instance.clear();

  let hasLogger = false;

  if (config) {
    if (config.console) {
      hasLogger = true;
      instance.add(
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          ),
          ...config.console
        })
      );
    }
    if (config.file) {
      hasLogger = true;
      instance.add(new winston.transports.File(config.file));
    }
    if (config.syslog) {
      hasLogger = true;
      instance.add(new winston.transports.Syslog(config.syslog));
    }
  }

  if (!hasLogger) {
    instance.add(new winston.transports.Console({ silent: true }));
  }
}

export const logger = createLogger({
  transports: [new winston.transports.Console({ silent: true })]
});
