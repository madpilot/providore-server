import { NextFunction, Request, Response } from "express";
import crypto from "crypto";
import { isPast, parseISO } from "date-fns";
import { logger } from "../logger";
import * as core from "express-serve-static-core";
import { Devices } from "../types";

interface AuthorizationObject {
  "key-id": string;
  signature: string;
}

function isAuthorizationObject(obj: any): obj is AuthorizationObject {
  return (
    typeof obj["key-id"] !== "undefined" && typeof obj.signature !== "undefined"
  );
}

export interface HMACRequest<
  P = core.ParamsDictionary,
  ResBody = any,
  ReqBody = any,
  ReqQuery = core.Query,
  Locals extends Record<string, any> = Record<string, any>
> extends Request<P, ResBody, ReqBody, ReqQuery, Locals> {
  device?: string;
}

export function sign(message: string | Buffer, secret: string): string {
  let buffer: Buffer;
  if (message instanceof Buffer) {
    buffer = message;
  } else {
    buffer = Buffer.from(message, "utf8");
  }
  const hash = crypto.createHmac("sha256", secret);
  hash.update(buffer);
  return hash.digest("base64");
}

export function signPayload(
  res: Response,
  payload: string | Buffer,
  secret: string
): void {
  const created = new Date();
  const expires = new Date(created.getTime() + 15 * 60 * 1000);

  const message = `${payload.toString(
    "utf-8"
  )}\n${created.toISOString()}\n${expires.toISOString()}`;
  const signature = sign(message, secret);

  res.set("created-at", created.toISOString());
  res.set("expiry", expires.toISOString());
  res.set("signature", signature);
}

export function hmacAuthorization(devices: Devices) {
  return (req: HMACRequest, res: Response, next: NextFunction): void => {
    const authorizationHeader = req.get("authorization");

    if (!authorizationHeader) {
      res.sendStatus(400);
      return next(new Error("No authorization header found"));
    }

    const [type, ...mac] = authorizationHeader.split(" ");

    if (type !== "Hmac") {
      res.sendStatus(400);
      return next(new Error("Unsupported authorization method"));
    }

    const authorization = mac
      .join(" ")
      .split(", ")
      .map((kv) => {
        const [key, ...values] = kv.replace(/"/g, "").split("=");
        return [key, values.join("=")];
      })
      .reduce<Record<string, string>>(
        (t, [key, value]) => ({ ...t, [key]: value }),
        {}
      );

    if (!isAuthorizationObject(authorization)) {
      logger.error("Invalid authorization header");
      res.sendStatus(401);
      return next("router");
    }

    const version = req.get("x-firmware-version");
    if (!version) {
      logger.error("Missing x-firmware-version header");
      res.sendStatus(401);
      return next("router");
    }

    const requestCreatedAt = req.get("created-at");
    if (!requestCreatedAt) {
      logger.error("Missing created-at header");
      res.sendStatus(401);
      return next("router");
    }
    const created = parseISO(requestCreatedAt);
    if (created.toString() === "Invalid Date") {
      res.sendStatus(400);
      return next(new Error("Invalid created-at date"));
    }

    const requestExpiry = req.get("expiry");
    if (!requestExpiry) {
      logger.error("Missing expiry header");
      res.sendStatus(401);
      return next("router");
    }

    const expiry = parseISO(requestExpiry);
    if (expiry.toString() === "Invalid Date") {
      res.sendStatus(400);
      return next(new Error("Invalid expiry"));
    }

    if (isPast(expiry)) {
      res.sendStatus(401);
      return next(new Error("Authorization header has expired"));
    }

    const device = devices[authorization["key-id"]];
    if (!device) {
      logger.error("Device not found");
      res.sendStatus(401);
      return next("router");
    }

    const message = `${req.method}\n${
      req.path
    }\n${version}\n${requestCreatedAt}\n${req.get("expiry")}`;

    const signature = sign(message, device.secretKey);

    if (signature !== authorization.signature) {
      logger.error("Invalid signature");
      res.sendStatus(401);
      return next("router");
    }

    req.device = authorization["key-id"];
    next();
  };
}
