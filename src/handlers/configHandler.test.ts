import { configHandler } from "./configHandler";
import path, { join } from "path";
import { Response } from "express";
import { HMACRequest, sign } from "../middleware/hmac";

import { readFile } from "fs/promises";

class MockError extends Error {
  public message: string;
  public code: string;

  public constructor(message: string, code: string) {
    super(message);
    this.message = message;
    this.code = code;
  }
}

describe("configHandler", () => {
  const storePath = join(__dirname, "..", "test", "store");
  const subject = () =>
    configHandler(storePath, {
      abc123: {
        secretKey: "secret",
        firmware: [
          {
            type: "type",
            version: "1.0.0",
            config: "1.0.0.json",
            file: "firmware.bin",
            next: "2.0.0"
          },
          {
            type: "type",
            version: "2.0.0",
            config: "2.0.0.json",
            file: "firmware.bin"
          }
        ]
      }
    });

  let req: HMACRequest;
  let res: Response;
  let device: string;
  let version: string;

  beforeEach(() => {
    device = "abc123";
    version = "1.0.0";
    req = {
      device,
      get: (str) => ({ "x-firmware-version": version }[str])
    } as HMACRequest;
    res = {
      contentType: jest.fn(),
      sendFile: jest.fn(),
      sendStatus: jest.fn(),
      set: jest.fn()
    } as unknown as Response;
  });

  describe("no params", () => {
    it("returns a 400", async () => {
      req = { device, get: () => undefined } as unknown as HMACRequest;
      const handler = subject();
      await handler(req, res);

      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(400);
    });
  });

  describe("when the file is found", () => {
    it("returns a 200", async () => {
      const handler = subject();
      await handler(req, res);

      expect(res.sendFile as jest.Mock).toBeCalledTimes(1);
      expect(res.sendFile as jest.Mock).toBeCalledWith(
        path.join(storePath, "abc123/1.0.0.json")
      );
    });

    it("signs the payload", async () => {
      const handler = subject();
      await handler(req, res);

      expect(res.set as jest.Mock).toBeCalledTimes(3);

      const created = (res.set as jest.Mock).mock.calls[0][1] as string;
      const expires = (res.set as jest.Mock).mock.calls[1][1] as string;

      const data = await readFile(path.join(storePath, "abc123/1.0.0.json"));
      const message = `${data.toString("utf-8")}\n${created}\n${expires}`;
      const signature = sign(message, "secret");

      expect(res.set as jest.Mock).toBeCalledWith("signature", signature);
    });
  });

  describe("when the file is not found", () => {
    it("returns a 404", async () => {
      res.sendFile = jest.fn().mockImplementation(() => {
        throw new MockError("", "ENOENT");
      });

      const handler = subject();
      await handler(req, res);

      expect(res.sendFile as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(404);
    });
  });

  describe("when there is an error reading the file", () => {
    it("returns a 500", async () => {
      res.sendFile = jest.fn().mockImplementation(() => {
        throw new MockError("Other Error", "Other");
      });

      const handler = subject();
      await handler(req, res);

      expect(res.sendFile as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(500);
    });
  });
});
