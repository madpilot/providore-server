import { checkUpdateHandler, firmwareHandler } from "./firmwareHandler";
import path, { join } from "path";
import { Response } from "express";
import { HMACRequest, sign } from "../middleware/hmac";

import { readFile } from "fs/promises";
import { FirmwareParams } from "types";

class MockError extends Error {
  public message: string;
  public code: string;

  public constructor(message: string, code: string) {
    super(message);
    this.message = message;
    this.code = code;
  }
}

describe("firmwareHandler", () => {
  const storePath = join(__dirname, "..", "test", "store");
  const subject = () =>
    firmwareHandler(storePath, {
      abc123: {
        secretKey: "secret",
        firmware: [
          {
            type: "type",
            version: "1.0.0",
            config: "config",
            file: "firmware.bin"
          },
          {
            type: "type",
            version: "1.0.1",
            config: "config",
            file: "firmware.bin"
          },
          {
            type: "type",
            version: "2.0.0",
            config: "config",
            file: "firmware.bin"
          }
        ]
      }
    });

  let req: HMACRequest<FirmwareParams>;
  let res: Response;
  let device: string;

  beforeEach(() => {
    res = {
      contentType: jest.fn(),
      sendFile: jest.fn(),
      sendStatus: jest.fn(),
      set: jest.fn()
    } as unknown as Response;
  });

  describe("when the device does not exist", () => {
    beforeEach(() => {
      device = "xyz123";
      req = { device } as HMACRequest;
    });

    it("returns a 404", async () => {
      res.sendFile = jest.fn().mockImplementation(() => {
        throw new MockError("", "ENOENT");
      });

      const handler = subject();
      await handler(req, res);

      expect(res.sendFile as jest.Mock).toBeCalledTimes(0);
      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(404);
    });
  });
  describe("when the device exists", () => {
    beforeEach(() => {
      device = "abc123";
      req = { device } as HMACRequest;
    });

    it("sets the content type to application/octet-stream", async () => {
      const handler = subject();
      await handler(req, res);
      expect(res.contentType as jest.Mock).toBeCalledTimes(1);
      expect(res.contentType as jest.Mock).toBeCalledWith(
        "application/octet-stream"
      );
    });

    describe("no version is supplied", () => {
      describe("when the file is found", () => {
        it("return the newest firmware", async () => {
          const handler = subject();
          await handler(req, res);

          expect(res.sendFile as jest.Mock).toBeCalledTimes(1);
          expect(res.sendFile as jest.Mock).toBeCalledWith(
            path.join(storePath, "type/2.0.0/firmware.bin")
          );
        });

        it("signs the payload", async () => {
          const handler = subject();
          await handler(req, res);

          expect(res.set as jest.Mock).toBeCalledTimes(3);

          const created = (res.set as jest.Mock).mock.calls[0][1] as string;
          const expires = (res.set as jest.Mock).mock.calls[1][1] as string;

          const data = await readFile(
            path.join(storePath, "type/2.0.0/firmware.bin")
          );
          const message = `${data.toString("utf-8")}\n${created}\n${expires}`;
          const signature = sign(message, "secret");

          expect(res.set as jest.Mock).toBeCalledWith("signature", signature);
        });
      });
    });

    describe("a version is supplied", () => {
      beforeEach(() => {
        const version = "1.0.0";
        req = { device, params: { version } } as HMACRequest<FirmwareParams>;
      });

      describe("when the version is found", () => {
        it("returns the firmware corresponding to the version number", async () => {
          const handler = subject();
          await handler(req, res);

          expect(res.sendFile as jest.Mock).toBeCalledTimes(1);
          expect(res.sendFile as jest.Mock).toBeCalledWith(
            path.join(storePath, "type/1.0.0/firmware.bin")
          );
        });

        it("signs the payload", async () => {
          const handler = subject();
          await handler(req, res);

          expect(res.set as jest.Mock).toBeCalledTimes(3);

          const created = (res.set as jest.Mock).mock.calls[0][1] as string;
          const expires = (res.set as jest.Mock).mock.calls[1][1] as string;

          const data = await readFile(
            path.join(storePath, "type/1.0.0/firmware.bin")
          );
          const message = `${data.toString("utf-8")}\n${created}\n${expires}`;
          const signature = sign(message, "secret");

          expect(res.set as jest.Mock).toBeCalledWith("signature", signature);
        });
      });

      describe("when the version is not found", () => {
        beforeEach(() => {
          const version = "4.0.0";
          req = { device, params: { version } } as HMACRequest<FirmwareParams>;
        });

        it("returns a 404", async () => {
          res.sendFile = jest.fn().mockImplementation(() => {
            throw new MockError("", "ENOENT");
          });

          const handler = subject();
          await handler(req, res);

          expect(res.sendFile as jest.Mock).toBeCalledTimes(0);
          expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
          expect(res.sendStatus as jest.Mock).toBeCalledWith(404);
        });
      });
    });
  });

  describe("when the file is not found", () => {
    beforeEach(() => {
      device = "abc123";
      req = { device } as HMACRequest<FirmwareParams>;
    });

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
    beforeEach(() => {
      device = "abc123";
      req = { device } as HMACRequest<FirmwareParams>;
    });

    it("returns a 500", async () => {
      res.sendFile = jest.fn().mockImplementation(() => {
        throw new MockError("Other Error", "Other");
      });

      const handler = subject();
      await handler(req, res);

      expect(res.sendFile as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(500);
    });
  });
});

describe("checkUpdateHandler", () => {
  const subject = () =>
    checkUpdateHandler({
      abc123: {
        secretKey: "secret",
        firmware: [
          {
            type: "type",
            version: "1.0.0",
            config: "config",
            file: "firmware.bin",
            next: "1.0.1"
          },
          {
            type: "type",
            version: "1.0.1",
            config: "config",
            file: "firmware.bin",
            next: "2.0.0"
          },
          {
            type: "type",
            version: "2.0.0",
            config: "config",
            file: "firmware.bin"
          }
        ]
      }
    });

  let req: HMACRequest;
  let res: Response;
  let device: string;

  beforeEach(() => {
    res = {
      sendStatus: jest.fn(),
      redirect: jest.fn()
    } as unknown as Response;
  });

  describe("when the device does not exist", () => {
    beforeEach(() => {
      device = "xyz123";
      req = { device } as HMACRequest;
    });

    it("returns a 404", async () => {
      const handler = subject();
      await handler(req, res);
      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(404);
    });
  });
  describe("when the device exists", () => {
    beforeEach(() => {
      device = "abc123";
      req = { device, get: (_str) => undefined } as HMACRequest;
    });

    describe("no version is supplied", () => {
      it("returns a 404", async () => {
        const handler = subject();
        await handler(req, res);
        expect(res.sendStatus as jest.Mock).toBeCalledWith(404);
      });
    });

    describe("a version is supplied", () => {
      beforeEach(() => {
        const version = "1.0.0";
        req = {
          device,
          get: (str) => ({ "x-firmware-version": version }[str])
        } as HMACRequest;
      });

      describe("when there is an update", () => {
        it("returns a redirect to the new firmware", async () => {
          const handler = subject();
          await handler(req, res);

          expect(res.redirect as jest.Mock).toBeCalledWith(
            "/firmware?version=1.0.1",
            302
          );
        });
      });

      describe("when a new version is not found", () => {
        beforeEach(() => {
          const version = "2.0.0";
          req = {
            device,
            get: (str) => ({ "x-firmware-version": version }[str])
          } as HMACRequest;
        });

        it("returns a 204", async () => {
          const handler = subject();
          await handler(req, res);

          expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
          expect(res.sendStatus as jest.Mock).toBeCalledWith(204);
        });
      });
    });
  });
});
