import { hmacAuthorization, HMACRequest, sign } from "./hmac";
import { Devices } from "../types";
import { Response, NextFunction } from "express";

describe("hmac middleware", () => {
  let req: HMACRequest;
  let res: Response;
  let nextFunction: NextFunction;

  const devices: Devices = {
    abc123: {
      secretKey: "secret",
      firmware: [
        {
          type: "type",
          version: "version",
          config: "config",
          file: "firmware.bin"
        }
      ]
    }
  };

  const subject = () => {
    return hmacAuthorization(devices);
  };

  beforeEach(() => {
    nextFunction = jest.fn();
    res = {
      contentType: jest.fn(),
      sendFile: jest.fn(),
      sendStatus: jest.fn()
    } as unknown as Response;
  });

  describe("no authorization header", () => {
    beforeEach(() => {
      req = {
        get: jest.fn((header) => {
          switch (header) {
            case "x-firmware-version":
              return "1.0.0";
            default:
              return undefined;
          }
        })
      } as unknown as HMACRequest;
    });

    it("returns a 400", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(400);
    });

    it("sets an error message", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(nextFunction as jest.Mock).toBeCalledTimes(1);
      expect(nextFunction as jest.Mock).toHaveBeenCalledWith(expect.any(Error));

      expect(() => {
        throw (nextFunction as jest.Mock).mock.calls[0];
      }).toThrowError(/No authorization header found/);
    });
  });

  describe("no x-firmware-version header", () => {
    beforeEach(() => {
      req = {
        get: jest.fn((header) => {
          switch (header) {
            case "authorization":
              // eslint-disable-next-line quotes
              return 'Hmac key-id="abc123", signature="signature"';
            default:
              return undefined;
          }
        })
      } as unknown as HMACRequest;
    });

    it("returns a 401", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(401);
    });

    it("fallsback to the router", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(nextFunction as jest.Mock).toBeCalledTimes(1);
      expect(nextFunction as jest.Mock).toHaveBeenCalledWith("router");
    });
  });

  describe("Unsupported authorization header", () => {
    beforeEach(() => {
      req = {
        get: jest.fn((header) => {
          switch (header) {
            case "authorization":
              return "UNKNOWN abc.123";
            case "x-firmware-version":
              return "1.0.0";
            default:
              return undefined;
          }
        })
      } as unknown as HMACRequest;
    });

    it("returns a 400", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(400);
    });

    it("sets an error message", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(nextFunction as jest.Mock).toBeCalledTimes(1);
      expect(nextFunction as jest.Mock).toHaveBeenCalledWith(expect.any(Error));

      expect(() => {
        throw (nextFunction as jest.Mock).mock.calls[0];
      }).toThrowError(/Unsupported authorization method/);
    });
  });

  describe("Invalid Hmac authorization header", () => {
    beforeEach(() => {
      req = {
        get: jest.fn((header) => {
          switch (header) {
            case "authorization":
              return "Hmac abc.123";
            case "x-firmware-version":
              return "1.0.0";
            default:
              return undefined;
          }
        })
      } as unknown as HMACRequest;
    });

    it("returns a 401", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(401);
    });

    it("fallsback to the router", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(nextFunction as jest.Mock).toBeCalledTimes(1);
      expect(nextFunction as jest.Mock).toHaveBeenCalledWith("router");
    });
  });

  describe("Unparsable created-at header", () => {
    beforeEach(() => {
      const created = new Date(new Date().getTime() - 60 * 60 * 1000);
      const expiry = new Date(created.getTime() + 15 * 60 * 1000);

      const message = `get\npath\n${created.toISOString()}\n${expiry.toISOString()}`;
      const signature = sign(message, "secret");

      req = {
        method: "get",
        path: "path",
        get: jest.fn((header) => {
          switch (header) {
            case "authorization":
              return `Hmac key-id="abc123", signature="${signature}"`;
            case "created-at":
              return "Hello!";
            case "expiry":
              return expiry.toISOString();
            case "x-firmware-version":
              return "1.0.0";
            default:
              return undefined;
          }
        })
      } as unknown as HMACRequest;
    });

    it("returns a 400", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(400);
    });

    it("sets an error message", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(nextFunction as jest.Mock).toBeCalledTimes(1);
      expect(nextFunction as jest.Mock).toHaveBeenCalledWith(expect.any(Error));

      expect(() => {
        throw (nextFunction as jest.Mock).mock.calls[0];
      }).toThrowError(/Invalid created-at date/);
    });
  });

  describe("Unparsable expiry header", () => {
    beforeEach(() => {
      const created = new Date(new Date().getTime() - 60 * 60 * 1000);
      const expiry = new Date(created.getTime() + 15 * 60 * 1000);

      const message = `get\npath\n${created.toISOString()}\n${expiry.toISOString()}`;
      const signature = sign(message, "secret");

      req = {
        method: "get",
        path: "path",
        get: jest.fn((header) => {
          switch (header) {
            case "authorization":
              return `Hmac key-id="abc123", signature="${signature}"`;
            case "created-at":
              return created.toISOString();
            case "expiry":
              return "hello!";
            case "x-firmware-version":
              return "1.0.0";
            default:
              return undefined;
          }
        })
      } as unknown as HMACRequest;
    });

    it("returns a 400", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(400);
    });

    it("sets an error message", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(nextFunction as jest.Mock).toBeCalledTimes(1);
      expect(nextFunction as jest.Mock).toHaveBeenCalledWith(expect.any(Error));

      expect(() => {
        throw (nextFunction as jest.Mock).mock.calls[0];
      }).toThrowError(/Invalid expiry/);
    });
  });

  describe("Expired authorization header", () => {
    beforeEach(() => {
      const created = new Date(new Date().getTime() - 60 * 60 * 1000);
      const expiry = new Date(created.getTime() + 15 * 60 * 1000);

      const message = `get\npath\n${created.toISOString()}\n${expiry.toISOString()}`;
      const signature = sign(message, "secret");

      req = {
        method: "get",
        path: "path",
        get: jest.fn((header) => {
          switch (header) {
            case "authorization":
              return `Hmac key-id="abc123", signature="${signature}"`;
            case "created-at":
              return created.toISOString();
            case "expiry":
              return expiry.toISOString();
            case "x-firmware-version":
              return "1.0.0";
            default:
              return undefined;
          }
        })
      } as unknown as HMACRequest;
    });

    it("returns a 401", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
      expect(res.sendStatus as jest.Mock).toBeCalledWith(401);
    });

    it("sets an error message", () => {
      const middleware = subject();
      middleware(req, res, nextFunction);

      expect(nextFunction as jest.Mock).toBeCalledTimes(1);
      expect(nextFunction as jest.Mock).toHaveBeenCalledWith(expect.any(Error));

      expect(() => {
        throw (nextFunction as jest.Mock).mock.calls[0];
      }).toThrowError(/Authorization header has expired/);
    });
  });

  describe("Valid Hmac authorization header", () => {
    describe("Unknown device", () => {
      beforeEach(() => {
        const created = new Date();
        const expiry = new Date(created.getTime() + 15 * 60 * 1000);

        const message = `get\npath\n${created.toISOString()}\n${expiry.toISOString()}`;
        const signature = sign(message, "secret");

        req = {
          method: "get",
          path: "path",
          get: jest.fn((header) => {
            switch (header) {
              case "authorization":
                return `Hmac key-id="xyz123", signature="${signature}"`;
              case "created-at":
                return created.toISOString();
              case "expiry":
                return expiry.toISOString();
              case "x-firmware-version":
                return "1.0.0";
              default:
                return undefined;
            }
          })
        } as unknown as HMACRequest;
      });

      it("returns a 401", () => {
        const middleware = subject();
        middleware(req, res, nextFunction);

        expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
        expect(res.sendStatus as jest.Mock).toBeCalledWith(401);
      });

      it("fallsback to the router", () => {
        const middleware = subject();
        middleware(req, res, nextFunction);

        expect(nextFunction as jest.Mock).toBeCalledTimes(1);
        expect(nextFunction as jest.Mock).toHaveBeenCalledWith("router");
      });
    });

    describe("Invalid signature", () => {
      beforeEach(() => {
        const created = new Date();
        const expiry = new Date(created.getTime() + 15 * 60 * 1000);

        const message = `get\npath\n${created.toISOString()}\n${expiry.toISOString()}`;
        const signature = sign(message, "notsecret");

        req = {
          method: "get",
          path: "path",
          get: jest.fn((header) => {
            switch (header) {
              case "authorization":
                return `Hmac key-id="abc123", signature="${signature}"`;
              case "created-at":
                return created.toISOString();
              case "expiry":
                return expiry.toISOString();
              case "x-firmware-version":
                return "1.0.0";
              default:
                return undefined;
            }
          })
        } as unknown as HMACRequest;
      });

      it("returns a 401", () => {
        const middleware = subject();
        middleware(req, res, nextFunction);

        expect(res.sendStatus as jest.Mock).toBeCalledTimes(1);
        expect(res.sendStatus as jest.Mock).toBeCalledWith(401);
      });

      it("fallsback to the router", () => {
        const middleware = subject();
        middleware(req, res, nextFunction);

        expect(nextFunction as jest.Mock).toBeCalledTimes(1);
        expect(nextFunction as jest.Mock).toHaveBeenCalledWith("router");
      });
    });

    describe("Valid signature", () => {
      beforeEach(() => {
        const version = "1.0.0";
        const created = new Date();
        const expiry = new Date(created.getTime() + 15 * 60 * 1000);

        const message = `get\npath\n${version}\n${created.toISOString()}\n${expiry.toISOString()}`;
        const signature = sign(message, "secret");

        req = {
          method: "get",
          path: "path",
          get: jest.fn((header) => {
            switch (header) {
              case "authorization":
                return `Hmac key-id="abc123", signature="${signature}"`;
              case "created-at":
                return created.toISOString();
              case "expiry":
                return expiry.toISOString();
              case "x-firmware-version":
                return version;
              default:
                return undefined;
            }
          })
        } as unknown as HMACRequest;
      });

      it("sets the device", () => {
        const middleware = subject();
        middleware(req, res, nextFunction);
        expect(req.device).toEqual("abc123");
      });

      it("passes to the next middleware in the chain", () => {
        const middleware = subject();
        middleware(req, res, nextFunction);

        expect(nextFunction as jest.Mock).toBeCalledTimes(1);
        expect(nextFunction as jest.Mock).toHaveBeenCalledWith();
      });
    });
  });
});

describe("sign", () => {
  let message: string | Buffer;
  let secret: string;

  const subject = () => sign(message, secret);

  it("signs strings", () => {
    message = "get\npath\n2021-04-08T11:00:21\n2021-04-08T11:15:21";
    secret = "secret";
    expect(subject()).toEqual("SpzyqqImicOLKO9ZwhB+kk4/gM32+wd+I6h6Si6BW/s=");
  });

  it("signs Buffers", () => {
    message = Buffer.from(
      "get\npath\n2021-04-08T11:00:21\n2021-04-08T11:15:21",
      "utf8"
    );
    secret = "secret";
    expect(subject()).toEqual("SpzyqqImicOLKO9ZwhB+kk4/gM32+wd+I6h6Si6BW/s=");
  });
});
