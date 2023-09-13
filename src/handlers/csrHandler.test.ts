import { Response } from "express";
import { HMACRequest, sign } from "../middleware/hmac";
import { csrHandler } from "./csrHandler";
import { readFile, writeFile } from "fs/promises";
import _rimraf from "rimraf";
import { join } from "path";

async function rimraf(path: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    _rimraf(path, (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

describe("csrHandler", () => {
  let req: HMACRequest;
  let res: Response;
  let certificatePath: string;
  let openSSLPath: string;
  let device: string;
  let csr: string;

  beforeAll(async () => {
    const confTemplate = await readFile(
      join(__dirname, "..", "test", "ca", "intermediate", "openssl.cnf.tmpl")
    );
    const rendered = confTemplate
      .toString()
      .replace(
        "{{directory}}",
        join(__dirname, "..", "test", "ca", "intermediate")
      );
    await writeFile(
      join(__dirname, "..", "test", "ca", "intermediate", "openssl.cnf"),
      rendered
    );
  });

  beforeEach(async () => {
    certificatePath = join(__dirname, "..", "test", "tls");
    openSSLPath = join(__dirname, "..", "test", "ca", "intermediate");

    // Reset the open ssl certificate state
    await rimraf(join(openSSLPath, "newcerts", "*.pem"));
    await rimraf(join(openSSLPath, "index.txt*"));
    await rimraf(join(openSSLPath, "serial*"));
    await rimraf(join(openSSLPath, "crlnumber*"));
    await rimraf(join(openSSLPath, "crl.pem"));
    await writeFile(join(openSSLPath, "serial"), "1000");
    await writeFile(join(openSSLPath, "index.txt"), "");
    await writeFile(join(openSSLPath, "crlnumber"), "1000");

    device = "abc123";
    csr = (
      await readFile(join(openSSLPath, "private", "abc123.csr.pem"))
    ).toString("utf-8");
    req = { device, body: csr } as HMACRequest;
    res = {
      contentType: jest.fn(),
      send: jest.fn(),
      sendStatus: jest.fn(),
      set: jest.fn()
    } as unknown as Response;
  });

  const subject = () =>
    csrHandler(
      certificatePath,
      {
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
      },
      {
        configFile: join(openSSLPath, "openssl.cnf"),
        passwordFile: join(openSSLPath, ".pass")
      }
    );

  describe("When a valid CSR is sent for the first time", () => {
    it("creates a certificate", async () => {
      const handler = subject();
      await handler(req, res);

      const saved = await readFile(join(certificatePath, "abc123.cert.pem"));
      const reference = await readFile(
        join(openSSLPath, "newcerts", "1000.pem")
      );

      expect(saved.toString("utf-8")).toEqual(reference.toString("utf-8"));

      expect(res.send as jest.Mock).toBeCalledTimes(1);
      expect(res.send as jest.Mock).toBeCalledWith(saved.toString("utf-8"));
    });

    it("signs the payload", async () => {
      const handler = subject();
      await handler(req, res);

      expect(res.set as jest.Mock).toBeCalledTimes(3);

      const created = (res.set as jest.Mock).mock.calls[0][1] as string;
      const expires = (res.set as jest.Mock).mock.calls[1][1] as string;

      const data = await readFile(join(certificatePath, "abc123.cert.pem"));
      const message = `${data.toString("utf-8")}\n${created}\n${expires}`;
      const signature = sign(message, "secret");

      expect(res.set as jest.Mock).toBeCalledWith("signature", signature);
    });

    it("increments the serial", async () => {
      const handler = subject();
      await handler(req, res);
      const serial = await readFile(join(openSSLPath, "serial"));
      expect(serial.toString("utf-8").trim()).toEqual("1001");
    });

    it("stores the certificate in the db", async () => {
      const handler = subject();
      await handler(req, res);
      const db = await readFile(join(openSSLPath, "index.txt"));
      const [status, _a, _b, index, _c, cn] = db
        .toString("utf-8")
        .trim()
        .split("\t");
      expect(status).toEqual("V");
      expect(index).toEqual("1000");
      expect(cn).toEqual(
        "/C=AU/ST=Victoria/O=Providore/OU=Test/CN=abc123/emailAddress=test@example.com"
      );
    });
  });

  describe("Same device requests a second certificate", () => {
    it("creates a second certificate", async () => {
      const handler = subject();
      await handler(req, res);
      await handler(req, res);

      const saved = await readFile(join(certificatePath, "abc123.cert.pem"));
      const reference = await readFile(
        join(openSSLPath, "newcerts", "1001.pem")
      );

      expect(saved.toString("utf-8")).toEqual(reference.toString("utf-8"));

      expect(res.send as jest.Mock).toBeCalledTimes(2);
      expect(res.send as jest.Mock).toBeCalledWith(saved.toString("utf-8"));
    });

    it("stores the certificate in the db", async () => {
      const handler = subject();
      await handler(req, res);
      await handler(req, res);
      const db = await readFile(join(openSSLPath, "index.txt"));
      const [_first, last] = db
        .toString("utf-8")
        .trim()
        .split("\n")
        .map((line) => line.split("\t"));

      const [status, _a, _b, index, _c, cn] = last;
      expect(status).toEqual("V");
      expect(index).toEqual("1001");
      expect(cn).toEqual(
        "/C=AU/ST=Victoria/O=Providore/OU=Test/CN=abc123/emailAddress=test@example.com"
      );
    });

    it("revokes the first certificate", async () => {
      const handler = subject();
      await handler(req, res);
      await handler(req, res);
      const db = await readFile(join(openSSLPath, "index.txt"));
      const [first, _last] = db
        .toString("utf-8")
        .trim()
        .split("\n")
        .map((line) => line.split("\t"));

      const [status, _a, _b, index, _c, cn] = first;
      expect(status).toEqual("R");
      expect(index).toEqual("1000");
      expect(cn).toEqual(
        "/C=AU/ST=Victoria/O=Providore/OU=Test/CN=abc123/emailAddress=test@example.com"
      );
    });
  });
});
