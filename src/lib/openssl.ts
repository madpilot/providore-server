import { spawn } from "child_process";
import { file, FileResult } from "tmp-promise";
import { createWriteStream, PathLike } from "fs";
import { logger } from "../logger";
import { OpenSSLConfig } from "config";
import { readFile } from "fs/promises";
import { dirname } from "path";

type CertificateStatus = "valid" | "revoked" | "expired";
interface CertificateRecord {
  status: CertificateStatus;
  expiration: Date;
  revokation: Date;
  serial: string;
  subject: string;
}

interface TemporaryFile {
  file: FileResult;
  content: Buffer;
}

function isString(obj: any): obj is string {
  return typeof obj === "string";
}

function splitParameters(
  parameters: string | Array<string | Buffer>
): Array<string | Buffer> {
  if (isString(parameters)) {
    return parameters.split(" ");
  }
  return parameters;
}

async function resolveParameters(
  param: string | Buffer
): Promise<string | TemporaryFile> {
  if (isString(param)) {
    return Promise.resolve(param);
  } else {
    const p = await file();
    return {
      file: p,
      content: param
    };
  }
}

export async function openssl(
  params: string | Array<string | Buffer>,
  bin = "openssl"
): Promise<string> {
  const stdout: Array<string> = [];
  const stderr: Array<string> = [];

  const resolved = await Promise.all(
    splitParameters(params).map(resolveParameters)
  );

  // Write out all the tmp files
  await Promise.all(
    resolved
      .filter((v) => !isString(v))
      .map(async (v) => {
        if (!isString(v)) {
          const stream = createWriteStream(
            null as unknown as PathLike, // Null is valid when there is a file descriptor
            { fd: v.file.fd }
          );

          await new Promise<void>((resolve, reject) => {
            stream.write(v.content, (err) => {
              if (err) {
                reject(err);
              } else {
                resolve();
              }
            });
          });

          stream.close();
        }
      })
  );

  const args = resolved.map((v) => (isString(v) ? v : v.file.path));
  logger.debug(`Spawning '${bin} ${args.join(" ")}'`);
  const openSSLProcess = spawn(bin, args);

  openSSLProcess.stdout.on("data", (data) => {
    stdout.push(data);
  });

  openSSLProcess.stderr.on("data", (data) => {
    stderr.push(data);
  });

  // eslint-disable-next-line unused-imports/no-unused-vars
  return new Promise((resolve, reject) => {
    openSSLProcess.on("close", (code) => {
      const files = resolved.filter((v) => !isString(v));

      logger.debug(`Process returned ${code}`);
      if (files.length > 0) {
        logger.debug(
          `Removing temp files: ${files
            .map((v) => !isString(v) && v.file.path)
            .join(" | ")}`
        );
      }
      resolved.forEach((v) => !isString(v) && v.file.cleanup());

      if (code !== 0) {
        if (stderr.length > 0) {
          reject(Error(stderr.join("\n")));
        } else if (stdout.length > 0) {
          reject(Error(stdout.join("\n")));
        } else {
          reject(Error("Error processsing CSR"));
        }
      } else {
        resolve(stdout.join("\n"));
      }
    });
  });
}

function certificateStatus(status: string): CertificateStatus {
  if (status === "V") {
    return "valid";
  }
  if (status === "E") {
    return "expired";
  }
  return "revoked";
}

function parseDatabaseFile(
  certificates: Array<CertificateRecord>,
  line: string
): Array<CertificateRecord> {
  const [status, expiration, revokation, serial, _filename, subject] =
    line.split(/\t/);

  if (status) {
    const certificate: CertificateRecord = {
      status: certificateStatus(status),
      expiration: new Date(Date.parse(expiration)),
      revokation: new Date(Date.parse(revokation)),
      serial,
      subject
    };
    return [...certificates, certificate];
  }

  return certificates;
}

function parseCnFromSubject(subject: string): string | undefined {
  const str = subject.split("/").find((part) => part.indexOf("CN=") === 0);
  if (str) {
    const [_, cn] = str.split("=");
    return cn;
  }
  return undefined;
}

function filterOnCn(cn: string): (certificate: CertificateRecord) => boolean {
  return (certificate) => parseCnFromSubject(certificate.subject) === cn;
}

async function getCertificatesFromDatabase(
  cn: string,
  config: OpenSSLConfig
): Promise<Array<CertificateRecord>> {
  if (!config.configFile) {
    throw new Error("No Open SSL config file set");
  }
  if (!config.passwordFile) {
    throw new Error("No Open SSL password file set");
  }

  // Update the DB first
  await updateDB(config);
  const configDir = dirname(config.configFile);
  const file = await readFile(`${configDir}/index.txt`);

  return file
    .toString("utf-8")
    .split("\n")
    .reduce(parseDatabaseFile, [])
    .filter(filterOnCn(cn));
}

async function flavour({
  // eslint-disable-next-line unused-imports/no-unused-vars
  bin
}: OpenSSLConfig): Promise<"OpenSSL" | "LibreSSL"> {
  const result = await openssl(["version"]);
  const [name] = result.split(" ");
  if (name !== "OpenSSL" && name !== "LibreSSL") {
    throw new Error(`Unknown flavour of OpenSSL: ${name}`);
  }
  return name;
}

export async function getCSRSubject(
  csr: string,
  { bin }: OpenSSLConfig
): Promise<string> {
  const result = await openssl(
    ["req", "-noout", "-subject", "-in", Buffer.from(csr)],
    bin
  );
  const f = await flavour({ bin });
  // Probably backwards, but the LibreSSL version is easier to parse, and is the same format as index.txt
  if (f === "OpenSSL") {
    return result
      .replace(/subject=/, "subject=/")
      .replace(/ = /g, "=")
      .replace(/, /g, "/");
  } else {
    return result;
  }
}

export async function updateDB({
  bin,
  passwordFile,
  configFile
}: OpenSSLConfig): Promise<void> {
  if (!configFile) {
    throw new Error("No Open SSL config file set");
  }
  if (!passwordFile) {
    throw new Error("No Open SSL password file set");
  }

  logger.info("Updating the certificate database");

  const stdio = await openssl(
    [
      "ca",
      "-config",
      `${configFile}`,
      "-passin",
      `file:${passwordFile}`,
      "-updatedb"
    ],
    bin
  );

  if (stdio.length > 0) {
    logger.info(stdio);
  }
}

export async function sign(
  csr: string,
  device: string,
  certificateStore: string,
  { bin, passwordFile, configFile }: OpenSSLConfig
): Promise<string> {
  if (!configFile) {
    throw new Error("No Open SSL config file set");
  }
  if (!passwordFile) {
    throw new Error("No Open SSL password file set");
  }

  const subject = await getCSRSubject(csr, { bin });
  logger.debug(`Subject: ${subject}`);
  const cn = parseCnFromSubject(subject);
  if (!cn) {
    throw new Error("CN not found in the CSR");
  }
  if (cn !== device) {
    throw new Error("CN does not match the device name");
  }
  logger.debug(`Checking certificate database for CN=${cn}`);

  const certificates = await getCertificatesFromDatabase(cn, {
    bin,
    passwordFile,
    configFile
  });

  await Promise.all(
    certificates
      .filter((certificate) => certificate.status === "valid")
      .map((certificate) =>
        revoke(certificate.serial, { bin, passwordFile, configFile })
      )
  );

  const stdio = await openssl(
    [
      "ca",
      "-config",
      `${configFile}`,
      "-batch",
      "-passin",
      `file:${passwordFile}`,
      "-extensions",
      "usr_cert",
      "-notext",
      "-md",
      "sha256",
      "-in",
      Buffer.from(csr),
      "-out",
      `${certificateStore}/${device}.cert.pem`
    ],
    bin
  );

  if (stdio.length > 0) {
    logger.info(stdio);
  }

  const certificate = await readFile(`${certificateStore}/${device}.cert.pem`);
  return certificate.toString("utf-8");
}

export async function revoke(
  serial: string,
  { bin, passwordFile, configFile }: OpenSSLConfig
): Promise<void> {
  if (!configFile) {
    throw new Error("No Open SSL config file set");
  }
  if (!passwordFile) {
    throw new Error("No Open SSL password file set");
  }

  const configDir = dirname(configFile);
  logger.info(`Revoking ${configDir}/newcerts/${serial}.pem`);

  const stdio = await openssl(
    [
      "ca",
      "-config",
      `${configFile}`,
      "-passin",
      `file:${passwordFile}`,
      "-revoke",
      `${configDir}/newcerts/${serial}.pem`
    ],
    bin
  );

  if (stdio.length > 0) {
    logger.info(stdio);
  }

  await generateCRL({ bin, passwordFile, configFile });
}

export async function generateCRL({
  bin,
  passwordFile,
  configFile
}: OpenSSLConfig): Promise<void> {
  if (!configFile) {
    throw new Error("No Open SSL config file set");
  }
  if (!passwordFile) {
    throw new Error("No Open SSL password file set");
  }
  const configDir = dirname(configFile);
  logger.info("Generating a new CRL");

  const stdio = await openssl(
    [
      "ca",
      "-config",
      `${configFile}`,
      "-passin",
      `file:${passwordFile}`,
      "-gencrl",
      "-out",
      `${configDir}/crl.pem`
    ],
    bin
  );

  if (stdio.length > 0) {
    logger.info(stdio);
  }
}
